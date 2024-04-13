#include "pch.hpp"
#include "impersonate.hpp"

BOOL c_impersonate::token_is_not_restricted(HANDLE hToken, PBOOL pbIsNotRestricted)
{
	BOOL bReturnValue = FALSE;

	DWORD dwSize = 0;
	PTOKEN_GROUPS pTokenGroups = NULL;

	if (!GetTokenInformation(hToken, TokenRestrictedSids, NULL, dwSize, &dwSize))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			log_err("GetTokenInformation");
			goto end;
		}
	}

	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwSize);
	if (!pTokenGroups)
		goto end;

	if (!GetTokenInformation(hToken, TokenRestrictedSids, pTokenGroups, dwSize, &dwSize))
	{
		log_err("GetTokenInformation");
		goto end;
	}

	*pbIsNotRestricted = pTokenGroups->GroupCount == 0;

	bReturnValue = TRUE;

end:
	if (pTokenGroups)
		LocalFree(pTokenGroups);

	return bReturnValue;
}


BOOL c_impersonate::token_get_sid(HANDLE hToken, PSID* ppSid)
{
	BOOL bReturnValue = TRUE;
	DWORD dwSize = 0;
	PTOKEN_USER pTokenUser = NULL;

	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			log_err("GetTokenInformation");
			goto end;
		}
	}

	pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwSize);
	if (!pTokenUser)
		goto end;

	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
	{
		log_err("GetTokenInformation");
		goto end;
	}

	*ppSid = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
	if (!*ppSid)
		goto end;

	if (!CopySid(SECURITY_MAX_SID_SIZE, *ppSid, pTokenUser->User.Sid))
	{
		log_err("CopySid");
		LocalFree(*ppSid);
		goto end;
	}

	bReturnValue = TRUE;

end:
	if (pTokenUser)
		LocalFree(pTokenUser);

	return bReturnValue;
}


BOOL c_impersonate::token_get_username(HANDLE hToken, LPWSTR* ppwszUsername)
{
	BOOL bReturnValue = FALSE;
	PSID pSid = NULL;
	const DWORD dwMaxSize = 256;
	WCHAR wszUsername[dwMaxSize] = { 0 };
	WCHAR wszDomain[dwMaxSize] = { 0 };
	DWORD dwMaxUsername = dwMaxSize;
	DWORD dwMaxDomain = dwMaxSize;
	SID_NAME_USE type;

	if (!this->token_get_sid(hToken, &pSid))
		goto end;

	if (!LookupAccountSid(NULL, pSid, wszUsername, &dwMaxUsername, wszDomain, &dwMaxDomain, &type))
	{
		log_err("LookupAccountSid");
		goto end;
	}

	*ppwszUsername = (LPWSTR)LocalAlloc(LPTR, (dwMaxSize * 2 + 1) * sizeof(WCHAR));
	if (!*ppwszUsername)
		goto end;

	StringCchPrintf(*ppwszUsername, dwMaxSize * 2 + 1, L"%ws\\%ws", wszDomain, wszUsername);
	bReturnValue = TRUE;

end:
	if (pSid)
		LocalFree(pSid);

	return bReturnValue;
}

BOOL c_impersonate::token_compare_sids(PSID pSidA, PSID pSidB)
{
	BOOL bReturnValue = FALSE;
	LPWSTR pwszSidA = NULL;
	LPWSTR pwszSidB = NULL;

	if (ConvertSidToStringSid(pSidA, &pwszSidA) && ConvertSidToStringSid(pSidB, &pwszSidB))
	{
		bReturnValue = _wcsicmp(pwszSidA, pwszSidB) == 0;
		LocalFree(pwszSidA);
		LocalFree(pwszSidB);
	}
	else
		log_err("ConvertSidToStringSid");

	return bReturnValue;
}


BOOL c_impersonate::find_process_token_and_duplicate(_In_ LPCWSTR pwszTargetSid, _Out_ PHANDLE phToken, _In_opt_ LPCWSTR pwszPrivileges[], _In_ DWORD dwPrivilegeCount)
{
	BOOL bReturnValue = FALSE;

	PSID pTargetSid = NULL;
	PVOID pBuffer = NULL;
	PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
	HANDLE hProcess = NULL, hToken = NULL, hTokenDup = NULL;
	DWORD dwReturnedLen = 0, dwBufSize = 0x1000, dwSessionId = 0;
	PSID pSidTmp = NULL;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;

	LPWSTR pwszUsername = NULL;

	if (!ConvertStringSidToSid(pwszTargetSid, &pTargetSid))
		goto end;

	while (TRUE)
	{
		pBuffer = LocalAlloc(LPTR, dwBufSize);
		if (!pBuffer || status != STATUS_INFO_LENGTH_MISMATCH)
			break;

		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, pBuffer, dwBufSize, &dwReturnedLen);
		if (NT_SUCCESS(status))
		{
			pProcInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
			while (TRUE) {
				if (hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PtrToUlong(pProcInfo->UniqueProcessId)))
				{
					if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
					{
						if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hTokenDup))
						{
							if (this->token_get_sid(hTokenDup, &pSidTmp) && this->token_get_username(hTokenDup, &pwszUsername))
							{
								if (this->token_compare_sids(pSidTmp, pTargetSid))
								{
									log_debug("Found a potential Process candidate: PID=%d - Image='%ws' - User='%ws'", PtrToUlong(pProcInfo->UniqueProcessId), pProcInfo->ImageName.Buffer, pwszUsername);

									BOOL bTokenIsNotRestricted = FALSE;
									this->token_is_not_restricted(hTokenDup, &bTokenIsNotRestricted);

									if (bTokenIsNotRestricted)
										log_debug("This token is not restricted.");
									else
										log_debug("This token is restricted.");

									if (bTokenIsNotRestricted)
									{
										if (pwszPrivileges && dwPrivilegeCount != 0)
										{
											DWORD dwPrivilegeFound = 0;
											for (DWORD i = 0; i < dwPrivilegeCount; i++)
											{
												if (this->token_check_privilege(hTokenDup, pwszPrivileges[i], FALSE))
													dwPrivilegeFound++;
											}

											log_debug("Found %d/%d required privileges in token.", dwPrivilegeFound, dwPrivilegeCount);

											if (dwPrivilegeFound == dwPrivilegeCount)
											{
												log_debug("Found a valid Token candidate.");

												*phToken = hTokenDup;
												bReturnValue = TRUE;
											}
										}
										else
										{
											log_debug("Found a valid Token.");

											*phToken = hTokenDup;
											bReturnValue = TRUE;
										}
									}
								}
								LocalFree(pSidTmp);
								LocalFree(pwszUsername);
							}
							if (!bReturnValue)
								CloseHandle(hTokenDup);
						}
						CloseHandle(hToken);
					}
					CloseHandle(hProcess);
				}

				// If we found a valid token, stop
				if (bReturnValue)
					break;

				// If next entry is null, stop
				if (!pProcInfo->NextEntryOffset)
					break;

				// Increment SYSTEM_PROCESS_INFORMATION pointer
				pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
			}
		}

		LocalFree(pBuffer);
		dwBufSize <<= 1;
	}

end:
	if (pTargetSid)
		LocalFree(pTargetSid);

	return bReturnValue;
}

BOOL c_impersonate::token_check_privilege(HANDLE hToken, LPCWSTR pwszPrivilege, BOOL bEnablePrivilege)
{
	BOOL bReturnValue = FALSE;
	DWORD dwTokenPrivilegesSize = 0, i = 0, dwPrivilegeNameLength = 0;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
	LUID_AND_ATTRIBUTES laa = { 0 };
	TOKEN_PRIVILEGES tp = { 0 };
	LPWSTR pwszPrivilegeNameTemp = NULL;

	if (!GetTokenInformation(hToken, TokenPrivileges, NULL, dwTokenPrivilegesSize, &dwTokenPrivilegesSize))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			log_err("GetTokenInformation");
			goto end;
		}
	}

	pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, dwTokenPrivilegesSize);
	if (!pTokenPrivileges)
		goto end;

	if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwTokenPrivilegesSize, &dwTokenPrivilegesSize))
	{
		log_err("GetTokenInformation");
		goto end;
	}

	for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
	{
		laa = pTokenPrivileges->Privileges[i];
		dwPrivilegeNameLength = 0;

		if (!LookupPrivilegeName(NULL, &(laa.Luid), NULL, &dwPrivilegeNameLength))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				log_err("LookupPrivilegeName");
				goto end;
			}
		}

		dwPrivilegeNameLength++;

		if (pwszPrivilegeNameTemp = (LPWSTR)LocalAlloc(LPTR, dwPrivilegeNameLength * sizeof(WCHAR)))
		{
			if (LookupPrivilegeName(NULL, &(laa.Luid), pwszPrivilegeNameTemp, &dwPrivilegeNameLength))
			{
				if (!_wcsicmp(pwszPrivilegeNameTemp, pwszPrivilege))
				{
					if (bEnablePrivilege)
					{
						ZeroMemory(&tp, sizeof(TOKEN_PRIVILEGES));
						tp.PrivilegeCount = 1;
						tp.Privileges[0].Luid = laa.Luid;
						tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

						if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
							bReturnValue = TRUE;
						else
							log_err("AdjustTokenPrivileges");
					}
					else
					{
						bReturnValue = TRUE;
					}

					break;
				}
			}
			else
				log_err("LookupPrivilegeName");

			LocalFree(pwszPrivilegeNameTemp);
		}
	}

end:
	if (pTokenPrivileges)
		LocalFree(pTokenPrivileges);

	return bReturnValue;
}

BOOL c_impersonate::impersonate(_In_ HANDLE hToken)
{
	HANDLE hThread = GetCurrentThread(); // Pseudo handle, does not need to be closed

	if (!SetThreadToken(&hThread, hToken))
	{
		log_err("SetThreadToken");
		return FALSE;
	}

	return TRUE;
}

HANDLE c_impersonate::impersonate_as_local_service() {
	BOOL bReturnValue = FALSE;

	HANDLE hCurrentProcessToken = NULL;
	HANDLE hToken = NULL;
	HANDLE hCurrentThread = NULL;

	if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hCurrentProcessToken))
	{
		log_err("OpenProcessToken");
		goto end;
	}

	if (!this->token_check_privilege(hCurrentProcessToken, SE_DEBUG_NAME, TRUE))
		goto end;

	if (!this->token_check_privilege(hCurrentProcessToken, SE_IMPERSONATE_NAME, TRUE))
		goto end;

	if (!this->find_process_token_and_duplicate(L"S-1-5-19", &hToken, NULL, 0))
		goto end;
	
	log_debug("Impersonating as LOCAL SERVICE.");
	if (!this->impersonate(hToken))
		goto end;

	bReturnValue = TRUE;

end:
	if (hCurrentProcessToken)
		CloseHandle(hCurrentProcessToken);

	return hToken;
}

HANDLE c_impersonate::impersonate_as_system() {
	BOOL bReturnValue = FALSE;

	HANDLE hCurrentProcessToken = NULL;
	HANDLE hToken = NULL;
	HANDLE hCurrentThread = NULL;

	LPCWSTR pwszPrivileges[2] = {
		L"SeDebugPrivilege",
		L"SeAssignPrimaryTokenPrivilege"
	};

	if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hCurrentProcessToken))
	{
		log_err("OpenProcessToken");
		goto end;
	}

	if (!this->token_check_privilege(hCurrentProcessToken, SE_DEBUG_NAME, TRUE))
		goto end;

	if (!this->token_check_privilege(hCurrentProcessToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE))
		goto end;

	if (!this->find_process_token_and_duplicate(L"S-1-5-18", &hToken, pwszPrivileges, ARRAYSIZE(pwszPrivileges)))
		goto end;
	
	log_debug("Impersonating as SYSTEM.");
	if (!this->impersonate(hToken))
		goto end;

	bReturnValue = TRUE;

end:
	if (hCurrentProcessToken)
		CloseHandle(hCurrentProcessToken);

	return hToken;
}

BOOL c_impersonate::is_elevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}