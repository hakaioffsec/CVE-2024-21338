#pragma once

#include <sddl.h>
#pragma comment(lib, "advapi32.lib")
#include <strsafe.h>

class c_impersonate
{
private:

public:
	c_impersonate() = default;
	~c_impersonate() = default;

    BOOL token_is_not_restricted(HANDLE hToken, PBOOL pbIsNotRestricted);
    BOOL token_get_sid(HANDLE hToken, PSID* ppSid);
    BOOL token_get_username(HANDLE hToken, LPWSTR* ppwszUsername);
    BOOL token_compare_sids(PSID pSidA, PSID pSidB);
    BOOL find_process_token_and_duplicate(LPCWSTR pwszTargetSid, PHANDLE phToken, LPCWSTR pwszPrivileges[], DWORD dwPrivilegeCount);
    BOOL token_check_privilege(HANDLE hToken, LPCWSTR pwszPrivilege, BOOL bEnablePrivilege);
    BOOL impersonate(HANDLE hToken);
    HANDLE impersonate_as_local_service();
    HANDLE impersonate_as_system();
    BOOL is_elevated();
};

inline auto impersonate = std::make_unique<c_impersonate>();