#pragma once
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <map>
#include "minhook\include\MinHook.h"

#if defined _M_X64
#pragma comment(lib, "libMinHook-x64-v141-mtd.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86-v141-mtd.lib")
#endif

namespace IllegalInstruction {
    typedef BOOL(_fastcall* QueryWorkingSetEx_t)(HANDLE hProcess, PVOID  pv, DWORD  cb);
    QueryWorkingSetEx_t QueryWorkingSetEx_ptr;

    HMODULE mod = GetModuleHandleA("KERNELBASE.dll");
    void* queryAddr = (void*)GetProcAddress(mod, "QueryWorkingSetEx");

    void* NtQueryVirtualMemoryAddr = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryVirtualMemory");
    typedef LONG(_stdcall* NtQueryVirtualMemory_t)(HANDLE  ProcessHandle, PVOID BaseAddress, __int64 MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
    NtQueryVirtualMemory_t NtQueryVirtualMemory_ptr = nullptr;

    struct savedData {
        _MEMORY_BASIC_INFORMATION VIR_BLOCK;
        PSAPI_WORKING_SET_EX_BLOCK EX_BLOCK;
        SIZE_T MemoryInformationLength;
    };

    std::map<void*, savedData> savedResults;

    extern BOOL QueryWorkingSetEx_detour(HANDLE hProcess, PVOID pv, DWORD cb);
}
