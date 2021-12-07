#include "bypass.h"

namespace IllegalInstruction {
    BOOL QueryWorkingSetEx_detour(HANDLE hProcess, PVOID pv, DWORD cb)
    {
        BOOL result = QueryWorkingSetEx_ptr(hProcess, pv, cb);

        for (int k = 0; k < cb / sizeof(PMEMORY_BASIC_INFORMATION); k++) {
            void* manipuledAddress = ((PMEMORY_BASIC_INFORMATION)pv)[k].BaseAddress;
            for (int i = 0; i < cb / sizeof(PSAPI_WORKING_SET_EX_INFORMATION); i++) {
                if (!savedResults.count(manipuledAddress)) {
                    savedData saveToData;
                    saveToData.VIR_BLOCK = ((PMEMORY_BASIC_INFORMATION)pv)[k];
                    saveToData.EX_BLOCK = ((PPSAPI_WORKING_SET_EX_INFORMATION)pv)[i].VirtualAttributes;
                    saveToData.MemoryInformationLength = cb;
                    savedResults.insert(std::pair<void*, savedData>(manipuledAddress, saveToData));
                }
                else {
                    ((PMEMORY_BASIC_INFORMATION)pv)[k] = savedResults.find(manipuledAddress)->second.VIR_BLOCK;
                    ((PPSAPI_WORKING_SET_EX_INFORMATION)pv)[i].VirtualAttributes = savedResults.find(manipuledAddress)->second.EX_BLOCK;
                    cb = savedResults.find(manipuledAddress)->second.MemoryInformationLength;
                }
            }
        }
        return result;
    }

    LONG _stdcall NtQueryVirtualMemory_detour(HANDLE ProcessHandle, PVOID BaseAddress, __int64 MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
    {
        auto result = NtQueryVirtualMemory_ptr(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
        for (int k = 0; k < MemoryInformationLength / sizeof(PMEMORY_BASIC_INFORMATION); k++) {
            void* manipuledAddress = ((PMEMORY_BASIC_INFORMATION)MemoryInformation)[k].BaseAddress;
            for (int i = 0; i < MemoryInformationLength / sizeof(PSAPI_WORKING_SET_EX_INFORMATION); i++) {
                if (!savedResults.count(manipuledAddress)) {
                    savedData saveToData;
                    saveToData.VIR_BLOCK = ((PMEMORY_BASIC_INFORMATION)MemoryInformation)[k];
                    saveToData.EX_BLOCK = ((PPSAPI_WORKING_SET_EX_INFORMATION)MemoryInformation)[i].VirtualAttributes;
                    saveToData.MemoryInformationLength = MemoryInformationLength;
                    savedResults.insert(std::pair<void*, savedData>(manipuledAddress, saveToData));
                }
                else {
                    ((PMEMORY_BASIC_INFORMATION)MemoryInformation)[k] = savedResults.find(manipuledAddress)->second.VIR_BLOCK;
                    ((PPSAPI_WORKING_SET_EX_INFORMATION)MemoryInformation)[i].VirtualAttributes = savedResults.find(manipuledAddress)->second.EX_BLOCK;
                    MemoryInformationLength = savedResults.find(manipuledAddress)->second.MemoryInformationLength;
                }
            }
        }
        return result;
    }
}

auto BypassChecks() {

    AllocConsole();

    SetConsoleTitleA("Bypass");

    freopen_s((FILE**)stdin, "conin$", "r", stdin);
    freopen_s((FILE**)stdout, "conout$", "w", stdout);

    MH_Initialize();
    MH_CreateHook(IllegalInstruction::queryAddr, IllegalInstruction::QueryWorkingSetEx_detour, (LPVOID*)&IllegalInstruction::QueryWorkingSetEx_ptr);
    
    // are you a naughty boy ? 
    // MH_CreateHook(IllegalInstruction::NtQueryVirtualMemoryAddr, IllegalInstruction::NtQueryVirtualMemory_detour, (LPVOID*)&IllegalInstruction::NtQueryVirtualMemory_ptr);

    std::cout << "Press F5 to bypass memory page count checks." << std::endl;

    while (true) {
        if (GetAsyncKeyState(VK_F5)) {
            MH_EnableHook(IllegalInstruction::queryAddr);
            // MH_EnableHook(IllegalInstruction::NtQueryVirtualMemoryAddr);
            
            std::cout << "Bypass enabled, press F6 to disable it." << std::endl;
        }
        else if (GetAsyncKeyState(VK_F6)) {
            MH_DisableHook(IllegalInstruction::queryAddr);
            // MH_DisableHook(IllegalInstruction::NtQueryVirtualMemoryAddr);
            std::cout << "Bypass disabled. Press F5 to bypass memory page count checks." << std::endl;
        }
        Sleep(250);
    }
 
}

__int64 APIENTRY DllMain( __int64 hModule, __int64 ul_reason_for_call, __int64 lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) BypassChecks();
    return TRUE;
}

