#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Hello World from injected DLL!", "Module Stomper Test", MB_OK | MB_ICONINFORMATION);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
