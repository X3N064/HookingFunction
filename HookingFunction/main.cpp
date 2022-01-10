//This is External Hook
#include <Windows.h>

bool Hook(void* toHook, void* ourFunct, int len) 
{
    if (len < 5) 
    {
        return false;
    }

    DWORD curProtection;
    VirtualProtect(toHook, len, PAGE_EXECUTE_READWRITE, &curProtection);

    memset(toHook, 0x90, len); //nop

    DWORD relativeAddress = ((DWORD)ourFunct - (DWORD)toHook) - 5;

    *(BYTE*)toHook = 0xE9; //jmp
    *(DWORD*)((DWORD)toHook + 1) = relativeAddress;

    DWORD temp;
    VirtualProtect(toHook, len, curProtection, &temp);

    return true;
}

DWORD jmpBackAddy;
void __declspec(naked) ourFunct() 
{
    __asm 
    {
        add ecx, ecx //ex
        mov edx, [ebp-8] //ex
        jmp[jmpBackAddy]
    }
}

DWORD WINAPI MainThread(LPVOID param) 
{
    int hookLength = 6;
    DWORD hookAddress = 0x0; //ex
    jmpBackAddy = hookAddress + hookLength;

    Hook((void*)hookAddress, ourFunct, hookLength);

    while (true)
    {
        if (GetAsyncKeyState(VK_ESCAPE)) break; //ex
        Sleep(50);
    }

    FreeLibraryAndExitThread((HMODULE)param, 0);

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved) 
{
    switch (dwReason) 
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, MainThread, hModule, 0, 0);
        break;
    }

    return TRUE;
}
