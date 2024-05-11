// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <intrin.h>
BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved){
    
    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:MessageBoxA(0, "DLL_PROCESS_ATTACH", "", MB_OK); break;
    case DLL_THREAD_ATTACH:MessageBoxA(0, "DLL_THREAD_ATTACH", "", MB_OK); break;
    case DLL_THREAD_DETACH:MessageBoxA(0, "DLL_THREAD_DETACH", "", MB_OK); break;
    case DLL_PROCESS_DETACH:MessageBoxA(0, "DLL_PROCESS_DETACH", "", MB_OK); break;
        break;
    }
    return TRUE;
}

