#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <winternl.h>


#ifdef _WIN64
#define GetCurrentTeb() (struct _TEB*)__readgsqword(FIELD_OFFSET(NT_TIB, Self))
#else
#define GetCurrentTeb() (struct _TEB*)(ULONG_PTR)__readfsdword(0x18)

#endif // _X64;

#define MakePointer(Struct, Base, offset) ((Struct)((char*)(Base) + offset))
#define xstrcmp(s1,s2,CaseInsensitive,b) {int _____i = 0;if(!CaseInsensitive)while (((s1)[_____i]&(s2)[_____i])&&!((s1)[_____i] ^ (s2)[_____i])) _____i++; else while (((s1)[_____i]&(s2)[_____i])&&!(((s1)[_____i]|0x20) ^ ((s2)[_____i]|0x20))) _____i++; b=(s1)[_____i] == (s2)[_____i];}
#define xmemset(Dst,Val,Size) for(int ___i=0;___i<Size;___i++)((CHAR*)Dst)[___i]=Val;
#define VGetProcAddress(ModuleName,lpProcName, pProc) {                                                                                                     \
    PTEB pTeb__ = GetCurrentTeb();                                                                                                                          \
    PPEB pPeb__ = pTeb__->ProcessEnvironmentBlock;                                                                                                          \
    LPSTR uModuleName__ = ModuleName;                                                                                                                       \
    LPSTR ulpProcName__ = lpProcName;                                                                                                                       \
    CHAR Buffer__[0x200];                                                                                                                                   \
    CHAR* Address__ = 0;                                                                                                                                   \
    BOOL GotoRedirect = FALSE;                                                                                                                              \
    BOOL FindFunc = FALSE;                                                                                                                                  \
    PLIST_ENTRY Links__ = pPeb__->Ldr->InMemoryOrderModuleList.Flink;                                                                                       \
                                                                                                                                                            \
    do {                                                                                                                                                    \
        if (GotoRedirect) GotoRedirect = FALSE;                                                                                                             \
        PLDR_DATA_TABLE_ENTRY Entry__ = (CHAR*)Links__ - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);                                               \
        BOOL IsEuqal___ = FALSE;                                                                                                                            \
        xstrcmp(uModuleName__, (&Entry__->FullDllName)[1].Buffer, TRUE, IsEuqal___);                                                                        \
        if (IsEuqal___) {                                                                                                                                   \
            UINT32* NameRva__;                                                                                                                              \
            UINT16* OrdinalRva__;                                                                                                                           \
            UINT32* FuncRva__;                                                                                                                              \
            PIMAGE_EXPORT_DIRECTORY pExport__;                                                                                                              \
            PVOID FuncAddress__ = 0;                                                                                                                        \
            PIMAGE_DOS_HEADER pDos__ = Entry__->DllBase;                                                                                                    \
            PIMAGE_NT_HEADERS pNt__ = MakePointer(PIMAGE_NT_HEADERS, pDos__, pDos__->e_lfanew);                                                             \
            pExport__ = (IMAGE_EXPORT_DIRECTORY*)(pNt__->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (CHAR*)pDos__);       \
            FuncRva__ = pExport__->AddressOfFunctions + (CHAR*)pDos__;                                                                                     \
            NameRva__ = pExport__->AddressOfNames + (CHAR*)pDos__;                                                                                         \
            OrdinalRva__ = pExport__->AddressOfNameOrdinals + (CHAR*)pDos__;                                                                               \
            for (int i_ = 0; i_ < pExport__->NumberOfNames; i_++) {                                                                                      \
                BOOL bFind__ = FALSE;                                                                                                                       \
                xstrcmp((CHAR*)pDos__ + NameRva__[i_], ulpProcName__, TRUE, bFind__);                                                                       \
                if (bFind__) {                                                                                                                              \
                    Address__ = (CHAR*)pDos__ + FuncRva__[OrdinalRva__[i_]];                                                                               \
                                                                                                                                                            \
                    PIMAGE_SECTION_HEADER pImageSectionHeader__ = MakePointer(PIMAGE_SECTION_HEADER, pNt__, sizeof(IMAGE_NT_HEADERS));                      \
                    pImageSectionHeader__ = MakePointer(PIMAGE_SECTION_HEADER, pNt__, sizeof(IMAGE_NT_HEADERS));                                            \
                    PVOID pSectionBase__ = NULL;                                                                                                            \
                    PVOID pSectionDataSource__ = NULL;                                                                                                      \
                    CHAR* NumberOfSection__ = pNt__->FileHeader.NumberOfSections;                                                                          \
                    for (int i__ = 0; i__ < NumberOfSection__; i__++) {                                                                                     \
                        if (pImageSectionHeader__[i__].VirtualAddress) {                                                                                    \
                            pSectionBase__ = MakePointer(PVOID, pDos__, pImageSectionHeader__[i__].VirtualAddress);                                         \
                            if (Address__ >= pSectionBase__ && Address__ <= (CHAR*)pSectionBase__ + pImageSectionHeader__[i__].SizeOfRawData) {            \
                                if (!(pImageSectionHeader__[i__].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {                                                \
                                    uModuleName__ = Buffer__;                                                                                               \
                                    int i___ = 0;                                                                                                           \
                                    for (; (uModuleName__[i___] = ((CHAR*)Address__)[i___]) != '.'; i___++);                                                \
                                                                                                                                                            \
                                    *(UINT32*)(&uModuleName__[++i___]) = '\0lld';                                                                           \
                                    ulpProcName__ = &uModuleName__[i___ + sizeof(UINT32)];                                                                  \
                                    for (int t___ = 0; (ulpProcName__[t___] = ((CHAR*)Address__)[t___ + i___]) != 0; t___++);                               \
                                    Links__ = pPeb__->Ldr->InMemoryOrderModuleList.Flink;                                                                   \
                                    GotoRedirect = TRUE;                                                                                                    \
                                                                                                                                                            \
                                }                                                                                                                           \
                                else {                                                                                                                      \
                                    pProc = Address__;                                                                                                     \
                                    GotoRedirect = FALSE;                                                                                                   \
                                    FindFunc = TRUE;                                                                                                        \
                                }                                                                                                                           \
                                break;                                                                                                                      \
                            }                                                                                                                               \
                        }                                                                                                                                   \
                    }                                                                                                                                       \
                    if (GotoRedirect || FindFunc) break;                                                                                                    \
                                                                                                                                                            \
                }                                                                                                                                           \
            }                                                                                                                                               \
        }                                                                                                                                                   \
        if (GotoRedirect) continue;                                                                                                                         \
        if (FindFunc) break;                                                                                                                                \
        Links__ = Links__->Flink;                                                                                                                           \
    } while (GotoRedirect || Links__ != &pPeb__->Ldr->InMemoryOrderModuleList);                                                                             \
}

#define VGetModuleByName( ModuleName,Address) {                                                                                                                             \
    PTEB pTeb_____ = GetCurrentTeb();                                                                                                                                       \
    PPEB pPeb_____ = pTeb_____->ProcessEnvironmentBlock;                                                                                                                    \
    for (PLIST_ENTRY Links_____ = pPeb_____->Ldr->InMemoryOrderModuleList.Flink;Links_____ != &pPeb_____->Ldr->InMemoryOrderModuleList;Links_____ = Links_____->Flink) {    \
        PLDR_DATA_TABLE_ENTRY Entry_____ = (UINT64)Links_____ - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);                                                         \
        BOOL IsEuqal_____ = FALSE;                                                                                                                                          \
        xstrcmp(ModuleName, (&Entry_____->FullDllName)[1].Buffer,TRUE, IsEuqal_____);                                                                                       \
        if (IsEuqal_____) {                                                                                                                                                 \
            Address= Entry_____->DllBase;                                                                                                                                   \
        }                                                                                                                                                                   \
    }                                                                                                                                                                       \
    Address= 0;                                                                                                                                                             \
}

 UINT64 ManualMap( PVOID pFileBase) {
    CHAR aKernelBase[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'B', L'a', L's', L'e', L'.', L'd', L'l', L'l', L'\0' };
    CHAR aNtdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };

    CHAR aVirtualAlloc[] = {L'V',L'i',L'r',L't',L'u',L'a',L'l',L'A',L'l',L'l',L'o',L'c',L'\0'};
    CHAR aVirtualProtect[] = {L'V',L'i',L'r',L't',L'u',L'a',L'l',L'P',L'r',L'o',L't',L'e',L'c',L't',L'\0'};
    CHAR aLoadLibraryA[] = {L'L',L'o',L'a',L'd',L'L',L'i',L'b',L'r',L'a',L'r',L'y',L'A',L'\0'};

    LPVOID(WINAPI * pVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
    VGetProcAddress(aKernelBase, aVirtualAlloc, pVirtualAlloc);
    LPVOID(WINAPI * pVirtualProtect)(_In_  LPVOID lpAddress, _In_  SIZE_T dwSize, _In_  DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
    VGetProcAddress(aKernelBase, aVirtualProtect, pVirtualProtect);
    HMODULE (WINAPI*pLoadLibraryA)(_In_ LPCSTR lpLibFileName);
    VGetProcAddress(aKernelBase, aLoadLibraryA, pLoadLibraryA);

    UINT64 pImageBase = 0;
    PIMAGE_DOS_HEADER pDos = pFileBase;
    PIMAGE_NT_HEADERS pNt = MakePointer(PIMAGE_NT_HEADERS, pDos, pDos->e_lfanew);

    UINT64 NumberOfSection = pNt->FileHeader.NumberOfSections;
    pImageBase = pVirtualAlloc(0, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);

    __movsb(pImageBase, pFileBase, pNt->OptionalHeader.SizeOfHeaders);

    pDos = (PIMAGE_DOS_HEADER)pImageBase;
    pNt = MakePointer(PIMAGE_NT_HEADERS, pDos, pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pNt, sizeof(IMAGE_NT_HEADERS));
    pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pNt, sizeof(IMAGE_NT_HEADERS));
    PVOID pSectionBase = NULL;
    PVOID pSectionDataSource = NULL;
    for (int i = 0; i < NumberOfSection; i++) {
        if (pImageSectionHeader[i].VirtualAddress) {
            pSectionBase = MakePointer(PVOID, pImageBase, pImageSectionHeader[i].VirtualAddress);
            if (pImageSectionHeader[i].SizeOfRawData) {
                // Get the section data source and copy the data to the section buffer
                pSectionDataSource = MakePointer(PVOID, pFileBase, pImageSectionHeader[i].PointerToRawData);
                __movsb(pSectionBase, pSectionDataSource, pImageSectionHeader[i].SizeOfRawData);
            }
            else {
                UINT32 size = 0;
                if (pImageSectionHeader[i].Misc.VirtualSize > 0) size = pImageSectionHeader[i].Misc.VirtualSize;
                else size = pNt->OptionalHeader.SectionAlignment;
                if (size > 0) xmemset(pSectionBase, 0, size);
            }
        }
    }


    PIMAGE_BASE_RELOCATION pImageRelocation = MakePointer(PIMAGE_BASE_RELOCATION, pDos, pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    while (pImageRelocation->VirtualAddress + pImageRelocation->SizeOfBlock) {
        if (!pImageRelocation) break;

        PUSHORT pRelocationData = MakePointer(PUSHORT, pImageRelocation, sizeof(IMAGE_BASE_RELOCATION));
        int NumberOfRelocationData = (pImageRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);

        for (int i = 0; i < NumberOfRelocationData; i++) {
            if (IMAGE_REL_BASED_HIGHLOW == (pRelocationData[i] >> 12)) {
                PUINT32 pAddress = (PUINT32)(pImageBase + pImageRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
                UINT32 Old = *pAddress;
                *pAddress = pImageBase + (*pAddress - pNt->OptionalHeader.ImageBase);
            }
            if (IMAGE_REL_BASED_DIR64 == (pRelocationData[i] >> 12)) {
                PUINT64 pAddress = (PULONGLONG)(pImageBase + pImageRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
                UINT64 Old = *pAddress;
                *pAddress = pImageBase + (*pAddress - pNt->OptionalHeader.ImageBase);  // pModuleBase+;
            }
        }
        pImageRelocation = MakePointer(PIMAGE_BASE_RELOCATION, pImageRelocation, pImageRelocation->SizeOfBlock);
    }

    PIMAGE_IMPORT_DESCRIPTOR pImageImportDes = MakePointer(PIMAGE_IMPORT_DESCRIPTOR, pDos, pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (TRUE) {
        if (!pImageImportDes->Name) break;
        PCHAR pDllName = MakePointer(PCHAR, pDos, pImageImportDes->Name);
        PVOID pDllBase = 0;
        VGetModuleByName(pDllName, pDllBase);
        if (!pDllBase) pLoadLibraryA(pDllName);
        PIMAGE_THUNK_DATA pOriginalThunk = NULL;
        if (pImageImportDes->OriginalFirstThunk)pOriginalThunk = MakePointer(PIMAGE_THUNK_DATA, pDos, pImageImportDes->OriginalFirstThunk);
        else pOriginalThunk = MakePointer(PIMAGE_THUNK_DATA, pDos, pImageImportDes->FirstThunk);
        PIMAGE_THUNK_DATA pIATThunk = MakePointer(PIMAGE_THUNK_DATA, pDos, pImageImportDes->FirstThunk);

        for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++) {
            UINT64 lpFunction = NULL;
            if (IMAGE_SNAP_BY_ORDINAL64(pOriginalThunk->u1.Ordinal)) {
                 VGetProcAddress(pDllName, (LPCSTR)IMAGE_ORDINAL64(pOriginalThunk->u1.Ordinal), lpFunction);// GetExportFunc(pModuleBase, (LPCSTR)IMAGE_ORDINAL64(pOriginalThunk->u1.Ordinal));
                //printf("Repair Import %s::%s At:%p\n", pDllName, (LPCSTR)IMAGE_ORDINAL64(pOriginalThunk->u1.Ordinal), lpFunction);
            }
            else {
                PIMAGE_IMPORT_BY_NAME pImageImportByName = MakePointer(PIMAGE_IMPORT_BY_NAME, pDos, pOriginalThunk->u1.AddressOfData);
                VGetProcAddress(pDllName, (LPCSTR) & (pImageImportByName->Name), lpFunction);// GetExportFunc(pModuleBase, (LPCSTR) & (pImageImportByName->Name));
                //printf("Repair Import %s::%s At:%p\n", pDllName, (LPCSTR) & (pImageImportByName->Name), lpFunction);
            }
            pIATThunk->u1.Function = lpFunction;
        }
        pImageImportDes++;
    }

    for (int i = 0; i < NumberOfSection; i++) {
        if (pImageSectionHeader[i].VirtualAddress) {
            pSectionBase = MakePointer(PVOID, pImageBase, pImageSectionHeader[i].VirtualAddress);

            UINT32 size;
            if (pImageSectionHeader[i].SizeOfRawData) size = pImageSectionHeader[i].SizeOfRawData;
            else {
                if (pImageSectionHeader[i].Misc.VirtualSize > 0) size = pImageSectionHeader[i].Misc.VirtualSize;
                else size = pNt->OptionalHeader.SectionAlignment;
            }
            DWORD ProtectMap[] = {              //
                PAGE_NOACCESS,                  //
                PAGE_EXECUTE,                   //IMAGE_SCN_MEM_EXECUTE
                PAGE_READONLY,                  //IMAGE_SCN_MEM_READ
                PAGE_EXECUTE_READ,              //IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ
                PAGE_READWRITE,                 //IMAGE_SCN_MEM_WRITE
                PAGE_EXECUTE_READWRITE,         //IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE
                PAGE_READWRITE,                 //IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE
                PAGE_EXECUTE_READWRITE          //IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE
            };
            DWORD OldProtect;
            DWORD Protect = ProtectMap[(pImageSectionHeader[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) >> 29];
            pVirtualProtect(pSectionBase, pImageSectionHeader[i].SizeOfRawData, Protect, &OldProtect);
        }
    }
    //printf("MappedBase:%p\n", pDos);
    BOOL(APIENTRY * DllMain)(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) = MakePointer(UINT64, pDos, pNt->OptionalHeader.AddressOfEntryPoint);
    DllMain(pDos, 1, 0);

}
 char ManualMapStop() {};

__declspec(noinline)PVOID   __stdcall VSLoadFile(LPSTR FilePath, OUT OPTIONAL UINT64* FileSize) {
    OFSTRUCT FileInfo = { 0 };
    HFILE hFile;
    PVOID Ret = 0;
    DWORD NumberOfRead = 0;
    size_t uFileSize = 0;
    if ((hFile = OpenFile(FilePath, &FileInfo, OF_READ)) != INVALID_HANDLE_VALUE) {
        if ((uFileSize = GetFileSize(hFile, NULL)) > 0) {
            if (Ret = VirtualAlloc(0, uFileSize, MEM_COMMIT, PAGE_READWRITE)) {
                ReadFile(hFile, Ret, uFileSize, &NumberOfRead, NULL);
                if (uFileSize != NumberOfRead) {
                    VirtualFree(Ret, 0, MEM_DECOMMIT);
                    Ret = 0;
                }
                else {
                    if (FileSize) *FileSize = uFileSize;
                }

            }
        }
        CloseHandle(hFile);
    }
    return Ret;
}


void main() {
    printf("ManualMap:%p ManualMapStop:%p\n", ManualMap, ManualMapStop);
    UCHAR* Code = ManualMap;
    printf("CHAR ManualMap%s[]={0x%02X",sizeof(void*)==sizeof(UINT64)?"64":"32",*Code++);
    for (; Code < ManualMapStop; Code++) {
        printf(",0x%02X", *Code);
    }
    printf("};\n");

    UINT64 FileSize = 0;
    PVOID pFile = VSLoadFile("Dll1.dll", &FileSize);
    DWORD ProcessId = 0;
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    while (!ProcessId) {
        printf("Enter the ProcessId:");
        scanf_s("%d", &ProcessId);
        hProcess=OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId );
        if (hProcess == INVALID_HANDLE_VALUE) {
            ProcessId = 0;
            printf("Unable Open ProcessId:%d ErrorCode:%d\n", ProcessId,GetLastError());
        }
    }
    PVOID RemoteAddress= VirtualAllocEx(hProcess, 0, FileSize + ((CHAR*)ManualMapStop - (CHAR*)ManualMap), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (RemoteAddress) {
        HANDLE hThread;
        WriteProcessMemory(hProcess, RemoteAddress, ManualMap, ((CHAR*)ManualMapStop - (CHAR*)ManualMap), 0);
        WriteProcessMemory(hProcess, (CHAR*)RemoteAddress + ((CHAR*)ManualMapStop - (CHAR*)ManualMap), pFile, FileSize, 0);
        hThread=CreateRemoteThread(hProcess, 0, 0, RemoteAddress, (CHAR*)RemoteAddress + ((CHAR*)ManualMapStop - (CHAR*)ManualMap), 0, 0);
        WaitForSingleObject(hThread, INFINITE);
        VirtualFreeEx(hProcess, RemoteAddress, 0, MEM_RELEASE);
    }
}