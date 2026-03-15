#include "pch.h"
#include "resolver.h"
#include "primitives.h"

#include <stdio.h>


DWORD Hasher(const void* data, size_t length, BOOL isWide, DWORD seed) {
    DWORD hash = seed;
    size_t i = 0;

    if (isWide) {
        const wchar_t* w = (const wchar_t*)data;
        length = length / sizeof(wchar_t); // Convert byte length to wchar_t count
        char* ansiStr = (char*)calloc(1, length * sizeof(char)); // For printing purposes
        WideToAnsi(w, ansiStr, length + 1);

        data = (void*)ansiStr; // Use ansiStr for printing
    }

    const char* c = (const char*)data;
    for (i = 0; i < length; ++i) {
        WORD w = c[i] | 0x2020;
        hash ^= w + ROR8(hash);
    }

    return hash;
}


// function to fetch the base address of a Mmodule from the Process Environment Block
UINT64 GetModule(DWORD TargetHash) {
    ULONG_PTR dll, val1;
    PWSTR val2;
    USHORT usCounter;
    // We want to stop when we find this
    DWORD firstHash = 0;
    DWORD currentHash = 1;

    // PEB is at 0x60 offset and __readgsqword is compiler intrinsic,
    // so we don't need to extract it's symbol
    dll = __readgsqword(0x60);

    dll = (ULONG_PTR)((_PPEB)dll)->pLdr;
    val1 = (ULONG_PTR)((PPEB_LDR_DATA)dll)->InMemoryOrderModuleList.Flink;

    while (firstHash != currentHash) {
        val2 = (PWSTR)((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.pBuffer;
        usCounter = (USHORT)((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.Length;

        //calculate the hash of module
        if (firstHash == 0) {
            firstHash = Hasher(val2, usCounter, TRUE, BYOUD_RND_SEED);;
        }
        else {
            currentHash = Hasher(val2, usCounter, TRUE, BYOUD_RND_SEED);;
            // compare the hash of module
            if (currentHash == TargetHash) {
                //return module address if found
                dll = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)val1)->DllBase;
                return dll;
            }
        }

        val1 = DEREF(val1);
    }
    return 0;
}

UINT64 GetSymbolAddress2(DWORD ModuleHash, DWORD FunctionHash) {

    HMODULE hMod = (HMODULE)GetModule(ModuleHash);
    if (hMod == NULL) {
        return 0;
    }

    return GetSymbolAddress(hMod, FunctionHash);

}

DWORD FindCallInstructionOffset(uint64_t startAddress, DWORD searchLimit) {

    DWORD offset = 0;
    DWORD callOffset = 0;
    DWORD staticOffset = 4; // Size of CALL instruction
    BOOL found = FALSE;

    while (offset < searchLimit) {
        if (*(BYTE*)(startAddress + offset) == CALL_NEAR || *(WORD*)(startAddress + offset) == CALL_NEAR_QPTR || (*(DWORD*)(startAddress + offset) & 0x00ffffff) == CALL_FAR_QPTR) {
            if ((*(DWORD*)(startAddress + offset) & 0x00ffffff) == CALL_FAR_QPTR) {
                callOffset += 3;
            }
            else if (*(WORD*)(startAddress + offset) == CALL_NEAR_QPTR) {
                callOffset += 2;
            }
            else {
                callOffset++;
            }
            found = TRUE;
            break;
        }
        offset++;
    }

    if (found) {
        return (offset + staticOffset + callOffset);
    }
    return 0;

}

UINT64 GetSymbolAddress(HMODULE hModule, DWORD FunctionHash) {
    if (hModule == NULL) return 0;

    UINT64 dllAddress = (UINT64)hModule;
    UINT64 symbolAddress = 0;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + ((PIMAGE_DOS_HEADER)dllAddress)->e_lfanew);
    PIMAGE_DATA_DIRECTORY dataDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllAddress + dataDirectory->VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)(dllAddress + exportDirectory->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)(dllAddress + exportDirectory->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)(dllAddress + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* cpExportedFunctionName = (char*)(dllAddress + addressOfNames[i]);
        if (!cpExportedFunctionName) continue;

        USHORT nameLen = (USHORT)internal_strlen(cpExportedFunctionName);
        DWORD hash = Hasher(cpExportedFunctionName, nameLen, FALSE, BYOUD_RND_SEED);

        if (FunctionHash == hash) {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD functionRVA = addressOfFunctions[ordinal];
            symbolAddress = dllAddress + functionRVA;
            break;
        }
    }

    return symbolAddress;
}

void GetSectionInfo(HMODULE hModule, PCHAR sectionName, PSECTION_INFO pSectionInfo) {
    if (!hModule)
        return;

    // Parse DOS header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    // Parse NT headers
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return;

    size_t sectionNameLength = internal_strlen(sectionName);

    // Locate section headers
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    WORD numSections = pNtHeaders->FileHeader.NumberOfSections;

    for (int i = 0; i < numSections; ++i, ++pSection)
    {
        if (internal_memcmp(pSection->Name, (char*)sectionName, sectionNameLength) == 0)
        {
            pSectionInfo->Address = (void*)((BYTE*)hModule + pSection->VirtualAddress);
            pSectionInfo->Size = (size_t)pSection->Misc.VirtualSize;
            return;
        }
    }

    return;

}

void GetTextSectionInfo(HMODULE hModule, PSECTION_INFO pSectionInfo)
{
    const char sectionName[] = { '.', 't', 'e', 'x', 't', '\0' };
    GetSectionInfo(hModule, (PCHAR)sectionName, pSectionInfo);
}

void GetRdataSectionInfo(HMODULE hModule, PSECTION_INFO pSectionInfo)
{
    const char sectionName[] = { '.', 'r', 'd', 'a', 't', 'a', '\0' };
    GetSectionInfo(hModule, (PCHAR)sectionName, pSectionInfo);
}

void GetDataSectionInfo(HMODULE hModule, PSECTION_INFO pSectionInfo)
{
    const char sectionName[] = { '.', 'd', 'a', 't', 'a', '\0' };
    GetSectionInfo(hModule, (PCHAR)sectionName, pSectionInfo);
}

void GetPdataSectionInfo(HMODULE hModule, PSECTION_INFO pSectionInfo)
{
    const char sectionName[] = { '.', 'p', 'd', 'a', 't', 'a', '\0' };
    GetSectionInfo(hModule, (PCHAR)sectionName, pSectionInfo);
}


UINT64 GetSymbolOffset(HMODULE hModule, DWORD FunctionHash) {
    if (hModule == NULL) return 0;

    UINT64 dllAddress = (UINT64)hModule;
    UINT64 symbolAddress = GetSymbolAddress(hModule, FunctionHash);
    if (symbolAddress == 0) {
        return 0; // Symbol not found
    }
    return (symbolAddress - dllAddress);


}

char* GetSymbolNameByOffset(HMODULE hModule, UINT64 offset) {
    UINT64 dllAddress = (UINT64)hModule,
        symbolAddress = 0;

    if (hModule == NULL) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

    ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + ((PIMAGE_DOS_HEADER)dllAddress)->e_lfanew);
    dataDirectory = (PIMAGE_DATA_DIRECTORY)&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllAddress + dataDirectory->VirtualAddress);

    LPDWORD exportedAddressTable = (LPDWORD)(dllAddress + exportDirectory->AddressOfFunctions);
    LPDWORD namePointerTable = (LPDWORD)(dllAddress + exportDirectory->AddressOfNames);
    LPWORD ordinalTable = (LPWORD)(dllAddress + exportDirectory->AddressOfNameOrdinals);

    char* currProcName;

    for (SIZE_T i = 0; i < exportDirectory->NumberOfNames; i++) {
        // Get current function name
        currProcName = (LPSTR)((LPBYTE)hModule + namePointerTable[i]);

        // Get current function address
        if (exportedAddressTable[ordinalTable[i]] == offset) {
            return currProcName;
        }

    }

    return NULL;
}


PVOID GetExceptionDirectoryAddress(HMODULE hModule, DWORD* tSize)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD64)hModule + dosHeader->e_lfanew);
    PIMAGE_DATA_DIRECTORY dirAddress = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    printf("DataDirectory[3] address: 0x%p\n", (void*)dirAddress);

    DWORD64 exceptionDirectoryRVA = ntHeader->OptionalHeader.DataDirectory[3].VirtualAddress;
    *tSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    DWORD64 imageExceptionDirectory = (DWORD64)((DWORD_PTR)hModule + exceptionDirectoryRVA);
    return (PVOID)imageExceptionDirectory;

}

PVOID GetExportDirectoryAddress(HMODULE hModule, DWORD* tSize)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD64)hModule + dosHeader->e_lfanew);
    DWORD_PTR exportDirectoryRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    *tSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    DWORD64 imageExportDirectory = (DWORD64)((DWORD_PTR)hModule + exportDirectoryRVA);

    return (PVOID)imageExportDirectory;
}

