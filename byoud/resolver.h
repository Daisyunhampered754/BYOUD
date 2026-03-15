#pragma once
#define _CRT_SECURE_NO_WARNINGS 1

#include <windows.h>
#include <stdint.h>
#include <inttypes.h>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

#define CURRENT_PROCESS ((HANDLE)0xFFFFFFFFFFFFFFFF)

#define NTDLL 0xe63ef1dd
#define KERNEL32 0x060f1d61
#define KERNELBASE 0x4136ec56
#define VCRUNTIME140D 0x3fde5226
#define UCRTBASED 0xd3d3e02d
#define RPCRT4 0x2532faa1

// KB
#define VirtualAlloc_H 0x0318940b
#define VirtualAllocEx_H 0xfa1390d6
#define VirtualFree_H 0x0f04aaec
#define VirtualFreeEx_H 0x00e8a3e4
#define VirtualProtectEx_H 0xe3d2bad1
#define WriteProcessMemory_H 0x4766169e

// K32
#define RtlZeroMemory_H 0x02d05339
#define BaseThreadInitThunk_H 0x2b0fba56

// RPCRT4
#define I_RpcPauseExecution 0x770b01cf
#define I_RpcServerInqAddressChangeFn 0x0312d70b
#define I_RpcServerRegisterForwardFunction 0xeffba0e6
#define I_RpcServerSetAddressChangeFn 0x06fdbb16
#define I_RpcBindingInqDynamicEndpointA 0x3d1aa8ce
#define RpcAsyncRegisterInfo 0x08cab106 // NOP

#define BYOUD_RND_SEED 0x138C1F16
#define ROL8(v) (v << 8 | v >> 24)
#define ROR8(v) (v >> 8 | v << 24)
#define ROX8(v) ((BYOUD_RND_SEED % 2) ? ROL8(v) : ROR8(v))

#define CALL_NEAR		0xe8	    // 1 bytes,	0xe8						+ 4 bytes offset
#define CALL_NEAR_QPTR	0xff15	    // 2 bytes, 0xff 0x15 -> reversed		+ 4 bytes offset 
#define CALL_FAR_QPTR	0x0015ff48  // 3 bytes, appended 0 for DWORD , needs shifting on compare - 0x48 0xff 0x15 -> reversed  + 4 bytes offset

typedef struct {
    uint8_t bytes[8];     // max size = 3 + 3 + padding
    uint8_t mask[8];
    size_t size;
} GADGET_PATTERN;

typedef HMODULE(WINAPI* LoadLibraryAType)(LPCSTR lpLibFileName);
typedef int(WINAPI* MessageBoxAType)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

typedef PIMAGE_RUNTIME_FUNCTION_ENTRY PERF;

typedef struct _dll {

    HMODULE                 Handle;
    UINT64                  TextSectionAddress;
    UINT64                  TextSectionSize;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    PERF                    ExceptionTable;
    DWORD                   ExceptionTableLastEntryIndex;

} DLL, * PDLL;

//redefine UNICODE_STR struct
typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

//redefine PEB_LDR_DATA struct
typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

//redefine LDR_DATA_TABLE_ENTRY struct
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//redefine PEB_FREE_BLOCK struct
typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

//redefine PEB struct
typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct _SECTION_INFO {
    void* Address;     // VA of .text section
    size_t Size;       // Virtual size of .text section
} SECTION_INFO, * PSECTION_INFO;

void GetTextSectionInfo(HMODULE hModule, PSECTION_INFO pSectionInfo);
void GetRdataSectionInfo(HMODULE hModule, PSECTION_INFO pSectionInfo);
void GetPdataSectionInfo(HMODULE hModule, PSECTION_INFO pSectionInfo);
void GetDataSectionInfo(HMODULE hModule, PSECTION_INFO pSectionInfo);

DWORD Hasher(const void* data, size_t length, BOOL isWide, DWORD hash);
UINT64 GetModule(DWORD TargetHash);
UINT64 GetSymbolAddress(HMODULE hModule, DWORD dwProcNameHash);
UINT64 GetSymbolAddress2(DWORD dwModHash, DWORD dwProcNameHash);
UINT64 GetSymbolOffset(HMODULE hModule, DWORD FunctionHash);
char* GetSymbolNameByOffset(HMODULE hModule, UINT64 offset);
PVOID GetExceptionDirectoryAddress(HMODULE hModule, DWORD* tSize);
PVOID GetExportDirectoryAddress(HMODULE hModule, DWORD* tSize);
DWORD FindCallInstructionOffset(uint64_t startAddress, DWORD searchLimit);
