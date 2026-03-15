#pragma once
#include <Windows.h>
#include "unwind.h"
#include "context.h"

#define UNWIND_DATA_TAMPER   0x000f0000
#define UNWIND_DATA_HIJACK   0x0000f000
#define RT_FUNCTION_HIJACK   0x00000f00
#define RT_FUNCTION_INJECT   0x000000f0
#define RTFI_JIT_SYSINFORMER 0x0000000f
#define RTFI_JIT_WINDBG      0x0f000000
#define RTFI_JIT_NORMAL_VA   0x00f00000

typedef struct _CALLGATE_PARAMS {
    UINT64 pFunction;
    UINT64 dwMinimumFrameSize;
    UINT64 argc;
    UINT64 argv[ANYSIZE_ARRAY];
} CALLGATE_PARAMS, * PCALLGATE_PARAMS;

typedef struct _CALLGATE_COPY_INFO {
    PVOID  pSourceAddress;
    DWORD  dwSize;
    PVOID  pCopiedAddress;
} CALLGATE_COPY_INFO, * PCALLGATE_COPY_INFO;

typedef UINT64(*CallGateFn)(PCALLGATE_PARAMS);

/* ---------------------------------------------------------------
 * Unwind tampering
 * --------------------------------------------------------------- */
BOOL TamperUnwind(PUNWIND_INFO tInfo, DWORD dwNewSize, DWORD* pdwOldSize);
BOOL ChangeUnwind(PUNWIND_INFO tInfo, DWORD dwNewSize, DWORD* pdwOldSize);
BOOL ChangeUnwindInfoExceptionAddress(HMODULE hModule, PUNWIND_INFO tInfo, DWORD newAddress);

/* ---------------------------------------------------------------
 * Runtime function manipulation
 * --------------------------------------------------------------- */
BOOL HijackUnwindInfoAddress(HMODULE hModule, PRUNTIME_FUNCTION pRuntimeFunction,
    DWORD dwDesiredSize, BOOL strict, PDWORD pdwActualSize,
    PRUNTIME_FUNCTION_BACKUP* ppRuntimeFunctionBackup);

BOOL HijackRuntimeFunction(HMODULE hModule, PRUNTIME_FUNCTION pRuntimeFunction,
    DWORD dwDesiredSize, BOOL strict, PDWORD pdwActualSize,
    PRUNTIME_FUNCTION_BACKUP* ppRuntimeFunctionBackup);

BOOL RuntimeFunctionInstallCustomUnwind(ULONG64 BaseAddress, DWORD dwShcOffset,
    DWORD dwShcSize, DWORD dwFrameSize, PDWORD pdwActualSize,
    PRUNTIME_FUNCTION_BACKUP* ppRuntimeFunctionBackup);

/* JIT install — now tracked via BYOUD_CONTEXT, no PRUNTIME_FUNCTION_BACKUP */
BOOL RuntimeFunctionInstall(PBYOUD_CONTEXT ctx, HMODULE hModule,
    DWORD dwShcOffset, DWORD dwShcSize, DWORD dwDesiredSize, PDWORD pdwActualSize);

BOOL RuntimeFunctionInstallWinDbg(PBYOUD_CONTEXT ctx, HMODULE hModule,
    DWORD dwShcOffset, DWORD dwShcSize, DWORD dwDesiredSize, PDWORD pdwActualSize);

/* ---------------------------------------------------------------
 * Search helper
 * --------------------------------------------------------------- */
PRUNTIME_FUNCTION SearchRtFunctionWithSpecificSize(HMODULE moduleBase,
    DWORD dwFrameSize, BOOL strict, PDWORD pdwActualSize);

/* ---------------------------------------------------------------
 * Pdata / cache helpers
 * --------------------------------------------------------------- */
BOOL SuppressPdataAccess(HMODULE hModule, PDWORD pOldProtect);
BOOL RestorePdataAccess(HMODULE hModule, DWORD oldProtect);
BOOL ZeroOutPdata(HMODULE hModule, PVOID* ppOriginalPdata, SIZE_T* pPdataSize);
BOOL RestorePdata(HMODULE hModule, PVOID pOriginalPdata, SIZE_T pdataSize);
BOOL RecommitAsPrivate(PVOID ShcAddress, SIZE_T ShcSize);

BOOL InvalidateFunctionTableCache(PULONG64 pCachedSizeAddr, PDWORD pOldSize);
BOOL InvalidateFunctionEntryCache(PULONG64 pCachedSizeAddr, PDWORD pOldSize);
BOOL RestoreFunctionTableCache(ULONG64 oldBase, DWORD oldSize);

/* ---------------------------------------------------------------
 * CallGate helpers
 * --------------------------------------------------------------- */
PCALLGATE_PARAMS BuildCallGateParamsFromArray(PVOID pFunction, DWORD dwFrameSize,
    UINT64 argc, PUINT64 argv);
PCALLGATE_PARAMS BuildCallGateParams(PVOID pFunction, DWORD dwFrameSize,
    UINT64 argc, ...);

BOOL GetCallGateInfo(PCALLGATE_COPY_INFO pInfo);
BOOL CopyCallGateTo(PVOID pDestination, PCALLGATE_COPY_INFO pInfo);
BOOL RelocateCallGate(HMODULE hTargetModule);
HMODULE GetCurrentModule(void);

/* ---------------------------------------------------------------
 * Allocation helpers
 * --------------------------------------------------------------- */
void* AllocateAdjacentToModule(HMODULE targetModule, SIZE_T size,
    SIZE_T maxDistance, DWORD protect);

void* AllocateAdjacentToModuleBidirectional(HMODULE targetModule, SIZE_T size,
    SIZE_T maxDistance, DWORD protect);

SIZE_T DistanceFromModule(HMODULE targetModule, void* address);

/* ---------------------------------------------------------------
 * Diagnostic / test helpers
 * --------------------------------------------------------------- */
BOOL TestStackWalk64(CONTEXT* pCtx);
BOOL TestStackWalk64Callback(CONTEXT* pCtx);
BOOL TestUnwindRegistration(ULONG64 ShcAddress, ULONG64 BaseAddress, DWORD frameSize);

/* ---------------------------------------------------------------
 * RailGun and exported API — must be extern "C" to match the
 * undecorated names expected by the .asm stub and the linker
 * /EXPORT pragmas in byoud.c
 * --------------------------------------------------------------- */
#ifdef __cplusplus
extern "C" {
#endif

    /* RailGun — assembly stub, undecorated name */
    UINT64 RailGun(LPVOID fPtr, DWORD argc, DWORD64* argv, DWORD64 dwStackAlloc);

    /* Exported API
     * RegisterShellcode  — takes PBYOUD_CONTEXT, drops PRUNTIME_FUNCTION_BACKUP
     * UnRegisterShellcode — takes PBYOUD_CONTEXT, calls ByoudRestoreAll
     * ShieldedExecution  — unchanged externally
     * CallGate           — assembly stub, unchanged
     */
    __declspec(dllexport) UINT64 CALLBACK ShieldedExecution(HMODULE hModule,
        LPSTR lpFunctionName, DWORD dwArgc, DWORD64* pqwArgv, DWORD technique);

    __declspec(dllexport) BOOL RegisterShellcode(PBYOUD_CONTEXT ctx, LPCSTR dllName,
        DWORD unwindSize, PDWORD pActualSize, DWORD technique,
        PCALLGATE_COPY_INFO pCopyInfo);

    __declspec(dllexport) BOOL UnRegisterShellcode(PBYOUD_CONTEXT ctx);

    __declspec(dllexport) UINT64 CALLBACK CallGate(PCALLGATE_PARAMS params);

#ifdef __cplusplus
}
#endif