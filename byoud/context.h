#pragma once
#include <windows.h>

/* ---------------------------------------------------------------
 * Change record types
 * --------------------------------------------------------------- */
typedef enum _BYOUD_CHANGE_TYPE {
    BCT_NONE = 0,
    BCT_CACHE_ZERO,
    BCT_PDATA_PROTECT,
    BCT_PDATA_NOACCESS,
    BCT_INVERTED_TABLE_SHRINK,
    BCT_DYNAMIC_TABLE_ADD,
    BCT_DYNAMIC_TABLE_TYPE,
    BCT_RUNTIME_FUNCTION,
    BCT_UNWIND_INFO,
    BCT_SHELLCODE_APPENDED,
    BCT_SHELLCODE_VIRTUALALLOC,
} BYOUD_CHANGE_TYPE;

/* ---------------------------------------------------------------
 * Per-change payload
 * --------------------------------------------------------------- */
typedef struct _BYOUD_CHANGE {
    BYOUD_CHANGE_TYPE Type;

    union {
        struct { ULONG64 Address; DWORD OldValue; } Cache;
        struct { HMODULE hModule; PVOID Base; SIZE_T Size; DWORD OldProtect; } Pdata;
        struct { HMODULE hModule; ULONG OldImageSize; } InvertedTable;
        struct { PRUNTIME_FUNCTION pFunctionTable; } DynamicAdd;
        struct { PVOID pEntry; DWORD OldType; } DynamicType;
        struct {
            HMODULE hModule; PRUNTIME_FUNCTION pOriginalLocation;
            RUNTIME_FUNCTION OldValue;
        } RuntimeFunction;
        struct { PVOID pLocation; PVOID pBackup; DWORD Size; } UnwindInfo;
        struct { HMODULE hModule; PVOID pAddress; DWORD Size; } ShellcodeAppended;
        struct { PVOID pAddress; SIZE_T Size; } ShellcodeVA;
    } u;
} BYOUD_CHANGE, * PBYOUD_CHANGE;

/* ---------------------------------------------------------------
 * Change log
 * --------------------------------------------------------------- */
#define BYOUD_MAX_CHANGES 32

typedef struct _BYOUD_CONTEXT {
    BYOUD_CHANGE Changes[BYOUD_MAX_CHANGES];
    DWORD        Count;
    DWORD        Technique;
    HMODULE      hTargetModule;
    PVOID        pShellcodeAddress;
    DWORD        ShellcodeSize;
} BYOUD_CONTEXT, * PBYOUD_CONTEXT;

/* ---------------------------------------------------------------
 * API
 * --------------------------------------------------------------- */
void ByoudContextInit(PBYOUD_CONTEXT ctx, DWORD technique, HMODULE hTarget);
BOOL ByoudPushChange(PBYOUD_CONTEXT ctx, PBYOUD_CHANGE change);
BOOL ByoudRestoreAll(PBYOUD_CONTEXT ctx);

BOOL ByoudTrackCacheZero(PBYOUD_CONTEXT ctx, ULONG64 addr, DWORD oldValue);
BOOL ByoudTrackPdataProtect(PBYOUD_CONTEXT ctx, BYOUD_CHANGE_TYPE type,
    HMODULE hModule, PVOID base, SIZE_T size, DWORD oldProtect);
BOOL ByoudTrackInvertedTableShrink(PBYOUD_CONTEXT ctx, HMODULE hModule, ULONG oldSize);
BOOL ByoudTrackDynamicAdd(PBYOUD_CONTEXT ctx, PRUNTIME_FUNCTION pFT);
BOOL ByoudTrackDynamicType(PBYOUD_CONTEXT ctx, PVOID pEntry, DWORD oldType);
BOOL ByoudTrackRuntimeFunction(PBYOUD_CONTEXT ctx, HMODULE hModule,
    PRUNTIME_FUNCTION pLocation, PRUNTIME_FUNCTION pOldValue);
BOOL ByoudTrackUnwindInfo(PBYOUD_CONTEXT ctx, PVOID pLocation,
    PVOID pBackup, DWORD size);
BOOL ByoudTrackShellcodeAppended(PBYOUD_CONTEXT ctx,
    HMODULE hModule, PVOID pAddress, DWORD size);
BOOL ByoudTrackShellcodeVA(PBYOUD_CONTEXT ctx, PVOID pAddress, SIZE_T size);