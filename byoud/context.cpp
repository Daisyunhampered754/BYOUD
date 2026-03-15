#include "pch.h"
#include "context.h"
#include "primitives.h"
#include "resolver.h"
#include <stdio.h>
#include "unwind.h"

void ByoudContextInit(PBYOUD_CONTEXT ctx, DWORD technique, HMODULE hTarget)
{
    memset(ctx, 0, sizeof(BYOUD_CONTEXT));
    ctx->Technique = technique;
    ctx->hTargetModule = hTarget;
}

BOOL ByoudPushChange(PBYOUD_CONTEXT ctx, PBYOUD_CHANGE change)
{
    if (ctx->Count >= BYOUD_MAX_CHANGES) {
        printf("[!] BYOUD_CONTEXT overflow\n");
        return FALSE;
    }
    ctx->Changes[ctx->Count++] = *change;
    return TRUE;
}

BOOL ByoudTrackCacheZero(PBYOUD_CONTEXT ctx, ULONG64 addr, DWORD oldValue)
{
    BYOUD_CHANGE c;
    memset(&c, 0, sizeof(c));
    c.Type = BCT_CACHE_ZERO;
    c.u.Cache.Address = addr;
    c.u.Cache.OldValue = oldValue;
    return ByoudPushChange(ctx, &c);
}

BOOL ByoudTrackPdataProtect(PBYOUD_CONTEXT ctx, BYOUD_CHANGE_TYPE type,
    HMODULE hModule, PVOID base, SIZE_T size, DWORD oldProtect)
{
    BYOUD_CHANGE c;
    memset(&c, 0, sizeof(c));
    c.Type = type;
    c.u.Pdata.hModule = hModule;
    c.u.Pdata.Base = base;
    c.u.Pdata.Size = size;
    c.u.Pdata.OldProtect = oldProtect;
    return ByoudPushChange(ctx, &c);
}

BOOL ByoudTrackInvertedTableShrink(PBYOUD_CONTEXT ctx, HMODULE hModule, ULONG oldSize)
{
    BYOUD_CHANGE c;
    memset(&c, 0, sizeof(c));
    c.Type = BCT_INVERTED_TABLE_SHRINK;
    c.u.InvertedTable.hModule = hModule;
    c.u.InvertedTable.OldImageSize = oldSize;
    return ByoudPushChange(ctx, &c);
}

BOOL ByoudTrackDynamicAdd(PBYOUD_CONTEXT ctx, PRUNTIME_FUNCTION pFT)
{
    BYOUD_CHANGE c;
    memset(&c, 0, sizeof(c));
    c.Type = BCT_DYNAMIC_TABLE_ADD;
    c.u.DynamicAdd.pFunctionTable = pFT;
    return ByoudPushChange(ctx, &c);
}

BOOL ByoudTrackDynamicType(PBYOUD_CONTEXT ctx, PVOID pEntry, DWORD oldType)
{
    BYOUD_CHANGE c;
    memset(&c, 0, sizeof(c));
    c.Type = BCT_DYNAMIC_TABLE_TYPE;
    c.u.DynamicType.pEntry = pEntry;
    c.u.DynamicType.OldType = oldType;
    return ByoudPushChange(ctx, &c);
}

BOOL ByoudTrackRuntimeFunction(PBYOUD_CONTEXT ctx, HMODULE hModule,
    PRUNTIME_FUNCTION pLocation, PRUNTIME_FUNCTION pOldValue)
{
    BYOUD_CHANGE c;
    memset(&c, 0, sizeof(c));
    c.Type = BCT_RUNTIME_FUNCTION;
    c.u.RuntimeFunction.hModule = hModule;
    c.u.RuntimeFunction.pOriginalLocation = pLocation;
    c.u.RuntimeFunction.OldValue = *pOldValue;
    return ByoudPushChange(ctx, &c);
}

BOOL ByoudTrackUnwindInfo(PBYOUD_CONTEXT ctx, PVOID pLocation, PVOID pBackup, DWORD size)
{
    BYOUD_CHANGE c;
    memset(&c, 0, sizeof(c));
    c.Type = BCT_UNWIND_INFO;
    c.u.UnwindInfo.pLocation = pLocation;
    c.u.UnwindInfo.pBackup = pBackup;
    c.u.UnwindInfo.Size = size;
    return ByoudPushChange(ctx, &c);
}

BOOL ByoudTrackShellcodeAppended(PBYOUD_CONTEXT ctx,
    HMODULE hModule, PVOID pAddress, DWORD size)
{
    BYOUD_CHANGE c;
    memset(&c, 0, sizeof(c));
    c.Type = BCT_SHELLCODE_APPENDED;
    c.u.ShellcodeAppended.hModule = hModule;
    c.u.ShellcodeAppended.pAddress = pAddress;
    c.u.ShellcodeAppended.Size = size;
    return ByoudPushChange(ctx, &c);
}

BOOL ByoudTrackShellcodeVA(PBYOUD_CONTEXT ctx, PVOID pAddress, SIZE_T size)
{
    BYOUD_CHANGE c;
    memset(&c, 0, sizeof(c));
    c.Type = BCT_SHELLCODE_VIRTUALALLOC;
    c.u.ShellcodeVA.pAddress = pAddress;
    c.u.ShellcodeVA.Size = size;
    return ByoudPushChange(ctx, &c);
}

BOOL ByoudRestoreAll(PBYOUD_CONTEXT ctx)
{
    BOOL  allOk = TRUE;
    INT   i;
    DWORD dummy;

    for (i = (INT)ctx->Count - 1; i >= 0; i--) {
        PBYOUD_CHANGE c = &ctx->Changes[i];

        switch (c->Type) {

        case BCT_CACHE_ZERO:
            VirtualProtect((PVOID)c->u.Cache.Address, sizeof(DWORD), PAGE_READWRITE, &dummy);
            *(DWORD*)c->u.Cache.Address = c->u.Cache.OldValue;
            VirtualProtect((PVOID)c->u.Cache.Address, sizeof(DWORD), PAGE_READONLY, &dummy);
            printf("[+] Cache restored @ 0x%016llX = 0x%08X\n",
                c->u.Cache.Address, c->u.Cache.OldValue);
            break;

        case BCT_PDATA_PROTECT:
        case BCT_PDATA_NOACCESS:
            if (!VirtualProtect(c->u.Pdata.Base, c->u.Pdata.Size,
                c->u.Pdata.OldProtect, &dummy)) {
                printf("[!] Failed to restore .pdata protect: 0x%08X\n", GetLastError());
                allOk = FALSE;
            }
            else {
                printf("[+] .pdata protection restored -> 0x%08X\n", c->u.Pdata.OldProtect);
            }
            break;

        case BCT_INVERTED_TABLE_SHRINK: {
            RestoreInvertedFunctionTableEntry(
                c->u.InvertedTable.hModule,
                c->u.InvertedTable.OldImageSize);
            printf("[+] LdrpInvertedFunctionTable ImageSize restored -> 0x%X\n",
                c->u.InvertedTable.OldImageSize);
            break;
        }

        case BCT_DYNAMIC_TABLE_ADD:
            if (!RtlDeleteFunctionTable(c->u.DynamicAdd.pFunctionTable)) {
                printf("[!] RtlDeleteFunctionTable failed\n");
                allOk = FALSE;
            }
            else {
                free(c->u.DynamicAdd.pFunctionTable);
                printf("[+] RtlDeleteFunctionTable succeeded\n");
            }
            break;

        case BCT_DYNAMIC_TABLE_TYPE: {
            PDWORD pType = (PDWORD)((ULONG64)c->u.DynamicType.pEntry + 0x50);
            *pType = c->u.DynamicType.OldType;
            printf("[+] DYNAMIC_FUNCTION_TABLE Type restored -> %u\n",
                c->u.DynamicType.OldType);
            break;
        }

        case BCT_RUNTIME_FUNCTION:
            UnprotectPdata(c->u.RuntimeFunction.hModule);
            *c->u.RuntimeFunction.pOriginalLocation = c->u.RuntimeFunction.OldValue;
            ProtectPdata(c->u.RuntimeFunction.hModule);
            printf("[+] RUNTIME_FUNCTION restored @ 0x%p\n",
                c->u.RuntimeFunction.pOriginalLocation);
            break;

        case BCT_UNWIND_INFO:
            UnprotectRdata(NULL);
            memcpy(c->u.UnwindInfo.pLocation,
                c->u.UnwindInfo.pBackup,
                c->u.UnwindInfo.Size);
            ProtectRdata(NULL);
            free(c->u.UnwindInfo.pBackup);
            printf("[+] UNWIND_INFO restored @ 0x%p\n", c->u.UnwindInfo.pLocation);
            break;

        case BCT_SHELLCODE_APPENDED: {
            DWORD oldProtect2;
            VirtualProtect(c->u.ShellcodeAppended.pAddress,
                c->u.ShellcodeAppended.Size,
                PAGE_EXECUTE_READWRITE, &oldProtect2);
            ZeroMemory(c->u.ShellcodeAppended.pAddress, c->u.ShellcodeAppended.Size);
            VirtualProtect(c->u.ShellcodeAppended.pAddress,
                c->u.ShellcodeAppended.Size,
                oldProtect2, &dummy);
            printf("[+] Appended shellcode zeroed @ 0x%p\n",
                c->u.ShellcodeAppended.pAddress);
            break;
        }

        case BCT_SHELLCODE_VIRTUALALLOC:
            ZeroMemory(c->u.ShellcodeVA.pAddress, c->u.ShellcodeVA.Size);
            VirtualFree(c->u.ShellcodeVA.pAddress, 0, MEM_RELEASE);
            printf("[+] VirtualAlloc shellcode freed @ 0x%p\n",
                c->u.ShellcodeVA.pAddress);
            break;

        default:
            break;
        }
    }

    ctx->Count = 0;
    return allOk;
}