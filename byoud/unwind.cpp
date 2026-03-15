/*
    BYOUD
    Copyright (C) 2025-2026  Alessandro Magnosi (aka klezVirus)

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
#include "unwind.h"
#include "resolver.h"
#include "primitives.h"
#include "dbg.h"
#include <Psapi.h>


BYTE ExtractOpInfo(BYTE OpIC) {
    return OpIC >> 4;
}

BYTE ExtractOpCode(BYTE OpIC) {
    return OpIC & 0x0F;
}

char* GetOpInfo(int op) {
    char* reg = (char*)malloc(4);
    if (reg == NULL) {
        return NULL;
    }

    internal_memset(reg, 0, 4);

    if (op == 0) {
        char rreg[4] = {'R', 'A', 'X', '\0'};
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 1) {
        char rreg[4] = { 'R', 'C', 'X', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 2) {
        char rreg[4] = { 'R', 'D', 'X', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 3) {
        char rreg[4] = { 'R', 'B', 'X', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 4) {
        char rreg[4] = { 'R', 'S', 'P', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 5) {
        char rreg[4] = { 'R', 'B', 'P', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 6) {
        char rreg[4] = { 'R', 'S', 'I', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 7) {
        char rreg[4] = { 'R', 'D', 'I', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 8) {
        char rreg[4] = { 'R', '8', '\0', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 9) {
        char rreg[4] = { 'R', '9', '\0', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 10) {
        char rreg[4] = { 'R', '1', '0', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 11) {
        char rreg[4] = { 'R', '1', '1', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 12) {
        char rreg[4] = { 'R', '1', '2', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 13) {
        char rreg[4] = { 'R', '1', '3', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 14) {
        char rreg[4] = { 'R', '1', '4', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    else if (op == 15) {
        char rreg[4] = { 'R', '1', '5', '\0' };
        internal_memcpy(reg, rreg, 4);
    }
    return reg;
}

DWORD SizeOfUnwind(PUNWIND_INFO pInfo) {

    DWORD size = 4; // header

    size += pInfo->CountOfCodes * 2;
    size = ALIGN_UP(size, 4);

    if (pInfo->Flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
        size += 4;   // ExceptionHandler / FunctionEntry
        size += 8;   // ExceptionData pointer (x64)
    }
    return size;
}


PUNWIND_BACKUP SaveUnwind(PUNWIND_INFO tInfo) {
    if (tInfo == NULL) {
        return NULL;
    }

    DWORD unwindSize = SizeOfUnwind(tInfo);
    PUNWIND_BACKUP backup = (PUNWIND_BACKUP)malloc(
        sizeof(UNWIND_BACKUP) - 1 + unwindSize
    );

    if (backup == NULL) {
        return NULL;
    }

    backup->pOriginalLocation = tInfo;
    backup->dwSize = unwindSize;
    internal_memcpy(backup->Data, tInfo, unwindSize);

    return backup;
}

BOOL RestoreUnwind(PUNWIND_BACKUP backup) {
    if (backup == NULL || backup->pOriginalLocation == NULL) {
        return FALSE;
    }

    internal_memcpy(
        backup->pOriginalLocation,
        backup->Data,
        backup->dwSize
    );

    return internal_memcmp(
        backup->pOriginalLocation,
        backup->Data,
        backup->dwSize
    ) == 0;
}

// Save a RUNTIME_FUNCTION
PRUNTIME_FUNCTION_BACKUP SaveRuntimeFunction(PRUNTIME_FUNCTION pFunc) {
    if (pFunc == NULL) {
        return NULL;
    }

    PRUNTIME_FUNCTION_BACKUP backup = (PRUNTIME_FUNCTION_BACKUP)malloc(
        sizeof(RUNTIME_FUNCTION_BACKUP)
    );
    if (backup == NULL) {
        return NULL;
    }

    backup->pOriginalLocation = pFunc;
    internal_memcpy(&backup->Data, pFunc, sizeof(RUNTIME_FUNCTION));

    return backup;
}

// Restore RUNTIME_FUNCTION from backup
BOOL RestoreRuntimeFunction(HMODULE hModule, PRUNTIME_FUNCTION_BACKUP backup) {
    if (backup == NULL || backup->pOriginalLocation == NULL) {
        return FALSE;
    }

    internal_memcpy(backup->pOriginalLocation, &backup->Data, sizeof(RUNTIME_FUNCTION));

    // Re-sort to restore original order
    DWORD pdataSize = 0;
    PRUNTIME_FUNCTION table = (PRUNTIME_FUNCTION)GetExceptionDirectoryAddress(hModule, &pdataSize);
    DWORD count = pdataSize / sizeof(RUNTIME_FUNCTION);
    qsort(table, count, sizeof(RUNTIME_FUNCTION), [](const void* a, const void* b) {
        return (int)(((PRUNTIME_FUNCTION)a)->BeginAddress - ((PRUNTIME_FUNCTION)b)->BeginAddress);
        });

    return TRUE;
}

void FreeUnwindBackup(PUNWIND_BACKUP backup) {
    if (backup != NULL) {
        free(backup);
    }
}

void FreeRuntimeFunctionBackup(PRUNTIME_FUNCTION_BACKUP backup) {
    if (backup != NULL) {
        free(backup);
    }
}

BOOL UnprotectHeaders(HMODULE hMod) {
    printf("Changing NtHeaders protection of 0x%p\n", hMod);
    DWORD oldProtect;
    return VirtualProtectEx(CURRENT_PROCESS, hMod, 0x1000, PAGE_READWRITE, &oldProtect);
}

BOOL ProtectHeaders(HMODULE hMod) {
    printf("Changing NtHeaders protection of 0x%p\n", hMod);
    DWORD oldProtect;

    return VirtualProtectEx(CURRENT_PROCESS, hMod, 0x1000, PAGE_READONLY, &oldProtect);
}

BOOL UnprotectText(HMODULE hMod) {
    SECTION_INFO si;
    GetTextSectionInfo(hMod, &si);
    DWORD oldProtect;
    printf("Changing .text protection of 0x%p\n", si.Address);

    return VirtualProtectEx(CURRENT_PROCESS, si.Address, si.Size, PAGE_EXECUTE_READWRITE, &oldProtect);
}

BOOL ProtectText(HMODULE hMod) {
    SECTION_INFO si;
    GetTextSectionInfo(hMod, &si);
    DWORD oldProtect;
    printf("Changing .text protection of 0x%p\n", si.Address);

    return VirtualProtectEx(CURRENT_PROCESS, si.Address, si.Size, PAGE_EXECUTE_READ, &oldProtect);
}

BOOL UnprotectData(HMODULE hMod) {
    SECTION_INFO si;
    GetDataSectionInfo(hMod, &si);
    DWORD oldProtect;
    printf("Changing protection of 0x%p\n", si.Address);

    return VirtualProtectEx(CURRENT_PROCESS, si.Address, si.Size, PAGE_READWRITE, &oldProtect);
}

BOOL ProtectData(HMODULE hMod) {
    SECTION_INFO si;
    GetDataSectionInfo(hMod, &si);
    DWORD oldProtect;
    printf("Changing protection of 0x%p\n", si.Address);

    return VirtualProtectEx(CURRENT_PROCESS, si.Address, si.Size, PAGE_READONLY, &oldProtect);
}


BOOL UnprotectRdata(HMODULE hMod) {
    SECTION_INFO si;
    GetRdataSectionInfo(hMod, &si);
    DWORD oldProtect;
    printf("Changing protection of 0x%p\n", si.Address);

    return VirtualProtectEx(CURRENT_PROCESS, si.Address, si.Size, PAGE_READWRITE, &oldProtect);
}

BOOL ProtectRdata(HMODULE hMod) {
    SECTION_INFO si;
    GetRdataSectionInfo(hMod, &si);
    DWORD oldProtect;
    printf("Changing protection of 0x%p\n", si.Address);

    return VirtualProtectEx(CURRENT_PROCESS, si.Address, si.Size, PAGE_READONLY, &oldProtect);
}

BOOL UnprotectPdata(HMODULE hMod) {
    SECTION_INFO si;
    GetPdataSectionInfo(hMod, &si);
    DWORD oldProtect;
    printf("Changing protection of 0x%p\n", si.Address);

    return VirtualProtectEx(CURRENT_PROCESS, si.Address, si.Size, PAGE_READWRITE, &oldProtect);
}

BOOL ProtectPdata(HMODULE hMod) {
    SECTION_INFO si;
    GetPdataSectionInfo(hMod, &si);
    DWORD oldProtect;
    printf("Changing protection of 0x%p\n", si.Address);

    return VirtualProtectEx(CURRENT_PROCESS, si.Address, si.Size, PAGE_READONLY, &oldProtect);
}

BOOL ChangeHeadersProtection(HMODULE hModule, DWORD protection, PDWORD oldProtect) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)hModule + dos->e_lfanew);

    SIZE_T headerSize = nt->OptionalHeader.SizeOfHeaders;

    return VirtualProtectEx(CURRENT_PROCESS, hModule, headerSize, protection, oldProtect);
    
}

BOOL IncreaseExceptionDirectorySize(HMODULE hMod, DWORD sizeIncrement) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(hMod + dos->e_lfanew);

    printf("Changing protection of... 0x%llx\n", (UINT64)nt);
    if (!UnprotectPdata(hMod)) {
        printf("VirtualProtect RX failed\n");
        return FALSE;
    }

    DWORD newSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size + sizeIncrement;
    UBYTE* uIncrement = (unsigned char*)((UINT64)newSize);

    // Overwrite the size of the Exception Directory
    printf("Old Exception Dir Size: %u\n", nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
    internal_memcpy((UBYTE*)(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] + 4), uIncrement, 4);  // or 0
    printf("New Exception Dir Size: %u\n", nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);

    // Restore protection
    if (!ProtectPdata(hMod)) {
        printf("VirtualProtect R- failed\n");
        return FALSE;
    }

    return nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size == newSize;
}

UBYTE* FindTextAppendPtr(const SECTION_INFO* si,
    SIZE_T align,
    BOOL include_nops,
    SIZE_T* out_skipped_pad,
    SIZE_T* out_bytes_available)
{
    if (!si || !si->Address || si->Size == 0) return NULL;

    UBYTE* const base = (UBYTE*)si->Address;
    SIZE_T const  size = (si->Size + 0x1000) & 0xFFFFF000;

    // compute last valid byte; guard overflow and size==0 already handled
    UBYTE* p = base + (size - 1);
    printf("Starting scan at 0x%p\n", p);

    SIZE_T skipped = 0;

    // walk backwards over padding
    for (;;)
    {
        if (p < base) break;                // fully consumed the section
        UBYTE b = *p;
        if (b != 0xCC && b != 0x00 && !(include_nops && b == 0x90))
            break;                          // found last non-padding byte
        --p;
        ++skipped;
    }

    // If everything was padding, the last non-padding "byte" is before base.
    // In that case, first free is at the start.
    UBYTE* first_free = (p < base) ? base : (p + 1);

    // Align up if requested
    if (align && (align & (align - 1)) == 0) { // power-of-two check
        uintptr_t v = (uintptr_t)first_free;
        uintptr_t aligned = (v + (align - 1)) & ~(uintptr_t)(align - 1);
        if (aligned < v) return NULL;         // wraparound (shouldn't happen)
        first_free = (UBYTE*)aligned;
    }
    else if (align > 1) {
        // non power-of-two align not supported here
        return NULL;
    }

    // Ensure the aligned pointer still lies within the section
    if (first_free < base || (SIZE_T)(first_free - base) > size)
        return NULL;

    if (out_skipped_pad)      *out_skipped_pad = skipped;
    if (out_bytes_available)  *out_bytes_available = (SIZE_T)(base + size - first_free);

    return first_free;
}


BOOL AppendCodeText(HMODULE hMod, PVOID codeAddress, DWORD codeSize, PDWORD BeginAddress) {


    SECTION_INFO si;
    GetTextSectionInfo(hMod, &si);

    SIZE_T skipped = 0, avail = 0;
    UBYTE* append_at = FindTextAppendPtr(&si, /*align=*/1024, /*include_nops=*/FALSE, &skipped, &avail);

    if (!append_at) {
        printf("Failed to find a suitable append address in .text section\n");
        return FALSE;
    }

    printf("Backword Search result: 0x%llx\n", (UINT64)append_at);
    *BeginAddress = (DWORD)((DWORD64)append_at - (DWORD64)hMod);


    if (!UnprotectText(hMod)) {
        printf("VirtualProtect RWX failed\n");
        return FALSE;
    }

    internal_memcpy((void*)append_at, codeAddress, codeSize);
    // Restore protection
    if (!ProtectText(hMod)) {
        printf("VirtualProtect R-X failed\n");
        return FALSE;
    }
    return TRUE;

}

BOOL AppendRuntimeFunctionToExceptionDirectory(HMODULE hMod, PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFunction) {

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD64)hMod + dosHeader->e_lfanew);
    printf("NtHeaders: 0x%llx\n", (UINT64)nt);
    DWORD64 exceptionDirectoryRVA = nt->OptionalHeader.DataDirectory[3].VirtualAddress;
    DWORD oldSize = nt->OptionalHeader.DataDirectory[3].Size;

    printf("Exception Directory Info: 0x%llx\n", (UINT64)&nt->OptionalHeader.DataDirectory[3]);
    printf("Exception Directory Size Addres: 0x%llx\n", (UINT64)&nt->OptionalHeader.DataDirectory[3].Size);

    // First Unprotect Headers and rewrite Exception Dir Size
    if (!UnprotectHeaders(hMod)) {
        printf("VirtualProtect RW failed\n");
        return FALSE;
    }

    DWORD newSize = oldSize + sizeof(RUNTIME_FUNCTION);
    UBYTE* uIncrement = (unsigned char*)((UINT64)newSize);

    // Overwrite the size of the Exception Directory
    printf("Old Exception Dir Size: %u\n", oldSize);
    internal_memcpy((UBYTE*)(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size), (UBYTE*)&newSize, 4);  // or 0
    printf("New Exception Dir Size: %u\n", nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);

    // Restore protection
    if (!ProtectHeaders(hMod)) {
        printf("VirtualProtect R- failed\n");
        return FALSE;
    }

    printf("Changing protection of... 0x%llx\n", (UINT64)nt);
    if (!UnprotectPdata(hMod)) {
        printf("VirtualProtect RX failed\n");
        return FALSE;
    }

    // Append the new runtime function entry
    PIMAGE_RUNTIME_FUNCTION_ENTRY pNewEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((BYTE*)hMod + exceptionDirectoryRVA + oldSize);
    internal_memcpy(pNewEntry, pRuntimeFunction, sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));

    // Restore protection
    if (!ProtectPdata(hMod)) {
        printf("VirtualProtect R- failed\n");
        return FALSE;
    }
    return TRUE;
}

DWORD FindLastUnwindOffset(UINT64 modulelBase) {

    DWORD                   tSize;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;
    DWORD 				    lastUnwindOffset = 0;
    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress((HMODULE)modulelBase, &tSize));

    DWORD numberOfFunctions = (DWORD)(tSize / 12);
    printf("Number of functions: %u\n", numberOfFunctions);

    for (DWORD i = 0; i < numberOfFunctions; i++)
    {
        if (lastUnwindOffset <= pRuntimeFunctionTable[i].UnwindData) {

            lastUnwindOffset = pRuntimeFunctionTable[i].UnwindData;
        }
    }
    return lastUnwindOffset;
}


BOOL AppendUnwindData(HMODULE hMod, PUNWIND_INFO tInfo, PDWORD address) {

    DWORD dwLastUnwindOffest = FindLastUnwindOffset((UINT64)hMod);
    if (dwLastUnwindOffest <= 0) {
        return FALSE;
    }

    UINT64 destination = (UINT64)hMod + dwLastUnwindOffest;

    printf("Last Unwind Offset: 0x%08x\n", dwLastUnwindOffest);
    printf("Unwind Address: 0x%llx\n", destination);

    if (!UnprotectRdata(hMod)) {
        printf("VirtualProtect RW failed\n");
        return FALSE;
    }

    internal_memcpy((void*)destination, (UBYTE*)((UBYTE*)tInfo), sizeof(UNWIND_INFO));

    if (!ProtectRdata(hMod)) {
        printf("VirtualProtect R- failed\n");
        return FALSE;
    }

    if (internal_memcmp((UBYTE*)((UBYTE*)tInfo), (void*)destination, sizeof(UNWIND_INFO)) == 0) {
        *address = dwLastUnwindOffest;
        return TRUE;
    }
    *address = 0;
    return FALSE;
}

BOOL ChangeExceptionDirectory(HMODULE hMod, DWORD size, DWORD rva) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(hMod + dos->e_lfanew);

    BOOL success = TRUE;
    DWORD oldProtect;

    printf("Changing protection of... 0x%llx\n", (UINT64)nt);
    if (!ChangeHeadersProtection(hMod, PAGE_READWRITE, &oldProtect)) {
        printf("MakeHeadersWritable failed\n");
        return 1;
    }

    UBYTE* nsb = (unsigned char*)((PVOID)((UINT64)size));
    UBYTE* nab = (unsigned char*)((PVOID)((UINT64)rva));

    // Overwrite the size of the Exception Directory
    printf("Old Exception Dir Address: %u\n", nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
    printf("Old Exception Dir Size: %u\n", nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
    
    if(size > 0){
        internal_memcpy((UBYTE*)((UINT64)(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION])+4), nsb, 4);  // or 0
        success = success && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size == size;
    }
    
    if (rva != NULL) {
        internal_memcpy((UBYTE*)(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]), nab, 4);  // or 0
        success = success && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress == rva;
    }

    printf("New Exception Dir Address: %u\n", nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
    printf("New Exception Dir Size: %u\n", nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);

    // Restore protection
    ChangeHeadersProtection(hMod, oldProtect, &oldProtect);
    return success;
}


DWORD GetStackFrameSize(HMODULE hModule, PVOID unwindInfoAddress, DWORD* targetStackOffset) {

    PRUNTIME_FUNCTION   pChainedFunction;

    DWORD               frameSize = 0;
    DWORD               nodeIndex = 0;
    BOOL                UWOP_SET_FPREG_HIT = FALSE;
    PUNWIND_INFO        unwindInfo = (PUNWIND_INFO)unwindInfoAddress;
    PUNWIND_CODE        unwindCode = (PUNWIND_CODE)unwindInfo->UnwindCode;
    MIN_CTX             ctx = MIN_CTX();
    BYTE opInfo = 0;

    // Restore Stack Size
    *targetStackOffset = 0;

    // Initialise context
    internal_memset(&ctx, 0, sizeof(MIN_CTX));
    // printf("The stack is now 0x%I64X\n", *targetOffset);

    while (nodeIndex < unwindInfo->CountOfCodes) {

        switch (unwindCode->UnwindOp) {

        case UWOP_PUSH_NONVOL: // 0

            *targetStackOffset += 8;
            frameSize += 8;
            break;

        case UWOP_ALLOC_LARGE: // 1
            // If the operation info equals 0 -> allocation size / 8 in next slot
            // If the operation info equals 1 -> unscaled allocation size in next 2 slots
            // In any case, we need to advance 1 slot and record the size

            // Skip to next Unwind Code
           // Save OpInfo BEFORE advancing
            opInfo = unwindCode->OpInfo;

            // Advance to first size slot
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            DPRINTUNWINDCODE(unwindCode);
            nodeIndex++;

            if (opInfo == 0) {
                // Size / 8 in one 16-bit slot
                frameSize += (DWORD)unwindCode->FrameOffset * 8;
            }
            else // opInfo == 1
            {
                // 32-bit unscaled size across two slots (little-endian)
                DWORD lowPart = unwindCode->FrameOffset;

                unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
                DPRINTUNWINDCODE(unwindCode);
                nodeIndex++;

                DWORD highPart = unwindCode->FrameOffset;
                frameSize += lowPart | (highPart << 16);
            }

            *targetStackOffset += frameSize;
            break;

        case UWOP_ALLOC_SMALL: // 2

            // Allocate a small-sized area on the stack. The size of the allocation is the operation 
            // info field * 8 + 8, allowing allocations from 8 to 128 bytes.
            *targetStackOffset += 8 * (unwindCode->OpInfo + 1);
            frameSize += 8 * (unwindCode->OpInfo + 1);
            break;


        case UWOP_SET_FPREG: // 3
            // Establish the frame pointer register by setting the register to some offset of the current RSP. 
            // The offset is equal to the Frame Register offset (scaled) field in the UNWIND_INFO * 16, allowing 
            // offsets from 0 to 240. The use of an offset permits establishing a frame pointer that points to the
            // middle of the fixed stack allocation, helping code density by allowing more accesses to use short 
            // instruction forms. The operation info field is reserved and shouldn't be used.
            UWOP_SET_FPREG_HIT = TRUE;

            //frameSize = -0x10 * (unwindInfo->FrameOffset);
            //*targetStackOffset += frameSize;
            break;


        case UWOP_SAVE_NONVOL: // 4
            // Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is 
            // primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack in a position 
            // that was previously allocated. The operation info is the number of the register. The scaled-by-8 
            // stack offset is recorded in the next unwind operation code slot, as described in the note above.
            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            nodeIndex++;

            // For future use
            *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset * 8;
            DPRINTCTX(ctx);

            break;
        case UWOP_SAVE_NONVOL_BIG: // 5
            // Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH. 
            // This code is primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack 
            // in a position that was previously allocated. The operation info is the number of the register. 
            // The unscaled stack offset is recorded in the next two unwind operation code slots, as described 
            // in the note above.

            // For future use
            *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset;
            *((ULONG*)&ctx + unwindCode->OpInfo) += (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 2))->FrameOffset << 16;

            // Skip the other two nodes used for this unwind operation
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;

            DPRINTCTX(ctx);
            break;

        case UWOP_EPILOG:            // 6
        case UWOP_SAVE_XMM128:       // 8
            // Save all 128 bits of a nonvolatile XMM register on the stack. The operation info is the number of 
            // the register. The scaled-by-16 stack offset is recorded in the next slot.

            // TODO: Handle this

            // Skip to next Unwind Code
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
            nodeIndex++;
            break;
        case UWOP_SPARE_CODE:        // 7
        case UWOP_SAVE_XMM128BIG:    // 9
            // Save all 128 bits of a nonvolatile XMM register on the stack with a long offset. The operation info 
            // is the number of the register. The unscaled stack offset is recorded in the next two slots.

            // TODO: Handle this

            // Advancing next 2 nodes
            unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
            nodeIndex += 2;
            break;
        case UWOP_PUSH_MACH_FRAME:    // 10
            // Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception. 
            // There are two forms.

            // NOTE: UNTESTED
            // TODO: Test this
            if (unwindCode->OpInfo == 0) {
                *targetStackOffset += 0x40;
                frameSize += 0x40;
            }
            else {
                *targetStackOffset += 0x48;
                frameSize += 0x48;
            }
            break;
        }

        unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
        nodeIndex++;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (BitChainInfo(unwindInfo->Flags))
    {
        if (hModule == NULL) {
            return frameSize;
        }

        nodeIndex = unwindInfo->CountOfCodes;
        if (0 != (nodeIndex & 1))
        {
            nodeIndex += 1;
        }
        pChainedFunction = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);
        return GetStackFrameSize(hModule, (PUNWIND_INFO)((UINT64)hModule + (DWORD)pChainedFunction->UnwindData), targetStackOffset);
    }

    DBG(printf("Final Frame Size: 0x%x\n", frameSize));
    return frameSize;


}


/*********************************************************************************

    HELPER FUNCTIONS

*********************************************************************************/

void CheckFunction(const char* moduleName, const char* funcName) {
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (!hMod) hMod = LoadLibraryA(moduleName);
    if (!hMod) {
        printf("[%s] Module not found\n", moduleName);
        return;
    }

    FARPROC pFunc = GetProcAddress(hMod, funcName);
    if (!pFunc) {
        printf("[%s!%s] Export not found\n", moduleName, funcName);
        return;
    }

    DWORD64 imageBase;
    PRUNTIME_FUNCTION pRF = RtlLookupFunctionEntry((DWORD64)pFunc, &imageBase, NULL);

    if (pRF) {
        PUNWIND_INFO pUI = (PUNWIND_INFO)(imageBase + pRF->UnwindData);
        printf("[%s!%s] OK - Flags: 0x%02x, Codes: %d\n",
            moduleName, funcName, pUI->Flags, pUI->CountOfCodes);
    }
    else {
        printf("[%s!%s] LEAF FUNCTION - No RUNTIME_FUNCTION\n", moduleName, funcName);
    }
}


void LookupSymbolFromRTIndex(HMODULE dllBase, int rtFuntionIndex, bool verbose) {


    PIMAGE_RUNTIME_FUNCTION_ENTRY rtFunction = RTFindFunctionByIndex((UINT64)dllBase, rtFuntionIndex);

    if (rtFunction == NULL) {
        DBG(printf("Function not found\n"));
        return;
    }

    if (verbose) {
        DBG(printf("Function found:             \n"));
        DBG(printf("  Begin Address 0x%p        \n", (PVOID)(dllBase + rtFunction->BeginAddress)));
        DBG(printf("  End Address 0x%p          \n", (PVOID)(dllBase + rtFunction->EndAddress)));
        DBG(printf("  Unwind Info Address 0x%p  \n", (PVOID)(dllBase + rtFunction->UnwindInfoAddress)));
        DBG(printf("Looking up in exports...    \n"));
    }
    char* procName = GetSymbolNameByOffset(dllBase, rtFunction->BeginAddress);

    if (procName == NULL) {
        if (verbose) {
            DBG(printf("Function not found\n"));
        }
        return;
    }

    DBG(printf("Function %u found: %s\n", rtFuntionIndex, procName));

    if (verbose) {
        PrintUnwindInfo(dllBase, (PVOID)(dllBase + rtFunction->UnwindData), -1, TRUE);
    }

    return;
}

BOOL PrintUnwindInfo(HMODULE dllBase, PVOID unwindDataAddress, INT UWOP_filter, BOOL headers) {

    PUNWIND_INFO tInfo = (PUNWIND_INFO)((UINT64)dllBase + (DWORD)((UINT64)unwindDataAddress));
    BOOL         printed = FALSE;

    if (headers) {
        printed = TRUE;
        printf("    Version: %d             \n", Version(tInfo->Flags));
        printf("    Ver + Flags: " B2BP "   \n", BYTE_TO_BINARY(tInfo->Flags));
        printf("    SizeOfProlog: 0x%x      \n", tInfo->SizeOfProlog);
        printf("    CountOfCodes: 0x%x      \n", tInfo->CountOfCodes);
        printf("    FrameRegister: 0x%x     \n", tInfo->FrameRegister);
        printf("    FrameOffset: 0x%x       \n", tInfo->FrameOffset);
        printf("    UnwindCodes:            \n");
    }
    char* reg = NULL;
    DWORD offset = 0;
    for (int j = 0; j < tInfo->CountOfCodes; j++) {

        if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp) {
            printf("    [%.2xh] Frame: 0x%.4x - ", j, tInfo->UnwindCode[j].FrameOffset);
            printed = TRUE;
        }
        reg = GetOpInfo(tInfo->UnwindCode[j].OpInfo);
        offset = 0;

        switch (tInfo->UnwindCode[j].UnwindOp) {

        case UWOP_PUSH_NONVOL: // 0
            if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp)
                printf("0x%.2x  - UWOP_PUSH_NONVOL     (%8s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            break;
        case UWOP_ALLOC_LARGE: // 1
            if (tInfo->UnwindCode[j].OpInfo == 0) {
                offset = tInfo->UnwindCode[++j].FrameOffset * 8;
            }
            else {
                offset = tInfo->UnwindCode[++j].FrameOffset + (tInfo->UnwindCode[++j].FrameOffset << 16);
            }
            if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp)
                printf("0x%.2x  - UWOP_ALLOC_LARGE     (%8s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, "NaN", offset);
            break;
        case UWOP_ALLOC_SMALL: // 2
            offset = 8 * (tInfo->UnwindCode[j].OpInfo + 1);
            if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp)
                printf("0x%.2x  - UWOP_ALLOC_SMALL     (%8s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, "NaN", offset);
            break;
        case UWOP_SET_FPREG: // 3
            offset = tInfo->FrameOffset * -0x10;
            if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp)
                printf("0x%.2x  - UWOP_SET_FPREG       (%8s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, offset);
            break;
        case UWOP_SAVE_NONVOL: // 4
            offset = tInfo->UnwindCode[++j].FrameOffset * 8;
            if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp)
                printf("0x%.2x  - UWOP_SAVE_NONVOL     (%8s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, offset);
            break;
        case UWOP_SAVE_NONVOL_BIG: // 5
            offset = tInfo->UnwindCode[++j].FrameOffset + (tInfo->UnwindCode[++j].FrameOffset << 16);
            if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp)
                printf("0x%.2x  - UWOP_SAVE_NONVOL_BIG (%8s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, offset);
            break;
        case UWOP_EPILOG:            // 6
            if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp)
                printf("0x%.2x  - UWOP_EPILOG          (%8s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            j++;
            break;
        case UWOP_SAVE_XMM128:       // 8
            if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp)
                printf("0x%.2x  - UWOP_SAVE_XMM128     (%8s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            j++;
            break;
        case UWOP_SPARE_CODE:        // 7
            if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp)
                printf("0x%.2x  - UWOP_SPARE_CODE      (%8s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            j++;
            j++;
            break;
        case UWOP_SAVE_XMM128BIG:    // 9
            if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp)
                printf("0x%.2x  - UWOP_SAVE_XMM128BIG  (%8s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            j++;
            j++;
            break;
        case UWOP_PUSH_MACH_FRAME:
            if (UWOP_filter == -1 || UWOP_filter == tInfo->UnwindCode[j].UnwindOp)
                printf("0x%.2x  - UWOP_PUSH_MACH_FRAME (%8s, 0x%.4x)\n", tInfo->UnwindCode[j].UnwindOp, reg, tInfo->UnwindCode[j].CodeOffset);
            break;
        default:
            printf("\n");
            break;
        }
        if (NULL != reg) {
            free(reg);
        }
    }
    if (UWOP_filter == -1) {
        if (BitChainInfo(tInfo->Flags)) {
            printf("    Function Entry Offset: 0x%p\n", GetChainedFunctionEntry(dllBase, tInfo));
        }
        if (BitUHandler(tInfo->Flags)) {

        }
        if (BitEHandler(tInfo->Flags)) {
            PVOID dataPtr = GetExceptionDataPtr(tInfo);
            PVOID handlerPtr = GetExceptionHandler(dllBase, tInfo);
            ULONG data = *((PULONG)dataPtr);
            INT32 handler = *((PDWORD)handlerPtr);

            printf("    Exception Handler Offset: 0x%p\n", GetExceptionHandler(dllBase, tInfo));
            printf("    Exception Data Offset: 0x%x\n", data);
        }
    }

    printf("\n\n    Frame Size: 0x%X                \n", offset);
    printf("\n\n    HexDump:                \n");
    hexdump(tInfo, sizeof(UNWIND_INFO));
    printf("\n");

    return printed;
}

void EnumAllRTFunctions(HMODULE moduleBase)
{
    DWORD                   tSize;
    DWORD                   numberOfFunctions;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;

    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress(moduleBase, &tSize));
    numberOfFunctions     = (DWORD)(tSize / sizeof(RUNTIME_FUNCTION));

    for (DWORD i = 0; i <= numberOfFunctions; i++)
    {
        /*
        PRUNTIME_FUNCTION rtft = (PRUNTIME_FUNCTION)(imageExportDirectory + 0xc*i);

        */

        DBG(printf("Runtime Function %u \n", i));
        DBG(printf("  Begin Address 0x%p\n  End Address 0x%p\n  Unwind Info Address 0x%p\n",
            (PVOID)(moduleBase + pRuntimeFunctionTable[i].BeginAddress),
            (PVOID)(moduleBase + pRuntimeFunctionTable[i].EndAddress),
            (PVOID)(moduleBase + pRuntimeFunctionTable[i].UnwindInfoAddress)));

        PrintUnwindInfo(moduleBase, (PVOID)(moduleBase + pRuntimeFunctionTable[i].UnwindData), -1, TRUE);

    }
    // printf(BYTE_TO_BINARY_PATTERN"\n", BYTE_TO_BINARY(UBYTE(UNW_FLAG_CHAININFO | UNW_FLAG_UHANDLER|  UNW_FLAG_EHANDLER )));

}

PRUNTIME_FUNCTION SearchRtFunctionWithSpecificSize(HMODULE moduleBase, DWORD dwFrameSize, BOOL strict, PDWORD pdwActualSize)
{
    DWORD                   tSize;
    DWORD                   numberOfFunctions;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;
    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress(moduleBase, &tSize));
    if (pRuntimeFunctionTable == NULL) {
        return NULL;
    }
    numberOfFunctions = (DWORD)(tSize / sizeof(RUNTIME_FUNCTION));
    for (DWORD i = 0; i < numberOfFunctions; i++)
    {
        DWORD unwindData = pRuntimeFunctionTable[i].UnwindData;
        // Skip invalid or chained entries
        if (unwindData == 0 || (unwindData & 0x1)) {
            continue;
        }

        DWORD pointless = 0;
        PUNWIND_INFO pInfo = (PUNWIND_INFO)((PBYTE)moduleBase + unwindData);

        // UNWIND info with exception handlers are tricky to handle correctly
        if (!(pInfo->Flags & UNW_FLAG_UHANDLER)) {
            continue;
        }
        
        tSize = GetStackFrameSize(moduleBase, (PVOID)pInfo, &pointless);
        printf("    [%d] BeginAddress=0x%08X frameSize=0x%X desired=0x%X diff=0x%X mod16=%d\n",
            i,
            pRuntimeFunctionTable[i].BeginAddress,
            tSize,
            dwFrameSize,
            tSize > dwFrameSize ? tSize - dwFrameSize : 0,
            tSize > dwFrameSize ? (tSize - dwFrameSize) % 16 : -1);

        if (strict && tSize == dwFrameSize) {
            if (pdwActualSize != NULL) {
                *pdwActualSize = 0;
            }
            return &pRuntimeFunctionTable[i];
        }
        else if (!strict && tSize >= (dwFrameSize + 0x28) && tSize <= (dwFrameSize + 0x500)) {
            DWORD diff = tSize - dwFrameSize;
            // Ensure difference is 8 mod 16 (for stack alignment)
            if ((diff % 16) == 8) {
                if (pdwActualSize != NULL) {
                    *pdwActualSize = diff;
                }
                return &pRuntimeFunctionTable[i];
            }
        }
    }
    return NULL;
}

PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddressInTable(PRUNTIME_FUNCTION pRuntimeFunctionTable, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD64 functionOffset) {

    for (DWORD i = 0; i < pImageExportDirectory->NumberOfFunctions; i++)
    {
        if (pRuntimeFunctionTable[i].BeginAddress == functionOffset) {

            return pRuntimeFunctionTable + i;
        }
    }
    return NULL;
}

PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddressInRFTable(PRUNTIME_FUNCTION pRuntimeFunctionTable, DWORD rtLastIndex, DWORD64 functionOffset) {

    for (DWORD i = 0; i < rtLastIndex; i++)
    {
        if (pRuntimeFunctionTable[i].BeginAddress == functionOffset) {

            return pRuntimeFunctionTable + i;
        }
    }
    return NULL;
}


PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddress(UINT64 modulelBase, DWORD functionOffset) {

    DWORD                   tSize;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;

    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress((HMODULE)modulelBase, &tSize));

    DWORD numberOfFunctions = (DWORD)(tSize / 12);
    printf("Number of functions: %u\n", numberOfFunctions);

    for (DWORD i = 0; i < numberOfFunctions; i++)
    {
        if (pRuntimeFunctionTable[i].BeginAddress == functionOffset) {

            return pRuntimeFunctionTable + i;
        }
    }
    return NULL;
}

PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByIndex(UINT64 kernelBase, DWORD index) {

    DWORD                   tSize;
    PRUNTIME_FUNCTION       pRuntimeFunctionTable;

    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress((HMODULE)kernelBase, &tSize));
    return pRuntimeFunctionTable + index;
}

DWORD FindRTFunctionsUnwind(HMODULE moduleBase, PVOID tUnwindCodeAddress) {

    DWORD               tSize;
    PUNWIND_CODE        tUnwindCode;
    PUNWIND_INFO        unwindInfo;
    PRUNTIME_FUNCTION   pRuntimeFunctionTable;

    tUnwindCode = (PUNWIND_CODE)tUnwindCodeAddress;
    pRuntimeFunctionTable = (PRUNTIME_FUNCTION)(GetExceptionDirectoryAddress(moduleBase, &tSize));

    for (DWORD i = 0; i <= (DWORD)(tSize/12); i++)
    {

        unwindInfo = (PUNWIND_INFO)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].UnwindData);
        for (int j = 0; j < unwindInfo->CountOfCodes; j++) {

            if (unwindInfo->UnwindCode[j].FrameOffset == tUnwindCode->FrameOffset) {

                DBG(printf("Found frame offset with Runtime Function: %u, unwindCode: %u   \n", i + 1, j));
                DBG(printf("Found: 0x%x - Expected: 0x%x                                   \n", unwindInfo->UnwindCode[j].FrameOffset, tUnwindCode->FrameOffset));
                DBG(printf("Address in module: 0x%p                                        \n", (PVOID)((UINT64)moduleBase + (DWORD)pRuntimeFunctionTable[i].BeginAddress)));

                return i;

            }

            // TODO: Implement the rest after

        }

    }
    DBG(printf("Function not found\n"));

    return 0;

}

DWORD GetFunctionSizeByAddress(HMODULE hModule, PVOID pFunction) {
    DWORD rva = (DWORD)((UINT64)pFunction - (UINT64)hModule);

    DWORD size = 0;
    PRUNTIME_FUNCTION pRTF = (PRUNTIME_FUNCTION)GetExceptionDirectoryAddress(hModule, &size);
    if (pRTF == NULL) {
        return 0;
    }

    DWORD count = size / sizeof(RUNTIME_FUNCTION);
    for (DWORD i = 0; i < count; i++) {
        if (pRTF[i].BeginAddress == rva) {
            return pRTF[i].EndAddress - pRTF[i].BeginAddress;
        }
    }

    return 0;
}


PDYNAMIC_FUNCTION_TABLE FindLocalDynamicFunctionTable(ULONG64 Address)
{
    ULONG64 headPtr = 0;
    ULONG64 sentinel = 0;

    if (!FindDynamicFunctionTablePointers(GetCurrentProcess(), &headPtr, &sentinel))
        return NULL;

    ULONG64 current = *(ULONG64*)headPtr;

    int index = 0;
    while (current != sentinel)
    {
        PDYNAMIC_FUNCTION_TABLE entry = (PDYNAMIC_FUNCTION_TABLE)current;

        if (Address >= entry->MinimumAddress && Address < entry->MaximumAddress)
            return entry;

        current = (ULONG64)entry->Links.Flink;
        if (++index > 1000) break;
    }

    return NULL;
}

//
// FindTablePointers.cpp
// Robust scanner for RtlpDynamicFunctionTable and LdrpInvertedFunctionTable
// across multiple Windows versions.
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------
static bool InNtdll(ULONG64 addr, ULONG64 base, SIZE_T size)
{
    return addr > base && addr < base + size;
}

// Decode a RIP-relative 32-bit offset at buf[i] where the instruction
// starts at VA instrVA and the offset field is at buf[i + offOff],
// and the next instruction is at instrVA + instrLen.
static ULONG64 RipRel(const BYTE* buf, int i, int offOff, int instrLen, ULONG64 instrVA)
{
    INT32 rel;
    memcpy(&rel, &buf[i + offOff], sizeof(INT32));
    return instrVA + i + instrLen + rel;
}

// ---------------------------------------------------------------
// Dump bytes for diagnosis
// ---------------------------------------------------------------
static void HexDump(const BYTE* buf, SIZE_T len, ULONG64 baseVA)
{
    for (SIZE_T i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n  %016llX: ", baseVA + i);
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

// ---------------------------------------------------------------
// Scan a buffer for all LEA/MOV RIP-relative references pointing
// inside ntdll, returning up to maxResults candidates.
// ---------------------------------------------------------------
struct RipRef {
    int     offset;     // byte offset within buf
    BYTE    opcode;     // first opcode byte
    BYTE    modrm;      // ModRM byte
    ULONG64 target;     // resolved VA
};

static int CollectRipRefs(
    const BYTE* buf, SIZE_T len, ULONG64 bufVA,
    ULONG64 ntdllBase, SIZE_T ntdllSize,
    RipRef* out, int maxResults)
{
    int count = 0;
    for (int i = 0; i < (int)len - 7 && count < maxResults; i++)
    {
        // REX.W MOV reg, [RIP+x]  -> 48 8B XX xx xx xx xx  (instrLen=7)
        // REX.W LEA reg, [RIP+x]  -> 48 8D XX xx xx xx xx  (instrLen=7)
        // REX.WR MOV reg, [RIP+x] -> 4C 8B XX xx xx xx xx  (instrLen=7)
        // REX.WR LEA reg, [RIP+x] -> 4C 8D XX xx xx xx xx  (instrLen=7)
        BYTE rex = buf[i];
        if (rex != 0x48 && rex != 0x4C) continue;

        BYTE op = buf[i + 1];
        if (op != 0x8B && op != 0x8D) continue;

        // ModRM: mod=00, rm=101 means RIP-relative
        BYTE modrm = buf[i + 2];
        if ((modrm & 0xC7) != 0x05) continue;

        ULONG64 target = RipRel(buf, i, 3, 7, bufVA);
        if (!InNtdll(target, ntdllBase, ntdllSize)) continue;

        out[count++] = { i, op, modrm, target };
    }
    return count;
}

// ---------------------------------------------------------------
// FindDynamicFunctionTablePointers
//
// Strategy: scan RtlAddFunctionTable for all RIP-relative refs
// into ntdll. The dynamic function table head and sentinel are
// two refs that appear close together in the epilogue where the
// new node is linked into the list:
//   MOV [RBX], RtlpDynamicFunctionTable  <- sentinel/head ref
//   MOV [DAT], RBX                       <- head ptr update
// We look for the specific CMP pattern from the disassembly:
//   MOV RAX, [RIP+x]   ; load DAT (head ptr storage)
//   LEA RCX, [RIP+x]   ; load &RtlpDynamicFunctionTable (sentinel)
//   CMP [RAX], RCX     ; 48 39 08
// But also fall back to a broader scan if that exact form isn't found.
// ---------------------------------------------------------------
BOOL FindDynamicFunctionTablePointers(
    HANDLE   hProcess,
    ULONG64* OutHeadPtr,
    ULONG64* OutSentinel)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    ULONG64 ntdllBase = (ULONG64)hNtdll;

    // Get ntdll size from PE headers
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(ntdllBase + dos->e_lfanew);
    SIZE_T ntdllSize = nt->OptionalHeader.SizeOfImage;

    ULONG64 fnAddr = (ULONG64)GetProcAddress(hNtdll, "RtlAddFunctionTable");
    if (!fnAddr) { printf("[!] RtlAddFunctionTable not found\n"); return FALSE; }
    printf("[*] RtlAddFunctionTable @ 0x%016llX\n", fnAddr);

    // Read 1KB - enough to cover all Windows versions
    const SIZE_T BUF = 1024;
    BYTE buf[BUF];
    SIZE_T bytesRead = 0;
    ReadProcessMemory(hProcess, (LPCVOID)fnAddr, buf, BUF, &bytesRead);
    printf("[*] Read %zu bytes\n", bytesRead);

    // ---- Pass 1: exact pattern from known disassembly ----
    // 48 8B 05 [rel32]   MOV RAX, [RIP+x]
    // 48 8D 0D [rel32]   LEA RCX, [RIP+x]
    // 48 39 08           CMP [RAX], RCX
    // Allow up to 32 bytes between MOV and LEA
    for (int i = 0; i < (int)bytesRead - 20; i++)
    {
        if (buf[i] != 0x48 || buf[i + 1] != 0x8B || buf[i + 2] != 0x05) continue;
        ULONG64 headPtr = RipRel(buf, i, 3, 7, fnAddr);
        if (!InNtdll(headPtr, ntdllBase, ntdllSize)) continue;

        // Search for LEA RCX within next 48 bytes
        for (int j = i + 7; j < i + 48 && j < (int)bytesRead - 10; j++)
        {
            // 48 8D 0D or 48 8D 15 etc. - LEA with RIP-rel
            if (buf[j] != 0x48 || buf[j + 1] != 0x8D) continue;
            if ((buf[j + 2] & 0xC7) != 0x05) continue;
            ULONG64 sentinel = RipRel(buf, j, 3, 7, fnAddr);
            if (!InNtdll(sentinel, ntdllBase, ntdllSize)) continue;

            // Look for CMP [RAX], RCX (48 39 08) within next 8 bytes
            for (int k = j + 7; k < j + 16 && k < (int)bytesRead - 3; k++)
            {
                if (buf[k] == 0x48 && buf[k + 1] == 0x39 && buf[k + 2] == 0x08)
                {
                    printf("[+] Pass1 match at +0x%X/+0x%X/+0x%X\n", i, j, k);
                    printf("    headPtr  : 0x%016llX\n", headPtr);
                    printf("    sentinel : 0x%016llX\n", sentinel);

                    ULONG64 firstEntry = 0;
                    ReadProcessMemory(hProcess, (LPCVOID)headPtr, &firstEntry, 8, NULL);
                    printf("    *headPtr : 0x%016llX%s\n", firstEntry,
                        firstEntry == sentinel ? " (list empty)" : " (has entries)");

                    *OutHeadPtr = headPtr;
                    *OutSentinel = sentinel;
                    return TRUE;
                }
            }
        }
    }
    printf("[~] Pass1 (MOV+LEA+CMP) not found, trying Pass2\n");

    // ---- Pass 2: look for linked-list insertion pattern ----
    // MOV [RBX], RCX/RAX  (node->flink = head sentinel)
    // MOV [RBX+8], RAX    (node->blink)
    // MOV [RAX], RBX      (old_head->blink = node)
    // MOV [DAT], RBX      (update head pointer)
    // The sentinel LEA and head MOV appear just before this block
    // Scan for:  48 89 0B (MOV [RBX], RCX)  or  48 89 03 (MOV [RBX], RAX)
    // preceded within 16 bytes by two RIP-relative refs
    for (int i = 14; i < (int)bytesRead - 20; i++)
    {
        // MOV [RBX], reg  or  MOV [RBX+8], reg
        bool listLink = (buf[i] == 0x48 && buf[i + 1] == 0x89 &&
            (buf[i + 2] == 0x0B || buf[i + 2] == 0x03));
        if (!listLink) continue;

        // Collect RIP refs in the 40 bytes before this point
        RipRef refs[16];
        // Scan backward window: [i-40, i]
        int winStart = max(0, i - 40);
        int nRefs = 0;
        for (int j = winStart; j < i && nRefs < 16; j++)
        {
            BYTE rex2 = buf[j];
            if (rex2 != 0x48 && rex2 != 0x4C) continue;
            BYTE op2 = buf[j + 1];
            if (op2 != 0x8B && op2 != 0x8D) continue;
            if ((buf[j + 2] & 0xC7) != 0x05) continue;
            ULONG64 t = RipRel(buf, j, 3, 7, fnAddr);
            if (InNtdll(t, ntdllBase, ntdllSize))
                refs[nRefs++] = { j, op2, buf[j + 2], t };
        }

        if (nRefs < 2) continue;

        // Heuristic: one should be a MOV (load), one should be a LEA (address-of)
        ULONG64 movTarget = 0, leaTarget = 0;
        for (int r = 0; r < nRefs; r++) {
            if (refs[r].opcode == 0x8B && movTarget == 0) movTarget = refs[r].target;
            if (refs[r].opcode == 0x8D && leaTarget == 0) leaTarget = refs[r].target;
        }

        if (!movTarget || !leaTarget || movTarget == leaTarget) continue;

        printf("[+] Pass2 candidate at +0x%X\n", i);
        printf("    headPtr  (MOV) : 0x%016llX\n", movTarget);
        printf("    sentinel (LEA) : 0x%016llX\n", leaTarget);

        ULONG64 firstEntry = 0;
        ReadProcessMemory(hProcess, (LPCVOID)movTarget, &firstEntry, 8, NULL);
        printf("    *headPtr       : 0x%016llX%s\n", firstEntry,
            firstEntry == leaTarget ? " (list empty)" : "");

        *OutHeadPtr = movTarget;
        *OutSentinel = leaTarget;
        return TRUE;
    }

    // ---- Pass 3: RtlReleaseSRWLock epilogue — last two RIP refs in function ----
    printf("[~] Pass2 not found, trying Pass3 (last two RIP refs)\n");
    RipRef allRefs[128];
    int total = CollectRipRefs(buf, bytesRead, fnAddr, ntdllBase, ntdllSize, allRefs, 128);
    printf("[*] Total RIP refs in RtlAddFunctionTable: %d\n", total);
    for (int i = 0; i < total; i++)
        printf("    +0x%03X %s 0x%016llX\n",
            allRefs[i].offset,
            allRefs[i].opcode == 0x8D ? "LEA" : "MOV",
            allRefs[i].target);

    // Find last MOV+LEA pair that are within 20 bytes of each other
    for (int i = total - 1; i >= 1; i--)
    {
        if (allRefs[i].opcode != 0x8B) continue; // want MOV for head
        for (int j = i - 1; j >= 0 && allRefs[i].offset - allRefs[j].offset < 20; j--)
        {
            if (allRefs[j].opcode != 0x8D) continue; // want LEA for sentinel
            printf("[+] Pass3 candidate: headPtr=0x%016llX sentinel=0x%016llX\n",
                allRefs[i].target, allRefs[j].target);
            *OutHeadPtr = allRefs[i].target;
            *OutSentinel = allRefs[j].target;
            return TRUE;
        }
    }

    printf("[!] All passes failed. Hex dump of RtlAddFunctionTable:\n");
    HexDump(buf, min(bytesRead, (SIZE_T)512), fnAddr);
    return FALSE;
}

// ---------------------------------------------------------------
// FindInvertedFunctionTable
//
// Strategy: 
//  Pass1 - find RtlpxLookupFunctionTable via first CALL in
//          RtlLookupFunctionEntry, then scan for LEA R15/R14/RCX
//          (SRW lock arg) followed by CALL RtlAcquireSRWLockShared
//  Pass2 - scan for the INVERTED_FUNCTION_TABLE Count field by
//          looking for MOV+CMP pairs loading a small integer
//  Pass3 - scan RtlpxLookupFunctionTable for ALL RIP refs and
//          dump them for manual identification
// ---------------------------------------------------------------
BOOL FindInvertedFunctionTable(
    PINVERTED_FUNCTION_TABLE* OutTable,
    PRTL_SRWLOCK* OutLock)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    ULONG64 ntdllBase = (ULONG64)hNtdll;

    PIMAGE_DOS_HEADER   dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(ntdllBase + dos->e_lfanew);
    SIZE_T ntdllSize = nt->OptionalHeader.SizeOfImage;

    // ----------------------------------------------------------------
    // Fast path: KiUserInvertedFunctionTable is exported from ntdll
    // directly on most Windows versions.
    // ----------------------------------------------------------------
    ULONG64 tableAddr = (ULONG64)GetProcAddress(hNtdll, "KiUserInvertedFunctionTable");
    if (tableAddr) {
        printf("[+] KiUserInvertedFunctionTable (exported) @ 0x%016llX\n", tableAddr);
    }
    else {
        printf("[~] KiUserInvertedFunctionTable not exported, falling back to scan\n");
    }

    // ----------------------------------------------------------------
    // Find RtlpxLookupFunctionTable via first CALL inside
    // RtlLookupFunctionEntry that lands within ntdll.
    // ----------------------------------------------------------------
    ULONG64 fnAddr = (ULONG64)GetProcAddress(hNtdll, "RtlLookupFunctionEntry");
    if (!fnAddr) return FALSE;
    printf("[*] RtlLookupFunctionEntry @ 0x%016llX\n", fnAddr);

    const SIZE_T BUF = 1024;
    BYTE buf[BUF];
    memcpy(buf, (PVOID)fnAddr, BUF);

    ULONG64 rtlpxAddr = 0;
    for (int i = 0; i < (int)BUF - 5; i++) {
        if (buf[i] != 0xE8) continue;
        INT32 rel; memcpy(&rel, &buf[i + 1], 4);
        ULONG64 target = fnAddr + i + 5 + rel;
        if (InNtdll(target, ntdllBase, ntdllSize)) {
            rtlpxAddr = target;
            printf("[*] RtlpxLookupFunctionTable @ 0x%016llX\n", rtlpxAddr);
            break;
        }
    }
    if (!rtlpxAddr) {
        printf("[!] Could not find RtlpxLookupFunctionTable\n");
        return FALSE;
    }

    // ----------------------------------------------------------------
    // Collect all RIP-relative refs in RtlpxLookupFunctionTable.
    // ----------------------------------------------------------------
    BYTE buf2[BUF];
    memcpy(buf2, (PVOID)rtlpxAddr, sizeof(buf2));

    RipRef refs[64];
    int nRefs = CollectRipRefs(buf2, sizeof(buf2), rtlpxAddr, ntdllBase, ntdllSize, refs, 64);
    printf("[*] RIP refs in RtlpxLookupFunctionTable: %d\n", nRefs);
    for (int i = 0; i < nRefs; i++)
        printf("    +0x%03X %s 0x%016llX  ->  val=0x%016llX\n",
            refs[i].offset,
            refs[i].opcode == 0x8D ? "LEA" : "MOV",
            refs[i].target,
            *(ULONG64*)refs[i].target);

    // ----------------------------------------------------------------
    // Pass 1: find SRW lock — LEA immediately before
    //         CALL RtlAcquireSRWLockShared.
    // ----------------------------------------------------------------
    ULONG64 lockAddr = 0;
    ULONG64 acquireShared = (ULONG64)GetProcAddress(hNtdll, "RtlAcquireSRWLockShared");
    printf("[*] RtlAcquireSRWLockShared @ 0x%016llX\n", acquireShared);

    for (int i = 5; i < (int)sizeof(buf2) - 5; i++) {
        if (buf2[i] != 0xE8) continue;
        INT32 rel; memcpy(&rel, &buf2[i + 1], 4);
        ULONG64 callTarget = rtlpxAddr + i + 5 + rel;
        if (callTarget != acquireShared) continue;

        for (int j = i - 1; j >= max(0, i - 16); j--) {
            BYTE rex2 = buf2[j];
            if (rex2 != 0x48 && rex2 != 0x4C) continue;
            if (buf2[j + 1] != 0x8D) continue;
            if ((buf2[j + 2] & 0xC7) != 0x05) continue;
            ULONG64 candidate = RipRel(buf2, j, 3, 7, rtlpxAddr);
            if (!InNtdll(candidate, ntdllBase, ntdllSize)) continue;
            lockAddr = candidate;
            printf("[+] Pass1 SRW lock @ 0x%016llX (LEA at +0x%03X, CALL at +0x%03X)\n",
                lockAddr, j, i);
            break;
        }
        if (lockAddr) break;
    }

    // ----------------------------------------------------------------
    // Pass 2 (scan fallback): if KiUserInvertedFunctionTable was not
    // exported, find it from the RIP refs.
    //
    // The table pointer is stored in a variable loaded via LEA.
    // Dereference once to get the table address.
    // Validate: first 4 bytes of the table = Count (1-512).
    // ----------------------------------------------------------------
    if (!tableAddr) {
        for (int i = 0; i < nRefs; i++) {
            if (refs[i].opcode != 0x8D) continue;       // LEA only
            if (refs[i].target == lockAddr) continue;    // skip lock

            ULONG64 ptrVar = refs[i].target;
            ULONG64 tblCandidate = *(ULONG64*)ptrVar;

            printf("[*] Pass2 candidate: ptrVar=0x%016llX -> tbl=0x%016llX\n",
                ptrVar, tblCandidate);

            if (tblCandidate == 0) {
                printf("[~]   tbl is NULL, skipping\n");
                continue;
            }

            // Validate: Count field (first ULONG) should be 1-512
            ULONG count = *(ULONG*)tblCandidate;
            printf("[*]   Count field = %u (valid range 1-512)\n", count);
            if (count == 0 || count > 512) {
                printf("[~]   Count out of range, skipping\n");
                continue;
            }

            tableAddr = tblCandidate;
            printf("[+] Pass2 LdrpInvertedFunctionTable @ 0x%016llX (Count=%u)\n",
                tableAddr, count);
            break;
        }
    }

    // ----------------------------------------------------------------
    // Pass 3: full dump for manual identification.
    // ----------------------------------------------------------------
    if (!lockAddr || !tableAddr) {
        printf("[~] Auto-resolve incomplete (lock=0x%016llX table=0x%016llX)\n",
            lockAddr, tableAddr);
        printf("[~] Full RIP ref dump for manual inspection:\n");
        for (int i = 0; i < nRefs; i++) {
            ULONG64 t = refs[i].target;
            ULONG64 deref = *(ULONG64*)t;
            ULONG64 deref2 = (deref && InNtdll(deref, ntdllBase, ntdllSize))
                ? *(ULONG64*)deref : 0;
            printf("    +0x%03X %s VA=0x%016llX *VA=0x%016llX **VA=0x%016llX\n",
                refs[i].offset,
                refs[i].opcode == 0x8D ? "LEA" : "MOV",
                t, deref, deref2);
        }
        return FALSE;
    }

    printf("[+] LdrpInvertedFunctionTableSRWLock @ 0x%016llX\n", lockAddr);
    printf("[+] LdrpInvertedFunctionTable        @ 0x%016llX\n", tableAddr);

    *OutLock = (PRTL_SRWLOCK)lockAddr;
    *OutTable = (PINVERTED_FUNCTION_TABLE)tableAddr;
    return TRUE;
}


BOOL ShrinkInvertedFunctionTableEntry(HMODULE hModule, ULONG64 ShcAddress, PULONG pOldSize)
{
    PINVERTED_FUNCTION_TABLE pTable = NULL;
    PRTL_SRWLOCK             pLock = NULL;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    fnRtlAcquireSRWLockExclusive pRtlAcquireSRWLockExclusive =
        (fnRtlAcquireSRWLockExclusive)GetProcAddress(hNtdll, "RtlAcquireSRWLockExclusive");

    fnRtlReleaseSRWLockExclusive pRtlReleaseSRWLockExclusive =
        (fnRtlReleaseSRWLockExclusive)GetProcAddress(hNtdll, "RtlReleaseSRWLockExclusive");

    if (!pRtlAcquireSRWLockExclusive || !pRtlReleaseSRWLockExclusive) {
        printf("[!] Failed to resolve SRW lock functions\n");
        return FALSE;
    }

    if (!FindInvertedFunctionTable(&pTable, &pLock)) {
        printf("[!] Failed to resolve Inverted Function Table\n");
        return FALSE;
    }

    fnLdrProtectMrdata pLdrProtectMrdata = NULL;
    if (!FindLdrProtectMrdata(&pLdrProtectMrdata)) return FALSE;

    pRtlAcquireSRWLockExclusive(pLock);
    pLdrProtectMrdata(FALSE);

    BOOL found = FALSE;
    for (ULONG i = 0; i < pTable->Count; i++) {
        if (pTable->Entries[i].ImageBase != (PVOID)hModule) continue;

        ULONG64 moduleBase = (ULONG64)pTable->Entries[i].ImageBase;
        ULONG   oldSize = pTable->Entries[i].ImageSize;
        if (NULL != pOldSize) {
            *pOldSize = oldSize;
        }

        ULONG64 shcRVA = ShcAddress - moduleBase;

        printf("[*] Found at index %u: Base=0x%016llX Size=0x%08X\n",
            i, moduleBase, oldSize);

        ULONG newSize = (ULONG)(shcRVA & ~0xFFF); // align down to page
        newSize = 0; // We are just 0-ing it out
        pTable->Entries[i].ImageSize = newSize;

        printf("[+] ImageSize shrunk: 0x%08X -> 0x%08X\n", oldSize, newSize);
        printf("    Module now covers: 0x%016llX - 0x%016llX\n",
            moduleBase, moduleBase + newSize);
        printf("    ShcAddress 0x%016llX is now outside reported range\n", ShcAddress);

        found = TRUE;
        break;
    }

    pLdrProtectMrdata(TRUE);
    pRtlReleaseSRWLockExclusive(pLock);

    return found;
}

BOOL EnlargeInvertedFunctionTableEntry(HMODULE hModule, ULONG64 ShcAddress, PULONG pOldSize)
{
    PINVERTED_FUNCTION_TABLE pTable = NULL;
    PRTL_SRWLOCK             pLock = NULL;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    fnRtlAcquireSRWLockExclusive pRtlAcquireSRWLockExclusive =
        (fnRtlAcquireSRWLockExclusive)GetProcAddress(hNtdll, "RtlAcquireSRWLockExclusive");

    fnRtlReleaseSRWLockExclusive pRtlReleaseSRWLockExclusive =
        (fnRtlReleaseSRWLockExclusive)GetProcAddress(hNtdll, "RtlReleaseSRWLockExclusive");

    if (!pRtlAcquireSRWLockExclusive || !pRtlReleaseSRWLockExclusive) {
        printf("[!] Failed to resolve SRW lock functions\n");
        return FALSE;
    }

    if (!FindInvertedFunctionTable(&pTable, &pLock)) {
        printf("[!] Failed to resolve Inverted Function Table\n");
        return FALSE;
    }

    fnLdrProtectMrdata pLdrProtectMrdata = NULL;
    if (!FindLdrProtectMrdata(&pLdrProtectMrdata)) return FALSE;

    pRtlAcquireSRWLockExclusive(pLock);
    pLdrProtectMrdata(FALSE);

    BOOL found = FALSE;
    for (ULONG i = 0; i < pTable->Count; i++) {
        if (pTable->Entries[i].ImageBase != (PVOID)hModule) continue;

        ULONG64 moduleBase = (ULONG64)pTable->Entries[i].ImageBase;
        ULONG   oldSize = pTable->Entries[i].ImageSize;
        if (NULL != pOldSize) {
            *pOldSize = oldSize;
        }

        ULONG64 shcRVA = ShcAddress - moduleBase;
        ULONG   newSize = (ULONG)((shcRVA + 0xFFF) & ~0xFFF);   /* page-align up */

        MODULEINFO mi;
        GetModuleInformation(GetCurrentProcess(), hModule, &mi, sizeof(mi));

        printf("[*] PE SizeOfImage (GetModuleInformation) : 0x%08X\n", mi.SizeOfImage);
        printf("[*] InvertedFunctionTable ImageSize        : 0x%08X\n", oldSize);
        printf("[*] Difference                             : 0x%08X\n", oldSize - mi.SizeOfImage);

        printf("[*] ShcAddress  : 0x%016llX\n", ShcAddress);
        printf("[*] moduleBase  : 0x%016llX\n", moduleBase);
        printf("[*] shcRVA      : 0x%016llX\n", shcRVA);
        printf("[*] newSize     : 0x%08X\n", newSize);
        printf("[*] oldSize     : 0x%08X\n", oldSize);

        /* Only enlarge — never shrink via this function. */
        if (newSize <= oldSize) {
            printf("[!] ShcAddress is already within reported range, no change needed\n");
            printf("    newSize (0x%08X) <= oldSize (0x%08X)\n", newSize, oldSize);
            found = TRUE;
            break;
        }

        pTable->Entries[i].ImageSize = newSize;

        printf("[+] ImageSize enlarged: 0x%08X -> 0x%08X\n", oldSize, newSize);
        printf("    Module now covers:  0x%016llX - 0x%016llX\n",
            moduleBase, moduleBase + newSize);
        printf("    ShcAddress 0x%016llX is now inside reported range\n", ShcAddress);

        found = TRUE;
        break;
    }

    pLdrProtectMrdata(TRUE);
    pRtlReleaseSRWLockExclusive(pLock);

    return found;
}

BOOL RestoreInvertedFunctionTableEntry(HMODULE hModule, ULONG oldSize)
{
    PINVERTED_FUNCTION_TABLE pTable = NULL;
    PRTL_SRWLOCK             pLock = NULL;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    fnRtlAcquireSRWLockExclusive pRtlAcquireSRWLockExclusive =
        (fnRtlAcquireSRWLockExclusive)GetProcAddress(hNtdll, "RtlAcquireSRWLockExclusive");

    fnRtlReleaseSRWLockExclusive pRtlReleaseSRWLockExclusive =
        (fnRtlReleaseSRWLockExclusive)GetProcAddress(hNtdll, "RtlReleaseSRWLockExclusive");

    if (!pRtlAcquireSRWLockExclusive || !pRtlReleaseSRWLockExclusive) {
        printf("[!] Failed to resolve SRW lock functions\n");
        return FALSE;
    }

    if (!FindInvertedFunctionTable(&pTable, &pLock)) {
        printf("[!] Failed to resolve Inverted Function Table\n");
        return FALSE;
    }

    fnLdrProtectMrdata pLdrProtectMrdata = NULL;
    if (!FindLdrProtectMrdata(&pLdrProtectMrdata)) return FALSE;

    pRtlAcquireSRWLockExclusive(pLock);
    pLdrProtectMrdata(FALSE);

    BOOL found = FALSE;
    for (ULONG i = 0; i < pTable->Count; i++) {
        if (pTable->Entries[i].ImageBase != (PVOID)hModule) continue;

        ULONG64 moduleBase = (ULONG64)pTable->Entries[i].ImageBase;
        ULONG   oldSize = 0;

        printf("[*] Found at index %u: Base=0x%016llX Size=0x%08X\n",
            i, moduleBase, oldSize);

        ULONG newSize = pTable->Entries[i].ImageSize;
        pTable->Entries[i].ImageSize = newSize;

        printf("[+] ImageSize shrunk: 0x%08X -> 0x%08X\n", oldSize, newSize);
        printf("    Module now covers: 0x%016llX - 0x%016llX\n",
            moduleBase, moduleBase + newSize);

        found = TRUE;
        break;
    }

    pLdrProtectMrdata(TRUE);
    pRtlReleaseSRWLockExclusive(pLock);

    return found;
}

BOOL FindLdrProtectMrdata(fnLdrProtectMrdata* OutFn)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    ULONG64 fnAddr = (ULONG64)GetProcAddress(hNtdll, "RtlAddFunctionTable");
    if (!fnAddr) return FALSE;

    BYTE buf[512];
    memcpy(buf, (PVOID)fnAddr, sizeof(buf));

    // Pattern: 33 C9          XOR ECX, ECX
    //          48 89 43 28    MOV [RBX+0x28], RAX
    //          E8 xx xx xx xx CALL LdrProtectMrdata
    static const BYTE pattern[] = { 0x33, 0xC9,
                                     0x48, 0x89, 0x43, 0x28,
                                     0xE8 };
    static const BYTE mask[] = { 0xFF, 0xFF,
                                     0xFF, 0xFF, 0xFF, 0xFF,
                                     0xFF };

    for (int i = 0; i < (int)(sizeof(buf) - sizeof(pattern)); i++)
    {
        BOOL match = TRUE;
        for (int j = 0; j < (int)sizeof(pattern); j++) {
            if ((buf[i + j] & mask[j]) != pattern[j]) { match = FALSE; break; }
        }
        if (!match) continue;

        // CALL is at i+6, rel32 follows
        INT32 offset;
        memcpy(&offset, &buf[i + 7], sizeof(INT32));
        ULONG64 candidate = fnAddr + i + 7 + 4 + offset;

        printf("[*] LdrProtectMrdata candidate @ 0x%016llX (pattern at +0x%X)\n",
            candidate, i);

        // Sanity: must be within ntdll
        if (candidate > (ULONG64)hNtdll && candidate < (ULONG64)hNtdll + 0x200000) {
            *OutFn = (fnLdrProtectMrdata)candidate;
            printf("[+] LdrProtectMrdata resolved @ 0x%016llX\n", candidate);
            return TRUE;
        }
    }

    printf("[!] LdrProtectMrdata pattern not found\n");
    return FALSE;
}

BOOL SuppressExceptionDirectory(HMODULE hModule, PIMAGE_DATA_DIRECTORY pBackup)
{
    PIMAGE_DOS_HEADER   dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((ULONG64)hModule + dos->e_lfanew);

    PIMAGE_DATA_DIRECTORY exDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    // Backup
    *pBackup = *exDir;

    DWORD oldProtect;
    VirtualProtect(exDir, sizeof(IMAGE_DATA_DIRECTORY), PAGE_READWRITE, &oldProtect);
    exDir->VirtualAddress = 0;
    exDir->Size = 0;
    VirtualProtect(exDir, sizeof(IMAGE_DATA_DIRECTORY), oldProtect, &oldProtect);

    printf("[+] Exception directory zeroed (was RVA=0x%08X Size=0x%08X)\n",
        pBackup->VirtualAddress, pBackup->Size);
    return TRUE;
}

BOOL RestoreExceptionDirectory(HMODULE hModule, PIMAGE_DATA_DIRECTORY pBackup)
{
    PIMAGE_DOS_HEADER   dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((ULONG64)hModule + dos->e_lfanew);

    PIMAGE_DATA_DIRECTORY exDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    DWORD oldProtect;
    VirtualProtect(exDir, sizeof(IMAGE_DATA_DIRECTORY), PAGE_READWRITE, &oldProtect);
    *exDir = *pBackup;
    VirtualProtect(exDir, sizeof(IMAGE_DATA_DIRECTORY), oldProtect, &oldProtect);

    printf("[+] Exception directory restored\n");
    return TRUE;
}