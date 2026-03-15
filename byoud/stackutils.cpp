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
#include <windows.h>
#include <stdio.h>
#include "resolver.h"
#include "stacksearch.h"

uint64_t GetStackBtitAddress(uint64_t* stack_pointer) {

    PVOID btit = (PVOID)GetSymbolAddress2(KERNEL32, BaseThreadInitThunk_H);
    if (btit == NULL) {
        printf("Failed to find BaseThreadInitThunk function address: %08x\n", GetLastError());
        return NULL;
    }

    DWORD callOffset = FindCallInstructionOffset((UINT64)btit, 0x100);

    uint64_t stackSpace = StackSearch((uint64_t)btit + callOffset, stack_pointer);

    if (stackSpace == 0) {
        printf("Failed to calculate stack space\n");
    }

    printf("Stack space: 0x%llx\n", stackSpace);
    return stackSpace;
    
}

BOOL ModuleHasStackCookies(HMODULE hModule)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((ULONG64)hModule + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY* lcDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

    if (lcDir->VirtualAddress == 0 || lcDir->Size == 0) {
        printf("[+] No LoadConfig directory — no stack cookies\n");
        return FALSE;
    }

    PIMAGE_LOAD_CONFIG_DIRECTORY64 lc =
        (PIMAGE_LOAD_CONFIG_DIRECTORY64)((ULONG64)hModule + lcDir->VirtualAddress);

    printf("[*] SecurityCookie @ 0x%016llX = 0x%016llX\n",
        lc->SecurityCookie, *(ULONG64*)lc->SecurityCookie);

    return lc->SecurityCookie != 0;
}

