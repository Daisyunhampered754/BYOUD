#include "pch.h"
#include "unwind.h"

DWORD BuildUnwindInfo(PUNWIND_INFO pDest, DWORD destSize, PUNWIND_BUILD_PARAMS params) {
    UBYTE* raw = (UBYTE*)pDest;
    DWORD codeIndex = 0;
    DWORD codeOffset = 1;
    DWORD numPushes;
    DWORD allocSize;

    if (pDest == NULL || destSize < 8) {
        return 0;
    }

    memset(raw, 0, destSize);

    // Calculate how to distribute the stack size
    UBYTE effectiveInstructions = params->numInstructions;

    // Reserve one instruction for FPREG if used
    if (params->useFpreg && effectiveInstructions > 0) {
        effectiveInstructions--;
    }

    // Special case: size is exactly 0x8, just use PUSH_NONVOL
    if (params->dwStackSize == 0x8) {
        numPushes = 1;
        allocSize = 0;
    }
    // Size fits in ALLOC_SMALL (8-128 bytes) with remaining pushes
    else if (effectiveInstructions > 0 && params->dwStackSize <= (DWORD)128 + ((effectiveInstructions - 1) * 8)) {
        // Try to use as many pushes as possible, rest goes to ALLOC_SMALL
        if (effectiveInstructions > 1) {
            numPushes = effectiveInstructions - 1;
            allocSize = params->dwStackSize - (numPushes * 8);

            // If alloc size is less than 8, convert to push
            if (allocSize < 8) {
                numPushes = params->dwStackSize / 8;
                allocSize = 0;
            }
            // If alloc size exceeds ALLOC_SMALL range, reduce pushes
            else if (allocSize > 128) {
                numPushes = 0;
                allocSize = params->dwStackSize;
            }
        }
        else {
            numPushes = 0;
            allocSize = params->dwStackSize;
        }
    }
    // Need ALLOC_LARGE
    else {
        if (effectiveInstructions > 1) {
            numPushes = effectiveInstructions - 1;
            allocSize = params->dwStackSize - (numPushes * 8);
        }
        else {
            numPushes = 0;
            allocSize = params->dwStackSize;
        }
    }

    // Header: Version (1) + Flags
    raw[0] = (params->flags << 3) | 0x01;

    // Unwind codes start at offset 4
    PUNWIND_CODE pCodes = (PUNWIND_CODE)(raw + 4);

    // Registers to push (in reverse order of actual pushes)
    UBYTE pushRegs[] = { RBP, RBX, RDI, RSI, R12, R13, R14, R15 };

    // Add PUSH_NONVOL instructions
    for (DWORD i = 0; i < numPushes && i < 8; i++) {
        pCodes[codeIndex].CodeOffset = (UBYTE)codeOffset++;
        pCodes[codeIndex].UnwindOp = UWOP_PUSH_NONVOL;
        pCodes[codeIndex].OpInfo = pushRegs[i];
        codeIndex++;
    }

    // Add allocation instruction if needed
    if (allocSize > 0) {
        if (allocSize <= 128) {
            // ALLOC_SMALL
            pCodes[codeIndex].CodeOffset = (UBYTE)codeOffset;
            pCodes[codeIndex].UnwindOp = UWOP_ALLOC_SMALL;
            pCodes[codeIndex].OpInfo = (UBYTE)((allocSize / 8) - 1);
            codeIndex++;
            codeOffset += 4;  // sub rsp, imm8 is typically 4 bytes
        }
        else if (allocSize <= 512 * 1024 - 8) {
            // ALLOC_LARGE with OpInfo = 0
            pCodes[codeIndex].CodeOffset = (UBYTE)codeOffset;
            pCodes[codeIndex].UnwindOp = UWOP_ALLOC_LARGE;
            pCodes[codeIndex].OpInfo = 0;
            codeIndex++;

            pCodes[codeIndex].FrameOffset = (USHORT)(allocSize / 8);
            codeIndex++;
            codeOffset += 7;  // sub rsp, imm32 is typically 7 bytes
        }
        else {
            // ALLOC_LARGE with OpInfo = 1 (32-bit unscaled)
            pCodes[codeIndex].CodeOffset = (UBYTE)codeOffset;
            pCodes[codeIndex].UnwindOp = UWOP_ALLOC_LARGE;
            pCodes[codeIndex].OpInfo = 1;
            codeIndex++;

            pCodes[codeIndex].FrameOffset = (USHORT)(allocSize & 0xFFFF);
            codeIndex++;

            pCodes[codeIndex].FrameOffset = (USHORT)(allocSize >> 16);
            codeIndex++;
            codeOffset += 7;
        }
    }

    // Add SET_FPREG if requested
    if (params->useFpreg) {
        raw[3] = (params->fpOffset << 4) | params->fpReg;  // FrameOffset + FrameRegister

        pCodes[codeIndex].CodeOffset = (UBYTE)codeOffset;
        pCodes[codeIndex].UnwindOp = UWOP_SET_FPREG;
        pCodes[codeIndex].OpInfo = 0;
        codeIndex++;
        codeOffset += 4;  // lea rbp, [rsp+X]
    }

    // Fill in header
    raw[1] = (UBYTE)codeOffset;  // SizeOfProlog
    raw[2] = (UBYTE)codeIndex;   // CountOfCodes

    // Calculate total size and align
    DWORD totalSize = 4 + (codeIndex * 2);
    totalSize = ALIGN_UP(totalSize, 4);

    return totalSize;
}

DWORD CreateUnwind(PUNWIND_INFO pDest, DWORD dwStackSize, UBYTE numInstructions, BOOL useFpreg) {
    UNWIND_BUILD_PARAMS params = { 0 };

    params.dwStackSize = dwStackSize;
    params.numInstructions = numInstructions;
    params.flags = UNW_FLAG_UHANDLER;
    params.useFpreg = useFpreg;
    params.fpReg = RBP;
    params.fpOffset = 0;

    // Calculate actual code count from logical instructions
    DWORD codeCount = 0;

    BOOL needsAlloc = (dwStackSize > 0x8) || (numInstructions == 1 && dwStackSize > 0);
    DWORD pushCount = needsAlloc ? (numInstructions - 1) : numInstructions;

    if (dwStackSize == 0x8 && numInstructions == 1) {
        codeCount = 1;
    }
    else {
        codeCount += pushCount;

        if (needsAlloc) {
            DWORD allocSize = dwStackSize - (pushCount * 8);

            if (allocSize <= 128) {
                codeCount += 1;
            }
            else if (allocSize <= 512 * 1024 - 8) {
                codeCount += 2;
            }
            else {
                codeCount += 3;
            }
        }
    }

    if (useFpreg) {
        codeCount += 1;
    }

    DWORD destSize = ALIGN_UP(4 + (codeCount * 2), 4);

    return BuildUnwindInfo(pDest, destSize, &params);
}