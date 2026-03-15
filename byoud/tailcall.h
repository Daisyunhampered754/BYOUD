#pragma once
#include <windows.h>

typedef struct _WorkItemContext {
    void* func;          // +000h
    UINT64   reserved;   // +008h (Reserved)
    UINT64   argc;       // +010h
    UINT64   argv[4];    // +018h, +020h, +028h, +030h
} WorkItemContext;

extern "C" __declspec(dllexport) BOOL CALLBACK TailCall(
    PINIT_ONCE InitOnce,
    PVOID      Parameter,
    PVOID* Context
);
