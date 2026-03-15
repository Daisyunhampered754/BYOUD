#include <Windows.h>

#define UNWIND_DATA_TAMPER 0x000f0000
#define UNWIND_DATA_HIJACK 0x0000f000
#define RT_FUNCTION_HIJACK 0x00000f00
#define RT_FUNCTION_INJECT 0x000000f0
#define RTFI_JIT_SYSINFORMER 0x0000000f
#define RTFI_JIT_NORMAL_VA 0x00f00000
#define RTFI_JIT_WINDBG 0x0f000000

typedef struct _WorkItemContext {
    void* func;       // +000h
    UINT64   unused;     // +008h (padding / formerly addressToPush)
    UINT64   argc;       // +010h
    UINT64   argv[4];    // +018h, +020h, +028h, +030h
} WorkItemContext;       // sizeof = 56 (0x38)

// Try one strategy with fallback mechanism
typedef UINT64(WINAPI* PFN_SHIELDED_EXECUTION)(HMODULE hModule, LPSTR lpFunctionName, DWORD dwArgc, DWORD64* pqwArgv, DWORD technique);
typedef BOOL(CALLBACK* TailCall_t)(PINIT_ONCE, PVOID, PVOID*);
