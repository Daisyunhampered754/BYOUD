#include <stdio.h>
#include "byoud.h"

BOOL CALLBACK MyCallback(PINIT_ONCE lpInitOnce, PVOID Parameter, PVOID* Context) {
    printf("InitOnce callback executed! Parameter: %p\n", Parameter);
    MessageBoxA(0, "InitOnce callback executed!", "Ah!", 0);
    return TRUE;
}

void TestTechnique(PFN_SHIELDED_EXECUTION pShieldedExecution, HMODULE hTarget, DWORD technique, const char* techniqueName) {
    printf("\n========================================\n");
    printf("[*] Testing technique: %s\n", techniqueName);
    printf("========================================\n");

    TailCall_t pTailCall = (TailCall_t)GetProcAddress(GetModuleHandleA("byoud"), "TailCall");
    if (pTailCall == NULL) {
        printf("[-] Couldn't find TailCall Export\n");
        return;
    }

    DWORD argc = 4;
    DWORD64* argv = (DWORD64*)malloc(argc * sizeof(DWORD64));
    if (argv == NULL) {
        printf("[-] Failed to alloc argv\n");
        return;
    }
    memset(argv, 0, argc * sizeof(DWORD64));

    const char* msg = "Sample Message";
    const char* title = "Sample Title";

    PVOID lpContext;
    INIT_ONCE g_InitOnce = INIT_ONCE_STATIC_INIT;

    WorkItemContext* ctx = (WorkItemContext*)malloc(sizeof(WorkItemContext));
    if (NULL == ctx) {
        printf("[-] Failed to alloc CTX structure\n");
        free(argv);
        return;
    }
    HMODULE user32 = LoadLibraryA("user32");
    if (NULL == user32) {
        free(argv);
        return;
    }

    FARPROC msgboxa = GetProcAddress(user32, "MessageBoxA");
    if (NULL == msgboxa) {
        free(argv);
        return;
    }

    ctx->func = msgboxa;
    ctx->argc = 4;
    ctx->argv[0] = (UINT64)0;
    ctx->argv[1] = (UINT64)msg;
    ctx->argv[2] = (UINT64)title;
    ctx->argv[3] = (UINT64)0;

    argv[0] = (DWORD64)&g_InitOnce;
    argv[1] = (DWORD64)pTailCall;
    argv[2] = (DWORD64)ctx;
    argv[3] = (DWORD64)&lpContext;
    
    printf("TailCall Address: 0x%llx\n", (ULONG64)pTailCall);

    UINT64 result = pShieldedExecution(hTarget, (LPSTR)"InitOnceExecuteOnce", argc, argv, technique);
    printf("[*] Result: 0x%llx\n", result);

    free(ctx);
    free(argv);
}

int main()
{
    HMODULE byoud = LoadLibraryA("byoud");
    if (byoud == NULL) {
        printf("[-] Failed to load byoud\n");
        return -1;
    }

    PFN_SHIELDED_EXECUTION pShieldedExecution = (PFN_SHIELDED_EXECUTION)GetProcAddress(byoud, "ShieldedExecution");
    if (pShieldedExecution == NULL) {
        printf("[-] Failed to get ShieldedExecution\n");
        return -1;
    }

    HMODULE k32 = GetModuleHandleA("kernelbase");
    if (k32 == NULL) {
        printf("[-] Failed to get kernelbase\n");
        return -1;
    }

    // Test menu
    printf("Select technique:\n");
    printf("  1. UNWIND_DATA_TAMPER\n");
    printf("  2. UNWIND_DATA_HIJACK\n");
    printf("  3. RT_FUNCTION_HIJACK\n");
    printf("  4. RT_FUNCTION_INJECT\n");
    printf("  5. RTFI_JIT_SYSINFORMER\n");
    printf("  6. RTFI_JIT_WINDBG\n");
    printf("  7. RTFI_JIT_NORMAL_VA\n");
    printf("  0. Run all\n");
    printf("> ");

    int choice;
    scanf_s("%d", &choice);

    switch (choice) {
    case 0:
        TestTechnique(pShieldedExecution, k32, UNWIND_DATA_TAMPER, "UNWIND_DATA_TAMPER");
        TestTechnique(pShieldedExecution, k32, UNWIND_DATA_HIJACK, "UNWIND_DATA_HIJACK");
        TestTechnique(pShieldedExecution, k32, RT_FUNCTION_HIJACK, "RT_FUNCTION_HIJACK");
        TestTechnique(pShieldedExecution, k32, RT_FUNCTION_INJECT, "RT_FUNCTION_INJECT");
        TestTechnique(pShieldedExecution, k32, RTFI_JIT_SYSINFORMER, "RTFI_JIT_SYSINFORMER");
        TestTechnique(pShieldedExecution, k32, RTFI_JIT_WINDBG, "RTFI_JIT_WINDBG");
        TestTechnique(pShieldedExecution, k32, RTFI_JIT_NORMAL_VA, "RTFI_JIT_NORMAL_VA");
        break;
    case 1:
        TestTechnique(pShieldedExecution, k32, UNWIND_DATA_TAMPER, "UNWIND_DATA_TAMPER");
        break;
    case 2:
        TestTechnique(pShieldedExecution, k32, UNWIND_DATA_HIJACK, "UNWIND_DATA_HIJACK");
        break;
    case 3:
        TestTechnique(pShieldedExecution, k32, RT_FUNCTION_HIJACK, "RT_FUNCTION_HIJACK");
        break;
    case 4:
        TestTechnique(pShieldedExecution, k32, RT_FUNCTION_INJECT, "RT_FUNCTION_INJECT");
        break;
    case 5:
        TestTechnique(pShieldedExecution, k32, RTFI_JIT_SYSINFORMER, "RTFI_JIT_SYSINFORMER");
        break;
    case 6:
        TestTechnique(pShieldedExecution, k32, RTFI_JIT_WINDBG, "RTFI_JIT_WINDBG");
        break;
    case 7:
        TestTechnique(pShieldedExecution, k32, RTFI_JIT_NORMAL_VA, "RTFI_JIT_NORMAL_VA");
        break;
    default:
        printf("[-] Invalid choice\n");
        break;
    }

    FreeLibrary(byoud);
    return 0;
}