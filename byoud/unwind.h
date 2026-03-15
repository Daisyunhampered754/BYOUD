#pragma once
#include <windows.h>
#include <stdio.h>

#ifdef _DEBUG
#define DPRINTUNWINDCODE(x) { \
	printf("0x%x\t", x->CodeOffset);		\
	printf("0x%x\t", x->OpInfo);			\
	printf("0x%x\n", x->UnwindOp);			\
}

#else
#define DPRINTUNWINDCODE(x) {}
#endif
#ifdef _DEBUG
#ifdef _VERBOSE_DEBUG
#define DPRINTCTX(x) { \
	printf("RAX: 0x%llx -", x.Rax);			\
	printf("RBX :0x%llx -", x.Rbx);			\
	printf("RCX: 0x%llx -", x.Rcx);			\
	printf("RDX: 0x%llx -", x.Rdx);			\
	printf("RDI: 0x%llx -", x.Rdi);			\
	printf("RSI: 0x%llx -", x.Rsi);			\
	printf("RBP: 0x%llx -", x.Rbp);			\
	printf("RSP: 0x%llx -\n", x.Rsp);			\
	printf("R8 : 0x%llx -", x.R8 );			\
	printf("R9 : 0x%llx -", x.R9 );			\
	printf("R10: 0x%llx -", x.R10);			\
	printf("R11: 0x%llx -", x.R11);			\
	printf("R12: 0x%llx -", x.R12);			\
	printf("R13: 0x%llx -", x.R13);			\
	printf("R14: 0x%llx -", x.R14);			\
	printf("R15: 0x%llx \n", x.R15);			\
	printf("RIP: 0x%llx \n", x.Rip);			\
	}
#else
#define DPRINTCTX(x) {}
#endif
#else
#define DPRINTCTX(x) {}
#endif

#define MAX_FRAMES 154
#define HIDWORD(l) ((DWORD)(((DWORDLONG)(l)>>32)&0xFFFFFFFF))
#define ALIGN_UP(x, a) (((x) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_UP_POW2(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

#define BitVal(data,y) ( (data>>y) & 1) 

#define BitChainInfo(data) BitVal(data, 2) 
#define BitUHandler(data) BitVal(data, 1) 
#define BitEHandler(data) BitVal(data, 0) 
#define Version(data) BitVal(data, 4)*2 + BitVal(data, 3) 

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define B2BP BYTE_TO_BINARY_PATTERN
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 

typedef PIMAGE_RUNTIME_FUNCTION_ENTRY PERF;

typedef UCHAR UBYTE;

typedef enum _REGISTERS {
    RAX = 0,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15
} REGISTERS;

typedef struct _UNWIND_BACKUP {
    PVOID pOriginalLocation;    // Dove era l'UNWIND_INFO
    DWORD dwSize;               // Dimensione totale
    BYTE  Data[1];              // Dati originali (flexible array)
} UNWIND_BACKUP, * PUNWIND_BACKUP;

typedef union _UNWIND_CODE {
    struct {
        UBYTE CodeOffset;  // 0xFF00
        UBYTE UnwindOp : 4; // 0x000f OPCODE
        UBYTE OpInfo : 4;   // 0x00f0 
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _MIN_CTX {

    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;

    DWORD64 Rip;
    DWORD64 Reserved;
    DWORD64 StackSize;

} MIN_CTX, * PMIN_CTX;

typedef struct _UNWIND_INFO {
    UBYTE Version : 3;
    UBYTE Flags : 5;    // 4 bytes
    UBYTE SizeOfProlog; // 4 bytes
    UBYTE CountOfCodes; // 4 bytes
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset : 4; // 4bytes
    UNWIND_CODE UnwindCode[1];
    union {
        OPTIONAL ULONG ExceptionHandler;
        OPTIONAL ULONG FunctionEntry;
    };
    OPTIONAL ULONG* ExceptionData;
} UNWIND_INFO, * PUNWIND_INFO;


typedef struct _RUNTIME_FUNCTION_BACKUP {
    PRUNTIME_FUNCTION pOriginalLocation;
    RUNTIME_FUNCTION  Data;
} RUNTIME_FUNCTION_BACKUP, * PRUNTIME_FUNCTION_BACKUP;

typedef struct _RTL_BALANCED_NODE {
    union {
        struct _RTL_BALANCED_NODE* Children[2];
        struct {
            struct _RTL_BALANCED_NODE* Left;
            struct _RTL_BALANCED_NODE* Right;
        };
    };
    union {
        UCHAR  Red : 1;
        UCHAR  Balance : 2;
        ULONG64 ParentValue;   // Parent pointer with flags encoded in low bits
        // actual parent = ParentValue & ~3
    };
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

// Undocumented — layout consistent across Win7–Win11
typedef struct _DYNAMIC_FUNCTION_TABLE {
    LIST_ENTRY          Links;                      // +0x000
    PRUNTIME_FUNCTION   FunctionTable;              // +0x010
    LARGE_INTEGER       TimeStamp;                  // +0x018
    ULONG64             MinimumAddress;             // +0x020
    ULONG64             MaximumAddress;             // +0x028
    ULONG64             BaseAddress;                // +0x030
    PVOID               Callback;                   // +0x038
    PVOID               Context;                    // +0x040
    PWSTR               OutOfProcessCallbackDll;    // +0x048
    DWORD               Type;                       // +0x050 
    DWORD               EntryCount;                 // +0x054
} DYNAMIC_FUNCTION_TABLE, * PDYNAMIC_FUNCTION_TABLE;

typedef struct _INVERTED_FUNCTION_TABLE_ENTRY {
    PVOID   ExceptionDirectory;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   ExceptionDirectorySize;
} INVERTED_FUNCTION_TABLE_ENTRY, * PINVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _INVERTED_FUNCTION_TABLE {
    ULONG   Count;
    ULONG   MaxCount;
    ULONG   Epoch;
    UCHAR   Overflow;
    INVERTED_FUNCTION_TABLE_ENTRY Entries[0x100];
} INVERTED_FUNCTION_TABLE, * PINVERTED_FUNCTION_TABLE;

PDYNAMIC_FUNCTION_TABLE FindLocalDynamicFunctionTable(ULONG64 Address);

BOOL FindDynamicFunctionTablePointers(
    HANDLE  hProcess,
    ULONG64* OutHeadPtr,
    ULONG64* OutSentinel);

static inline PULONG GetExceptionHandlerPtr(PUNWIND_INFO info)
{
    // Skip past the variable-length UnwindCode array, aligned to 4 bytes
    DWORD alignedCount = (info->CountOfCodes + 1) & ~1;  // round up to even
    return (PULONG)&info->UnwindCode[alignedCount];
}

static inline PVOID GetLanguageSpecificDataPtr(PUNWIND_INFO info)
{
    return (PVOID)(GetExceptionHandlerPtr(info) + 1);  // 4 bytes past the handler RVA
}

#define GetUnwindCodeEntry(info, index) \
    ((info)->UnwindCode[index])

#define GetLanguageSpecificDataPtr(info) \
    ((PVOID)&GetUnwindCodeEntry((info),((info)->CountOfCodes + 1) & ~1))

#define GetExceptionHandler(base, info) \
    ((PVOID)((ULONG64)(base) + *GetExceptionHandlerPtr(info)))

#define GetChainedFunctionEntry(base, info) \
    ((PRUNTIME_FUNCTION)GetExceptionHandlerPtr(info))

#define GetExceptionDataPtr(info) \
    GetLanguageSpecificDataPtr(info)

typedef enum _UNWIND_OP_CODES {
    // x86_64. https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64.
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,       // 1
    UWOP_ALLOC_SMALL,       // 2
    UWOP_SET_FPREG,         // 3
    UWOP_SAVE_NONVOL,       // 4
    UWOP_SAVE_NONVOL_BIG,   // 5
    UWOP_EPILOG,            // 6
    UWOP_SPARE_CODE,        // 7
    UWOP_SAVE_XMM128,       // 8
    UWOP_SAVE_XMM128BIG,    // 9
    UWOP_PUSH_MACH_FRAME,   // 10

    // ARM64. https://docs.microsoft.com/en-us/cpp/build/arm64-exception-handling
    UWOP_ALLOC_MEDIUM,
    UWOP_SAVE_R19R20X,
    UWOP_SAVE_FPLRX,
    UWOP_SAVE_FPLR,
    UWOP_SAVE_REG,
    UWOP_SAVE_REGX,
    UWOP_SAVE_REGP,
    UWOP_SAVE_REGPX,
    UWOP_SAVE_LRPAIR,
    UWOP_SAVE_FREG,
    UWOP_SAVE_FREGX,
    UWOP_SAVE_FREGP,
    UWOP_SAVE_FREGPX,
    UWOP_SET_FP,
    UWOP_ADD_FP,
    UWOP_NOP,
    UWOP_END,
    UWOP_SAVE_NEXT,
    UWOP_TRAP_FRAME,
    UWOP_CONTEXT,
    UWOP_CLEAR_UNWOUND_TO_CALL,
    // ARM: https://docs.microsoft.com/en-us/cpp/build/arm-exception-handling

    UWOP_ALLOC_HUGE,
    UWOP_WIDE_ALLOC_MEDIUM,
    UWOP_WIDE_ALLOC_LARGE,
    UWOP_WIDE_ALLOC_HUGE,

    UWOP_WIDE_SAVE_REG_MASK,
    UWOP_WIDE_SAVE_SP,
    UWOP_SAVE_REGS_R4R7LR,
    UWOP_WIDE_SAVE_REGS_R4R11LR,
    UWOP_SAVE_FREG_D8D15,
    UWOP_SAVE_REG_MASK,
    UWOP_SAVE_LR,
    UWOP_SAVE_FREG_D0D15,
    UWOP_SAVE_FREG_D16D31,
    UWOP_WIDE_NOP, // UWOP_NOP
    UWOP_END_NOP,  // UWOP_END
    UWOP_WIDE_END_NOP,
    // Custom implementation opcodes (implementation specific).
    UWOP_CUSTOM,
} UNWIND_OP_CODES;

typedef struct _UNWIND_BUILD_PARAMS {
    DWORD   dwStackSize;        // Total stack frame size
    UBYTE   numInstructions;    // Number of logical unwind operations
    UBYTE   flags;              // UNW_FLAG_*
    BOOL    useFpreg;           // Use SET_FPREG
    UBYTE   fpReg;              // Frame pointer register (e.g., RBP)
    UBYTE   fpOffset;           // Frame pointer offset (scaled by 16)
} UNWIND_BUILD_PARAMS, * PUNWIND_BUILD_PARAMS;

typedef VOID(NTAPI* fnRtlAcquireSRWLockExclusive)(PRTL_SRWLOCK);
typedef VOID(NTAPI* fnRtlReleaseSRWLockExclusive)(PRTL_SRWLOCK);
typedef VOID(NTAPI* fnLdrProtectMrdata)(BOOL Protect);

DWORD BuildUnwindInfo(PUNWIND_INFO pDest, DWORD destSize, PUNWIND_BUILD_PARAMS params);
DWORD CreateUnwind(PUNWIND_INFO pDest, DWORD dwStackSize, UBYTE numInstructions, BOOL useFpreg);

PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddress(UINT64, DWORD);
PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddressInTable(PRUNTIME_FUNCTION pRuntimeFunctionTable, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD64 functionOffset);
PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByAddressInRFTable(PRUNTIME_FUNCTION pRuntimeFunctionTable, DWORD rtLastIndex, DWORD64 functionOffset);
PIMAGE_RUNTIME_FUNCTION_ENTRY RTFindFunctionByIndex(UINT64, DWORD);
DWORD GetStackFrameSize(HMODULE, PVOID, DWORD*);
void LookupSymbolFromRTIndex(HMODULE, int, bool);
void EnumAllRTFunctions(HMODULE);
DWORD FindRTFunctionsUnwind(HMODULE, PVOID);
void CheckFunction(const char* moduleName, const char* funcName);
DWORD GetFunctionSizeByAddress(HMODULE hModule, PVOID pFunction);


BOOL PrintUnwindInfo(HMODULE dllBase, PVOID unwindDataAddress, INT UWOP_filter, BOOL headers = FALSE);

BYTE ExtractOpInfo(BYTE OpIC);
BYTE ExtractOpCode(BYTE OpIC);
char* GetOpInfo(int op);

BOOL UnprotectText(HMODULE hMod);
BOOL ProtectText(HMODULE hMod);
BOOL UnprotectPdata(HMODULE hMod);
BOOL ProtectPdata(HMODULE hMod);
BOOL UnprotectRdata(HMODULE hMod);
BOOL ProtectRdata(HMODULE hMod);
BOOL UnprotectData(HMODULE hMod);
BOOL ProtectData(HMODULE hMod);

BOOL SuppressExceptionDirectory(HMODULE hModule, PIMAGE_DATA_DIRECTORY pBackup);
BOOL RestoreExceptionDirectory(HMODULE hModule, PIMAGE_DATA_DIRECTORY pBackup);

BOOL AppendCodeText(HMODULE hMod, PVOID codeAddress, DWORD codeSize, PDWORD appendedCodeOffset);

DWORD FindLastUnwindOffset(UINT64 modulelBase);
BOOL AppendUnwindData(HMODULE hMod, PUNWIND_INFO tInfo, PDWORD address);
BOOL ChangeExceptionDirectoryAddress(HMODULE hMod, DWORD newAddress);
BOOL IncreaseExceptionDirectorySize(HMODULE hMod, DWORD size);
BOOL AppendRuntimeFunctionToExceptionDirectory(HMODULE hMod, PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFunction);

DWORD SizeOfUnwind(PUNWIND_INFO pInfo);

// Save entire UNWIND_INFO structure
// Returns backup handle (NULL on failure)
PUNWIND_BACKUP SaveUnwind(PUNWIND_INFO tInfo);

// Restore UNWIND_INFO from backup
// Returns TRUE on success
BOOL RestoreUnwind(PUNWIND_BACKUP backup);

PRUNTIME_FUNCTION_BACKUP SaveRuntimeFunction(PRUNTIME_FUNCTION pFunc);
BOOL RestoreRuntimeFunction(HMODULE hModule, PRUNTIME_FUNCTION_BACKUP backup);

// Free functions
void FreeUnwindBackup(PUNWIND_BACKUP backup);
void FreeRuntimeFunctionBackup(PRUNTIME_FUNCTION_BACKUP backup);


BOOL FindInvertedFunctionTable(
    PINVERTED_FUNCTION_TABLE* OutTable,
    PRTL_SRWLOCK* OutLock);

BOOL FindLdrProtectMrdata(fnLdrProtectMrdata* OutFn);

BOOL ShrinkInvertedFunctionTableEntry(HMODULE hModule, ULONG64 ShcAddress, PULONG pOldSize);
BOOL EnlargeInvertedFunctionTableEntry(HMODULE hModule, ULONG64 ShcAddress, PULONG pOldSize);
BOOL RestoreInvertedFunctionTableEntry(HMODULE hModule, ULONG oldSize);