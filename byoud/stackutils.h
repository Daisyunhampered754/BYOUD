#pragma once
#include <stdint.h>

#define GetCurrentRsp GetRSP

uint64_t GetStackBtitAddress(uint64_t* stack_pointer);
BOOL ModuleHasStackCookies(HMODULE hModule);
