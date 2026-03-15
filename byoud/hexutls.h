#pragma once
#include <windows.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

typedef struct _BINARY_SEARCH_OPTION {
    uint8_t* Pattern;
    size_t PatternSize;
    uint8_t* Mask;
} BINARY_SEARCH_OPTION, * PBINARY_SEARCH_OPTION;

size_t pattern_search(const uint8_t* buffer, size_t bufferSize, PBINARY_SEARCH_OPTION option);

void* search_rpc_init(HMODULE hModule);

void* search_rpc_invoke(HMODULE hModule);


