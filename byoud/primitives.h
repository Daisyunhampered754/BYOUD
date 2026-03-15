#pragma once

#include <Windows.h>

void* internal_memset(void* dest, int c, size_t n);
int internal_strcmp(const char* p1, const char* p2);
int internal_memcmp(const void* ptr1, const void* ptr2, size_t num);
void* internal_memcpy(void* dest, void* src, unsigned int len);
size_t internal_strlen(const char* str);
void WideToAnsi(const wchar_t* wide, char* ansiBuf, size_t maxOut);
unsigned int _Hton(unsigned int value);
