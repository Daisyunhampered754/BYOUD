#include "pch.h"
#include "primitives.h"

void* internal_memset(void* dest, int c, size_t n) {
    unsigned char* ptr = (unsigned char*)dest;
    for (size_t i = 0; i < n; i++) {
        ptr[i] = (unsigned char)c;
    }
    return dest;
}

int internal_strcmp(const char* p1, const char* p2) {
    const unsigned char* s1 = (const unsigned char*)p1;
    const unsigned char* s2 = (const unsigned char*)p2;
    unsigned char c1, c2;
    do {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if (c1 == '\0') {
            return c1 - c2;
        }
    } while (c1 == c2);
    return c1 - c2;
}

int internal_memcmp(const void* ptr1, const void* ptr2, size_t num) {
    const unsigned char* p1 = (const unsigned char*)ptr1;
    const unsigned char* p2 = (const unsigned char*)ptr2;

    for (size_t i = 0; i < num; ++i) {
        if (p1[i] != p2[i]) {
            return (int)(p1[i] - p2[i]);
        }
    }
    return 0;
}

size_t internal_strlen(const char* str) {
    const char* s = str;
    while (*s) ++s;
    return s - str;
}


void* internal_memcpy(void* dest, void* src, unsigned int len)
{
    unsigned int i;
    char* char_src = (char*)src;
    char* char_dest = (char*)dest;
    for (i = 0; i < len; i++) {
        char_dest[i] = char_src[i];
    }
    return dest;
}

void WideToAnsi(const wchar_t* wide, char* ansiBuf, size_t maxOut) {
    for (size_t i = 0; i < maxOut - 1 && wide[i]; i++) {
        ansiBuf[i] = (char)(wide[i] & 0x7F); // Only lower 7 bits, ASCII-safe
    }
    ansiBuf[maxOut - 1] = '\0';
}

unsigned int _Hton(unsigned int value)
{
    unsigned char* s = (unsigned char*)&value;
    return (unsigned int)(s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]);

}
