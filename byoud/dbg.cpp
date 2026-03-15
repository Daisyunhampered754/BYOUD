#include "pch.h"
#include "dbg.h"
#include <stdio.h>
#include <ctype.h>


void hexdump(void* ptr, int buflen) {
    unsigned char* buf = (unsigned char*)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16) {
        DBG(printf("%06x: ", i));
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                DBG(printf("%02x ", buf[i + j]));
            else
                DBG(printf("   "));
        DBG(printf(" "));
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                DBG(printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.'));
        DBG(printf("\n"));
    }
    DBG(printf("-------------------------------------------------------------------------\n"));
}