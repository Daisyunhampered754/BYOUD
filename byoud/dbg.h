#pragma once

#ifdef NDEBUG
#define DBG(x) ((void)0)
#else
#define DBG(x) x
#endif

#ifdef NDEBUG
#pragma function(printf) // Prevent linking printf accidentally
#endif

void hexdump(void* ptr, int buflen);

