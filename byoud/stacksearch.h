#ifndef STACK_SEARCH_H
#define STACK_SEARCH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	// Searches the current thread's stack for `value`
	// Returns offset in bytes from RSP to the found address, or 0 if not found
	uint64_t StackSearch(uint64_t value, uint64_t* stack_pointer_btit);
	
	uint64_t GetRSP();

#ifdef __cplusplus
}
#endif

#endif // STACK_SEARCH_H
