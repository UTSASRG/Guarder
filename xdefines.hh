/*
 * FreeGuard: A Faster Secure Heap Allocator
 * Copyright (C) 2017 Sam Silvestro, Hongyu Liu, Corey Crosser, 
 *                    Zhiqiang Lin, and Tongping Liu
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * 
 * @file   xdefines.hh: global constants, enums, definitions, and more.
 * @author Tongping Liu <http://www.cs.utsa.edu/~tongpingliu/>
 * @author Sam Silvestro <sam.silvestro@utsa.edu>
 */
#ifndef __XDEFINES_HH__
#define __XDEFINES_HH__

#include <stddef.h>
#include <stdint.h>
#include <ucontext.h>
#include <assert.h>

#include "slist.h"
#include "dlist.h"

/*
 * @file   xdefines.h
 */

extern char * getThreadBuffer();

extern "C" {
#ifndef CUSTOMIZED_STACK
__thread extern int _threadIndex;
#endif
typedef void * threadFunction(void*);

#ifdef LOGTOFILE
extern int outputfd;
#endif

#ifndef PTHREADEXIT_CODE
#define PTHREADEXIT_CODE 2230
#endif

typedef enum { LEFT, RIGHT } direction;

#ifdef LOGTOFILE
inline int getOutputFD() {
  return outputfd;
}
#endif

#ifndef CUSTOMIZED_STACK
inline int getThreadIndex(void * stackVar = NULL) {
	#warning using non-customized stack
  return _threadIndex;
}

inline void setThreadIndex(int index) {
  _threadIndex = index;
}
#endif
inline size_t alignup(size_t size, size_t alignto) {
  return (size % alignto == 0) ? size : ((size + (alignto - 1)) & ~(alignto - 1));
}

inline void * alignupPointer(void * ptr, size_t alignto) {
  return ((intptr_t)ptr%alignto == 0) ? ptr : (void *)(((intptr_t)ptr + (alignto - 1)) & ~(alignto - 1));
}

inline size_t aligndown(size_t addr, size_t alignto) { return (addr & ~(alignto - 1)); }

#ifdef LOGTOFILE
#define OUTFD getOutputFD()
#else 
#define OUTFD 2
#endif
#define LOG_SIZE 4096

}; // extern "C"

#define LOG2(x) ((unsigned) (8*sizeof(unsigned long long) - __builtin_clzll((x)) - 1))

#define DEFAULT_MAX_ALIVE_THREADS 128
//#define MAX_ALIVE_THREADS opts.max_alive_threads
#define MAX_ALIVE_THREADS 128

#define UNINITIALIZED_CACHE_REGION -1
#define ALLOC_SENTINEL 0x1
#define FREE_SENTINEL 0x0
#ifdef USE_CANARY
  #warning canary value in use
  #define CANARY_SENTINEL 0x7B
  #define NUM_MORE_CANARIES_TO_CHECK 2
  #define IF_CANARY_CONDITION ((size + 1) > LARGE_OBJECT_THRESHOLD)
#else
  #define IF_CANARY_CONDITION (size > LARGE_OBJECT_THRESHOLD)
#endif

#ifdef SSE2RNG
#define RNG_MAX 0x8000
#define SRAND(x) srand_sse(x)
#else
#define RNG_MAX RAND_MAX
#define SRAND(x) srand(x)
#endif

#define DEFAULT_BIBOP_ENTROPY_BITS 10
#define BIBOP_ENTROPY_BITS opts.bibop_entropy_bits
#define BIBOP_CACHE_SIZE opts.bibop_cache_size
#define BIBOP_CACHE_SIZE_MASK (BIBOP_CACHE_SIZE - 1)
#define BIBOP_HALF_CACHE_SIZE (BIBOP_CACHE_SIZE >> 1)
#define BIBOP_HALF_CACHE_SIZE_MASK (BIBOP_HALF_CACHE_SIZE - 1)
#define NUM_CACHE_REGIONS 8
#define NUM_CACHE_REGIONS_MASK (NUM_CACHE_REGIONS - 1)
#define NUM_CACHE_REGIONS_SHIFT_BITS LOG2(NUM_CACHE_REGIONS)
#define CACHE_REGION_SIZE (BIBOP_CACHE_SIZE >> NUM_CACHE_REGIONS_SHIFT_BITS)
#define CACHE_REGION_SIZE_MASK (CACHE_REGION_SIZE - 1)
#define CACHE_REGION_SIZE_SHIFT_BITS LOG2(CACHE_REGION_SIZE)

#define DEFAULT_OVER_PROV_OBJ_BUF_SZ (BIBOP_CACHE_SIZE >> 1)
#define OVER_PROV_OBJ_BUF_SZ (BIBOP_CACHE_SIZE >> 1)
#define NUM_DEAD_OBJS (OVER_PROV_OBJ_BUF_SZ * \
		(opts.over_prov_numerator - opts.over_prov_denominator) / opts.over_prov_numerator)
#define DEFAULT_OVER_PROV_NUMERATOR 8
#define DEFAULT_OVER_PROV_DENOMINATOR 7
#define DEFAULT_RAND_GUARD_PROP 0.1		// 10% guard pages per bag

#define PAGESIZE 0x1000
#define CACHE_LINE_SIZE 64

#define N_64BITS 64
#define TWO_KILOBYTES 2048
#ifdef DESTROY_ON_FREE
#warning destroy-on-free feature in use
#endif

struct guarder_opts {
	unsigned max_alive_threads = DEFAULT_MAX_ALIVE_THREADS;
	unsigned bibop_entropy_bits = DEFAULT_BIBOP_ENTROPY_BITS;
	unsigned bibop_cache_size = (1U << (DEFAULT_BIBOP_ENTROPY_BITS + 1));
	unsigned over_prov_numerator = DEFAULT_OVER_PROV_NUMERATOR;
	unsigned over_prov_denominator = DEFAULT_OVER_PROV_DENOMINATOR;
	float random_guard_prop = DEFAULT_RAND_GUARD_PROP;
};


/*
 * Important:
 * All BiBOP-related parameters must be specified as powers of 2
*/
//#define BIBOP_BAG_SIZE (size_t)0x080000000		// 2GB
//#define BIBOP_BAG_SIZE (size_t)0x040000000		// 1GB
//#define BIBOP_BAG_SIZE (size_t)0x020000000		// 512MB
//#define BIBOP_BAG_SIZE (size_t)0x010000000		// 256MB (not for PARSEC)

// Many PARSEC tests require at least a 512MB bag size
//#define MIN_RANDOM_BAG_SIZE (size_t)0x100000000			// 4GB
#define MIN_RANDOM_BAG_SIZE (size_t)0x200000000     // 4GB
#define MAX_RANDOM_BAG_SIZE (size_t)0x200000000			// 8GB

#define BIBOP_NUM_BAGS 16
#define BIBOP_MIN_BLOCK_SIZE 16
//#define LARGE_OBJECT_THRESHOLD (1U << (LOG2(BIBOP_MIN_BLOCK_SIZE) + BIBOP_NUM_BAGS - 1)
#define LARGE_OBJECT_THRESHOLD 0x80000	// 512KB

#define BIBOP_NUM_BAGS_MASK (BIBOP_NUM_BAGS - 1)
#define BIBOP_NUM_SUBHEAPS MAX_ALIVE_THREADS
#define BIBOP_SUBHEAP_SIZE (size_t)(BIBOP_NUM_BAGS * _bibopBagSize)
#define BIBOP_HEAP_SIZE (size_t)(BIBOP_SUBHEAP_SIZE * BIBOP_NUM_SUBHEAPS)
#define PageSize 4096UL
#define PageMask (PageSize - 1)
#define RANDOM_GUARD_PROP (opts.random_guard_prop)
#define RANDOM_GUARD_RAND_CUTOFF (RANDOM_GUARD_PROP * RNG_MAX)
#define THREAD_MAP_SIZE	1280

#ifdef CUSTOMIZED_STACK
#define STACK_SIZE  		0x800000	// 8M, PageSize * N
#define STACK_SIZE_BIT  23	// 8M
#define MAX_THREADS 		MAX_ALIVE_THREADS
#define INLINE      		inline __attribute__((always_inline))

#define GUARD_PAGE_SIZE PageSize // PageSize * N
#include <sys/mman.h>
extern intptr_t globalStackAddr;
// Get the thread index by its stack address
INLINE int getThreadIndex(void* stackVar) {
	//int index = ((intptr_t)stackVar - globalStackAddr) / STACK_SIZE;
	int index = ((intptr_t)stackVar - globalStackAddr) >> STACK_SIZE_BIT;
#if 0 // test
	if(index >= MAX_THREADS || index < 0) {
		fprintf(stderr, "var %p stackaddr %lx index %d\n", stackVar, globalStackAddr, index);
	}

	if(index == 1 ) {
		//char * tmp = (char*)(globalStackAddr + (index+1) * STACK_SIZE - 512);
		char * tmp = (char*)(globalStackAddr + (index) * STACK_SIZE + 512);
		fprintf(stderr, "touch %p thread %d %p - %p\n", tmp, index, globalStackAddr + (index) * STACK_SIZE, globalStackAddr + (index+1) * STACK_SIZE);
		*tmp = 'a';
	}
#endif
#ifdef CUSTOMIZED_MAIN_STACK
	assert(index >= 0 && index < MAX_THREADS);
	return index;
#endif
	if (index >= MAX_THREADS || index <= 0) return 0;
	else return index;
}
#endif

#define WORD_SIZE sizeof(size_t)
#define POINTER_SIZE sizeof(void *)
#define PTR_SIZE_SHIFT_BITS LOG2(sizeof(void *))
#define CALLSTACK_DEPTH 3

typedef char shadowObjectInfo;

#endif
