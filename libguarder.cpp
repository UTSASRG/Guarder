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
 * @file   libfreeguard.cpp: main file, includes memory interception functions.
 * @author Tongping Liu <http://www.cs.utsa.edu/~tongpingliu/>
 * @author Sam Silvestro <sam.silvestro@utsa.edu>
 */
#include <dlfcn.h>
#include <sys/mman.h>
#include "real.hh"
#include "xthread.hh"
#include "bibopheap.hh"
#include "mm.hh"
#include "bigheap.hh"
#ifdef SSE2RNG
#include "sse2rng.h"
#endif

void heapinitialize();
__attribute__((constructor)) void initializer() {
	heapinitialize();
}

#ifdef CUSTOMIZED_STACK
intptr_t globalStackAddr;

typedef int (*main_fn_t)(int, char**, char**);

extern "C" int __libc_start_main(main_fn_t, int, char**, void (*)(), void (*)(), void (*)(), void*) __attribute__((weak, alias("freeguard_libc_start_main")));

extern "C" int freeguard_libc_start_main(main_fn_t main_fn, int argc, char** argv, void (*init)(), void (*fini)(), void (*rtld_fini)(), void* stack_end) {
	// allocate stack area
	size_t stackSize = (size_t)STACK_SIZE * MAX_THREADS;
	if((globalStackAddr = (intptr_t)MM::mmapAllocatePrivate(stackSize)) == 0) {
		FATAL("Failed to initialize stack area\n");
	}
	madvise((void *)globalStackAddr, stackSize, MADV_NOHUGEPAGE);

	// set guard pages in cusotmized stack area. Set in both the beginnning and end.
	// better way is to set this when we use a new thread index, which may require changing the bool flag in thread_t to a int.
	for(int i = 1; i < MAX_THREADS; i++) { // ingore the first thread
		intptr_t stackStart = globalStackAddr + i * STACK_SIZE;
		if((mprotect((void*)(stackStart + STACK_SIZE - GUARD_PAGE_SIZE), GUARD_PAGE_SIZE, PROT_NONE) == -1)
				|| (mprotect((void*)stackStart, GUARD_PAGE_SIZE, PROT_NONE) == -1)) {
			perror("Failed to set guard pages");
			abort();
		}
	}
#ifdef CUSTOMIZED_MAIN_STACK
	intptr_t ebp, esp, customizedEbp, customizedEsp, ebpOffset, espOffset;
	intptr_t stackTop = (((intptr_t)&main_fn + PageSize) & ~(PageSize - 1)) + PageSize; // page align
	intptr_t newStackTop = globalStackAddr + STACK_SIZE - GUARD_PAGE_SIZE;
	// get current stack
#if defined(X86_32BIT)
	asm volatile("movl %%ebp,%0\n"
								"movl %%esp,%1\n"
								: "=r"(ebp), "=r"(esp)::"memory");
#else
	asm volatile("movq %%rbp,%0\n"
							"movq %%rsp, %1\n"
							: "=r"(ebp), "=r"(esp)::"memory");
#endif
	// copy stack data
	ebpOffset = stackTop - ebp;
	espOffset = stackTop - esp;
	customizedEbp = newStackTop - ebpOffset;
	customizedEsp = newStackTop - espOffset;
	memcpy((void*)customizedEsp, (void*)esp, espOffset);
#if defined(X86_32BIT)
	asm volatile("movl %0, %%ebp\n"
								"movl %1, %%esp\n"
								:: "r"(customizedEbp), "r"(customizedEsp):"memory");
#else
	asm volatile("movq %0,%%rbp\n"
								"movq %1,%%rsp\n"
								:: "r"(customizedEbp), "r"(customizedEsp):"memory");
#endif
	// re-direct arguments
	argv = (char**)(newStackTop - (stackTop - (intptr_t)argv));

	for(int i = 0; i < argc; i++) {
		argv[i] = (char*)(newStackTop - (stackTop - (intptr_t)argv[i]));
	}
	
	stack_end = (void*)(newStackTop - (stackTop - (intptr_t)stack_end));
	// re-direct arguments
	// reset original stack

	memset((void*)esp, 0, espOffset);
#if 0 
	unsigned long orig = ((unsigned long)esp) & ~(PageSize - 1); 
	fprintf(stderr, "unmap orig stack %p size %lx\n", orig, stackTop - orig);
	if(munmap((void*)orig, stackTop - orig) != 0) {
		//fprintf(stderr, "unmap orig stack %p size %lx failed, memeset instead %p\n", orig, stackTop - orig, stack_end);
		memset((void*)esp, 0, espOffset);
	}
#endif
#endif

	// real run
  auto real_libc_start_main = (decltype(__libc_start_main)*)dlsym(RTLD_NEXT, "__libc_start_main");
  return real_libc_start_main(main_fn, argc, argv, init, fini, rtld_fini, stack_end);
}
#else
	__thread int _threadIndex;
#endif

// Variables used by our pre-init private allocator
typedef enum {
	E_HEAP_INIT_NOT = 0,
	E_HEAP_INIT_WORKING,
	E_HEAP_INIT_DONE,
} eHeapInitStatus;

eHeapInitStatus heapInitStatus = E_HEAP_INIT_NOT;
unsigned long numLargeObjects = 0;

extern "C" {
	void xxfree(void *);
	void * xxmalloc(size_t);
	void * xxcalloc(size_t, size_t);
	void * xxrealloc(void *, size_t);

  void * xxvalloc(size_t);
  void * xxaligned_alloc(size_t, size_t);
  void * xxmemalign(size_t, size_t);
  void * xxpvalloc(size_t);
  void * xxalloca(size_t);
  int 	 xxposix_memalign(void **, size_t, size_t);

	// Function aliases
	void free(void *) __attribute__ ((weak, alias("xxfree")));
	void * malloc(size_t) __attribute__ ((weak, alias("xxmalloc")));
	void * calloc(size_t, size_t) __attribute__ ((weak, alias("xxcalloc")));
	void * realloc(void *, size_t) __attribute__ ((weak, alias("xxrealloc")));

  void * valloc(size_t) __attribute__ ((weak, alias("xxvalloc")));
  void * aligned_alloc(size_t, size_t) __attribute__ ((weak,
        alias("xxaligned_alloc")));
  void * memalign(size_t, size_t) __attribute__ ((weak, alias("xxmemalign")));
  void * pvalloc(size_t) __attribute__ ((weak, alias("xxpvalloc")));
  void * alloca(size_t) __attribute__ ((weak, alias("xxalloca")));
  int posix_memalign(void **, size_t, size_t) __attribute__ ((weak,
        alias("xxposix_memalign")));
}

__attribute__((destructor)) void finalizer() {
	PRDBG("%lu large objects (>%d) were allocated", numLargeObjects, LARGE_OBJECT_THRESHOLD);
}

void parseEnvOpts() {
		char * value;

		// opts is a global struct located in bibopheap.hh
		if((value = getenv("GUARDER_NUMERATOR"))) {
				opts.over_prov_numerator = atoi(value);
		}
    if((value = getenv("GUARDER_DENOMINATOR"))) {
        opts.over_prov_denominator = atoi(value);
    }
		// Over provisioning ratio must be greater than or equal to 1
		if((opts.over_prov_denominator <= 0) ||
						(opts.over_prov_numerator < opts.over_prov_denominator)) {
				PRERR("over provisioning ratio invalid; setting to 1/1");
				opts.over_prov_numerator = 1;
				opts.over_prov_denominator = 1;
		}

    if((value = getenv("GUARDER_ENTROPY_BITS"))) {
        opts.bibop_entropy_bits = atoi(value);
    }
		// Entropy bits must be a positive integer
		if(opts.bibop_entropy_bits <= 0) {
				PRERR("invalid bibop entropy bits; setting to default value (%u)",
								DEFAULT_BIBOP_ENTROPY_BITS);
				opts.bibop_entropy_bits = DEFAULT_BIBOP_ENTROPY_BITS;
		}

		opts.bibop_cache_size = (1U << (opts.bibop_entropy_bits + 1));

		/*
    if((value = getenv("GUARDER_CACHE_DIVISOR"))) {
        opts.bibop_cache_allowance_divisor = atoi(value);
    }
		// Cache allowance divisor must be a positive integer >= 2
		if(opts.bibop_cache_allowance_divisor < 2) {
				PRERR("invalid bibop cache allowance divisor; "
								"setting to default value (%u)", DEFAULT_BIBOP_CACHE_ALLOWANCE_DIVISOR);
				opts.bibop_cache_allowance_divisor = DEFAULT_BIBOP_CACHE_ALLOWANCE_DIVISOR;
		}
		*/

    if((value = getenv("GUARDER_RAND_GUARD_PROP"))) {
        opts.random_guard_prop = atof(value);
    }
		// Random guard proportion must be a fraction between [0, 1)
		if((opts.random_guard_prop < 0.0f) || (opts.random_guard_prop >= 1.0f)) {
				PRERR("invalid random guard proportion; "
								"setting to default value (%4.2f)", DEFAULT_RAND_GUARD_PROP);
				opts.random_guard_prop = DEFAULT_RAND_GUARD_PROP;
		}
}

void debugPrintOptions() {
		PRINT("DEBUG OUTPUT:");
		PRINT("entropy bits = %d", BIBOP_ENTROPY_BITS);
		PRINT("cache size = %d", BIBOP_CACHE_SIZE);
		PRINT("half cache size = %d", BIBOP_HALF_CACHE_SIZE);
		PRINT("over prov buffer size = %d", OVER_PROV_OBJ_BUF_SZ);
		PRINT("over prov num dead objects = %d", NUM_DEAD_OBJS);
		PRINT("over prov numerator = %d", opts.over_prov_numerator);
		PRINT("over prov denominator = %d", opts.over_prov_denominator);
		PRINT("rand guard page proportion = %0.2f", opts.random_guard_prop);
}

void heapinitialize() {
	if(heapInitStatus == E_HEAP_INIT_NOT) {
		heapInitStatus = E_HEAP_INIT_WORKING;
		parseEnvOpts();
		#ifndef NDEBUG
		debugPrintOptions();
		#endif
    SRAND(time(NULL));
		BibopHeap::getInstance().initialize();
		heapInitStatus = E_HEAP_INIT_DONE;
		// The following function will invoke dlopen and will call malloc in the end.
		// Thus, it is putted in the end so that it won't fail
		Real::initializer();
		xthread::getInstance().initialize();
		BigHeap::getInstance().initBigHeap();
	} else {
			while(heapInitStatus != E_HEAP_INIT_DONE);
	}
}

 void * xxmalloc(size_t size) {
    if(heapInitStatus != E_HEAP_INIT_DONE) {
			heapinitialize();
    }

		// Calculate the proper bag size needed to fulfill this request
		if(IF_CANARY_CONDITION) {
			numLargeObjects++;
			return BigHeap::getInstance().allocateAtBigHeap(size);
		} else {
			return BibopHeap::getInstance().allocateSmallObject(size);
		}

		return NULL;
}

 void xxfree(void * ptr) {
		if(ptr == NULL || heapInitStatus != E_HEAP_INIT_DONE) {
			return;
		}

    if(BibopHeap::getInstance().isSmallObject(ptr)) {
        BibopHeap::getInstance().freeSmallObject(ptr);
    } else if(BigHeap::getInstance().isLargeObject(ptr)) {
        BigHeap::getInstance().deallocateToBigHeap(ptr);
    } else {
        PRERR("invalid free on address %p", ptr);
    }
}

void * xxcalloc(size_t nelem, size_t elsize) {
	void * ptr = NULL;
	ptr = malloc(nelem * elsize);
	if(ptr != NULL) {
		memset(ptr, 0, nelem * elsize);
	}
	return ptr;
}

void * xxrealloc(void * ptr, size_t sz) {
		// We can't really support this library call when the allocator
		// is uninitialized; this is because there is no way for us to
		// determine the actual size of an object given only its
		// starting address using the temporary allocator.
    if(heapInitStatus != E_HEAP_INIT_DONE) {
        heapinitialize();
    }

		// If the pointer is null, call is equivalent to malloc(sz).
		if(ptr == NULL) {
				return xxmalloc(sz);
		}

		// If the pointer is non-null and size is zero, call is equivalent
		// to free(ptr).
		if(sz == 0) {
				xxfree(ptr);
				return NULL;
		}

		// If the object is unknown to us, return NULL to indicate error.
		size_t oldSize = -1;
    if(BibopHeap::getInstance().isSmallObject(ptr)) {
        oldSize = BibopHeap::getInstance().getObjectSize(ptr);
    } else if(BigHeap::getInstance().isLargeObject(ptr)) {
        oldSize = BigHeap::getInstance().getObjectSize(ptr);
    }

		if(oldSize == -1) {
				PRERR("realloc called with unknown object");
				return NULL;
		}

		// If the requested new size is less than
		// or equal to the old size, simply return the object as-is.
		if(oldSize >= sz) {
				return ptr;
		}

		void * newObject = xxmalloc(sz);
		memcpy(newObject, ptr, oldSize);
		xxfree(ptr);
		return newObject;
}


void * xxalloca(size_t size) {
    PRERR("%s CALLED", __FUNCTION__);
    return NULL;
}

void * xxvalloc(size_t size) {
    PRERR("%s CALLED", __FUNCTION__);
    return NULL;
}

int xxposix_memalign(void **memptr, size_t alignment, size_t size) {
		void * alignedObject = xxmemalign(alignment, size);
		*memptr = alignedObject;
		return 0;
}

void * xxaligned_alloc(size_t alignment, size_t size) {
    PRERR("%s CALLED", __FUNCTION__);
    return NULL;
}

void * xxmemalign(size_t alignment, size_t size) {
		if(size == 0) {
			return NULL;
		}

		// Calculate the proper bag size needed to fulfill this request
		if(size > LARGE_OBJECT_THRESHOLD) {
			numLargeObjects++;
			return BigHeap::getInstance().allocateAlignedAtBigHeap(alignment, size);
		} else {
			size_t allocObjectSize = alignment + size;
			uintptr_t object = (uintptr_t)BibopHeap::getInstance().allocateSmallObject(allocObjectSize);
			unsigned long residualBytes = alignment - (object % alignment);
			void * alignedObject = (void *)(object + residualBytes);
			PRDBG("memalign: original object @ 0x%lx, residual bytes=%lu, aligned object @ %p",
							object, residualBytes, alignedObject);
			return alignedObject;
		}

		return NULL;
}

void * xxpvalloc(size_t size) {
    PRERR("%s CALLED", __FUNCTION__);
    return NULL;
}

// Intercept thread creation
int pthread_create(pthread_t * tid, const pthread_attr_t * attr,
    void *(*start_routine)(void *), void * arg) {
	if(heapInitStatus != E_HEAP_INIT_DONE) {
			heapinitialize();
	}
  return xthread::getInstance().thread_create(tid, attr, start_routine, arg);
}
int pthread_join(pthread_t tid, void** retval) {
	return xthread::getInstance().thread_join(tid, retval);
}
