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
 * @file   bibopheap.hh: main BIBOP heap implementation.
 * @author Tongping Liu <http://www.cs.utsa.edu/~tongpingliu/>
 * @author Sam Silvestro <sam.silvestro@utsa.edu>
 */
#ifndef __BIBOPHEAP_H__
#define __BIBOPHEAP_H__

#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include "xdefines.hh"
#include "mm.hh"
#include "log.hh"
#include "errmsg.hh"

#ifdef SSE2RNG
#include "sse2rng.h"
#elif ARC4RNG
extern "C" uint32_t arc4random_uniform(uint32_t upper_bound);
#endif

struct guarder_opts opts;

class BibopHeap {
private:
	static unsigned _cacheSize;
	static unsigned _overProvObjBufSize;

	// Boundaries of the heap area
	char * _heapBegin;
	char * _heapEnd;

	// Boundaries of the shadow memory region
	char * _shadowMemBegin;
	char * _shadowMemEnd;

	// Boundaries of the free object cache region
	char * _freeAreaBegin;
	char * _freeAreaEnd;
	unsigned _numUsableBags;
	unsigned _lastUsableBag;

	static size_t _bibopBagSize;
	unsigned _threadShiftBits;

	static unsigned long _bagShiftBits;
	static unsigned long _bagMask;
	unsigned long _numBagsPerSubHeapMask;
	unsigned _shadowObjectInfoSizeShiftBits;
	

	class PerThreadMap {
		private:
			unsigned char classSizeToBag[LOG2(MAX_RANDOM_BAG_SIZE) + 1];	// "+1" to create
																																		// indices of
																																		// [0, max-power]
			unsigned char bagToClassSize[BIBOP_NUM_BAGS];

		public:

			void initialize(unsigned classSizePowerMax) {
					int i;

					// Initialize the classSize-to-bag mapping with sorted powers-of-two
					unsigned minClassSizePower = LOG2(BIBOP_MIN_BLOCK_SIZE);
					unsigned numClassSizePowers = BIBOP_NUM_BAGS + minClassSizePower - 1;
					classSizeToBag[minClassSizePower] = 0;
					for(i = minClassSizePower + 1; i <= numClassSizePowers; i++) {
							classSizeToBag[i] = classSizeToBag[i - 1] + 1;
					}

					// Shuffle the contents of the classSize-to-bag mapping,
					// which will randomize the bag ordering for the subheap
					for(i = numClassSizePowers; i >= minClassSizePower; i--) {
							unsigned j = getRandomNumber() % ((i - minClassSizePower) + 1);
							unsigned temp = classSizeToBag[i];
							classSizeToBag[i] = classSizeToBag[j + minClassSizePower];
							classSizeToBag[j + minClassSizePower] = temp;
					}
					for(i = 0; i < minClassSizePower; i++) {
							classSizeToBag[i] = classSizeToBag[minClassSizePower];
					}

					// Initialize the bag-to-classSize mapping
					for(i = minClassSizePower; i <= numClassSizePowers; i++) {
							bagToClassSize[classSizeToBag[i]] = i;
					}

					static bool isFirstThread = true;
					if(isFirstThread) {
							// DEBUG OUTPUT
							for(i = 0; i <= numClassSizePowers; i++) {
									PRDBG("classSizeToBag[%u] = %u", i, classSizeToBag[i]);
							}
							for(i = 0; i < BIBOP_NUM_BAGS; i++) {
									PRDBG("bagToClassSize[%u] = %u", i, bagToClassSize[i]);
							}
							PRDBG("num bags=%d, num class size powers = %d", BIBOP_NUM_BAGS, numClassSizePowers);
							PRDBG("&classSizeToBag = %p, &bagToClassSize = %p", classSizeToBag, bagToClassSize);
							isFirstThread = false;
					}
			}

			unsigned getClassSize(unsigned bagNum) {
					return bagToClassSize[bagNum];
			}

			unsigned getBagNum(unsigned classSizePower) {
					return classSizeToBag[classSizePower];
			}
	};

	class ObjectSource {
			public:
					virtual void * getNext() = 0;
	};

	class BibopGlobalFreeCache;

	class alignas(CACHE_LINE_SIZE) BibopFreeCache : public ObjectSource {
			private:
					uintptr_t _startaddr;
					uintptr_t _endaddr;

					// _head is defined as the next usable object; _tail
					// is defined as the first unavailable object.
					uintptr_t _head, _tail;
					unsigned long _capacity;
					BibopGlobalFreeCache * _myGlobalFreeCache;

			protected:
					unsigned long _numFreeObjects;

			public:
					void initialize(uintptr_t startaddr, unsigned long capacity, BibopGlobalFreeCache * globalFreeCache) {
							_startaddr = startaddr;
							_endaddr = _startaddr + (capacity << PTR_SIZE_SHIFT_BITS);
							_head = _startaddr;
							_tail = _head;
							_capacity = capacity;
							_numFreeObjects = 0;
							_myGlobalFreeCache = globalFreeCache;
					}

					unsigned long getNumObjects() {
							#ifdef USE_GLOBAL_FREE_CACHE
							if(_myGlobalFreeCache) {
									return _numFreeObjects + _myGlobalFreeCache->getNumObjects();
							} else {
									return _numFreeObjects;
							}
							#else
							return _numFreeObjects;
							#endif
					}

					// Attempts to refill up to half the local buffer with global objects
					int repopulate() {
							unsigned long halfCapacity = _capacity >> 1;
							_myGlobalFreeCache->acquireLock();
							unsigned numGlobalFreeObjects = _myGlobalFreeCache->getNumObjects();
							unsigned numObjectsToTransfer = (numGlobalFreeObjects <= halfCapacity) ? numGlobalFreeObjects : halfCapacity;
							int i;

							for(i = 0; i < numObjectsToTransfer; i++) {
									add(_myGlobalFreeCache->getNext());
							}
							_myGlobalFreeCache->releaseLock();
							if(i > 0) {
									PRDBG("received %d objects from global cache (numObjectsToTransfer=%u, "
													"numGlobalFreeObjects=%u)", i, numObjectsToTransfer, numGlobalFreeObjects);
							}

							return i;
					}

					inline void * getNext() {
							if(_numFreeObjects == 0) {
									#ifdef USE_GLOBAL_FREE_CACHE
									// Repopulate from the global free cache, if possible
									if(_myGlobalFreeCache) {
											if(repopulate() == 0) {
													return NULL;
											}
									} else {
											return NULL;
									}
									#else
									return NULL;
									#endif
							}

							void ** oldTail = (void **)_tail;

							_tail += POINTER_SIZE;
							if(_tail == _endaddr) {
									// do wrap-around on _tail
									_tail = _startaddr;
							}

							_numFreeObjects--;
							if(_head == _tail) {
									PRDBG("free cache is now empty");
							}

							PRDBG("freeCache->getNext(): retval=%p, this=%p, _numFreeObjects=%lu, _capacity=%lu, _start=0x%lx, _end=0x%lx",
											*oldTail, this, _numFreeObjects, _capacity, _startaddr, _endaddr);
							return *oldTail;
					}

					inline bool add(void * addr) {
							// Check if this buffer has reached full capacity...
							if(_numFreeObjects == _capacity) {
									#ifdef USE_GLOBAL_FREE_CACHE
									// Attempt to donate up to half of the
									// local buffer's items to the global buffer
									if(_myGlobalFreeCache) {
											int i;

											_myGlobalFreeCache->acquireLock();
											for(i = 0; i < (_capacity >> 1); i++) {
													if(!_myGlobalFreeCache->add(getNext())) {
															break;
													}
											}
											_myGlobalFreeCache->releaseLock();
											PRDBG("donated %d objects to global cache", i);
											// If i==0, the global free cache is also at full capacity
											if(i == 0) {
													FATAL("global and local free cache out of capacity");
											}
									} else {
											// If we are a global buffer and we're full,
											// simply return false back to the caller
											return false;
									}
									#else
									// If the global free cache is not in use and the local
									// buffer is full, print an error and return false
									PRERR("local free cache out of capacity: dropping object %p", addr);
									return false;
									#endif
							}

							*(void **)_head = addr;
							_head += POINTER_SIZE;
							if(_head == _endaddr) {
									// do wrap-around on _head
									_head = _startaddr;
							}

							_numFreeObjects++;

							/*
							// DEBUG: internal consistency check
							long count = (_endaddr - _startaddr) / sizeof(void *);
							if(_head > _tail) {
									count = (_head - _tail) / sizeof(void *);
							} else if(_head < _tail) {
									count = ((_endaddr - _tail) + (_head - _startaddr)) / sizeof(void *);
							}
							PRDBG("freeCache->add(%p): this=%p, _numFreeObjects=%lu, count=%ld, _capacity=%lu, _start=0x%lx, _end=0x%lx",
											addr, this, _numFreeObjects, count, _capacity, _startaddr, _endaddr);
							if(_numFreeObjects != count) {
									FATAL("freeCache->add(%p): this=%p, _numFreeObjects=%lu, count=%ld, _capacity=%lu, _start=0x%lx, _end=0x%lx",
													addr, this,  _numFreeObjects, count, _capacity, _startaddr, _endaddr);
							}
							*/

							if(_head == _tail) {
									PRDBG("free cache is now full");
									if(_numFreeObjects != _capacity) {
											PRERR("_numFreeObjects = %lu, _capacity = %lu", _numFreeObjects, _capacity);
									}
									assert(_numFreeObjects == _capacity);
							}

							return true;
					}
	};


	class alignas(CACHE_LINE_SIZE) BibopGlobalFreeCache : public BibopFreeCache {
			private:
					pthread_spinlock_t _spin_lock;

					inline void spin_lock() {
							pthread_spin_lock(&_spin_lock);
					}

					inline void spin_unlock() {
							pthread_spin_unlock(&_spin_lock);
					}


			public:
					void initialize(uintptr_t startaddr, unsigned long capacity) {
							pthread_spin_init(&_spin_lock, PTHREAD_PROCESS_PRIVATE);
							BibopFreeCache::initialize(startaddr, capacity, NULL);
					}

					void acquireLock() {
							spin_lock();
					}

					void releaseLock() {
							spin_unlock();
					}

					unsigned long getNumObjects() {
							return _numFreeObjects;
					}
	};


	class alignas(CACHE_LINE_SIZE) BibopObjCache : private ObjectSource {
		private:
			BibopFreeCache * _freeCache;
			size_t _classSize;
			uintptr_t _bagEnd;
			uintptr_t _heapTop;
			unsigned _nextUp;
			unsigned _numUsedObjects;
			unsigned _shiftBits;
			unsigned _regionCounters[NUM_CACHE_REGIONS];
			void ** _objects;
			uintptr_t * _nextObjs;


		public:
			void initialize(uintptr_t ustartaddr, uintptr_t uendaddr, uintptr_t * objectCache,
							BibopFreeCache * freeCache, unsigned shiftBits) {
					unsigned i;

          // Initialize each of the cache region object
          // counters to indicate an uninitialized object cache
          for(i = 0; i < NUM_CACHE_REGIONS; i++) {
              _regionCounters[i] = UNINITIALIZED_CACHE_REGION;
          }

					// Force the over-provisioning to choose a fresh set of objects
					_nextUp = BibopHeap::_overProvObjBufSize;

					_shiftBits = shiftBits;
					_classSize = (size_t)(1U << _shiftBits);

					// Check whether the current bag size can support the current
					// entropy setting (e.g., if any bag has fewer objects than
					// needed to fill its object cache or over-provisioning buffer,
					// then we cannot support the current entropy setting).
					unsigned numObjectsInBag = _bibopBagSize / _classSize;
					bool overProvFail = (numObjectsInBag < BibopHeap::_overProvObjBufSize);
					bool entropyFail = (numObjectsInBag < BibopHeap::_cacheSize);
					if(overProvFail) {
							PRERR("cannot support the given over-provisioning factor:");
							PRERR("           class size = %zu", _classSize);
							PRERR("   num objects in bag = %u", numObjectsInBag);
							PRERR("   over prov buf size = %u", BibopHeap::_overProvObjBufSize);
					}
					if(entropyFail) {
							PRERR("cannot support the given allocator entropy:");
							PRERR("           class size = %zu", _classSize);
							PRERR("   num objects in bag = %u", numObjectsInBag);
							PRERR("       obj cache size = %u", BibopHeap::_cacheSize);
					}
					if(overProvFail || entropyFail) { exit(EXIT_FAILURE); }

					_freeCache = freeCache;
					_numUsedObjects = 0;
					_heapTop = ustartaddr;		// next available object
					_bagEnd = uendaddr;				// last available object
					_objects = (void **)objectCache;
					_nextObjs = objectCache + BibopHeap::_cacheSize;
			}

			inline unsigned getClassSize() {
					return _classSize;
			}

			void * malloc() {
					// TODO: change how this repopulation threshold is calculated
					// Ex: cache size = 256, half cache size = 128, bag size = 32MB (yes, very small);
					// only 64 objects exist in each 512KB class; thus, we would never reach the cache
					// allowance of used objects until something bad has happened (segfault, doubly-
					// allocated objects, etc.)   -- SAS
					if(_numUsedObjects > BIBOP_HALF_CACHE_SIZE) {
							// Pull in free objects from the free cache
							//PRDBG("out of objects in the cache; need to repopulate from free cache");
							repopulate();
					}

					//#warning doReplacement turned off
					//bool doReplacement = false;
					bool doReplacement = true;
					uintptr_t object = getRandomObject(doReplacement);

    			#ifdef USE_CANARY
					// We must install the canary prior to marking the object as in-use,
					// otherwise another thread performing neighbor checking could
					// identify the object as in-use, but will raise a false alarm
					// due to the missing canary value.
					char * canary = (char *)object + _classSize - 1;
					*canary = CANARY_SENTINEL;
    			#endif

					// Mark the object as in-use in the shadow memory
					if(!markObjectUsed(object)) {
							FATAL("object 0x%lx already set as in-use", object);
					}

					PRDBG("...returning object 0x%lx", object);
					return (void *)object;
			}


		private:
			void initialPopulate() {
					unsigned i;

					// Initialize each of the cache region object
					// counters to indicate a full buffer
					for(i = 0; i < NUM_CACHE_REGIONS; i++) {
							_regionCounters[i] = CACHE_REGION_SIZE;
					}

					// Initialize the cache with new objects from top of current subheap
					for(i = 0; i < BibopHeap::_cacheSize; i++) {
							_objects[i] = getNext();

							assert(_objects[i] != NULL);
					}

					// If we decide to place the object cache in mmap'd memory rather than
					// global memory we MUST ensure that unused entries are initialized to
					// zero
					for(i = BibopHeap::_cacheSize; i < BibopHeap::_cacheSize; i++) {
							_objects[i] = NULL;
					}
			}

			void * getNext() {
					if(_heapTop >= _bagEnd) {
							FATAL("heap out of memory (bag size = %lu)", _bibopBagSize);
					}

					uintptr_t foundNextObject = 0;
					do {
							// Repopulate the over provisioning buffer, if necessary...
							if(_nextUp >= BibopHeap::_overProvObjBufSize) {
									int i;
									for(i = 0; i < BibopHeap::_overProvObjBufSize; i++) {
											#ifdef RANDOM_GUARD
											if((_heapTop & PageMask) == 0) {
													tryRandomGuardPage(&_heapTop);
											}
											#endif

											// Use the top-of-bag pointer to satisfy this request
											_nextObjs[i] = _heapTop;
											// Bump the top-of-bag pointer to point to next object
											_heapTop += _classSize;
									}
									// Now kill a portion of these objects in accordance with
									// the over-provisioning ratio
									for(i = 0; i < NUM_DEAD_OBJS; i++) {
											unsigned randIndex = getRandomNumber() % BibopHeap::_overProvObjBufSize;

											// Perform a forward sequential search if the
											// object we selected for sacrifice is already dead
											while(_nextObjs[randIndex] == 0) {
													randIndex = (randIndex + 1) % BibopHeap::_overProvObjBufSize;
											}
											_nextObjs[randIndex] = 0;		// Mark selected index as a dead object
									}
									_nextUp = 0;
							}

							// Try the next object in the over-provisioning buffer...
							foundNextObject = _nextObjs[_nextUp++];
					} while(foundNextObject == 0);
					//PRDBG("\theap top returning object @ 0x%lx", foundNextObject);
		
					return (void *)foundNextObject;
			}

			// Tries to place a random guard page at the current location pointed
			// to by the specified top-of-heap pointer.
			bool tryRandomGuardPage(uintptr_t * position) {
					void * savedPosition = (void *)*position;

					if(getRandomNumber() < RANDOM_GUARD_RAND_CUTOFF) {
							size_t guardSize;
							if(_classSize < PageSize) {
									guardSize = PageSize;
									unsigned numObjectsPerPage = PageSize / _classSize;
									// For the purposes of the caller (allocateSmallObject()), we want
									// it to assume we are operating on the last object of this page;
									// thus, we should increment the bump pointer by the number of
									// objects that make up a page, minus one.
									*position += numObjectsPerPage * _classSize; 
							} else {
									guardSize = _classSize;
									*position += _classSize; 
							}
							mprotect(savedPosition, guardSize, PROT_NONE);

							//uintptr_t endPosition = (uintptr_t)savedPosition + guardSize;
							//PRDBG("placing random guard page at %p~0x%lx, size=%zu", savedPosition, endPosition, guardSize);
							/*
							// This version checks the return value of the mprotect call
							if(mprotect(savedPosition, guardSize, PROT_NONE) == -1) {
									PRERR("mprotect(%p, %zu, PROT_NONE) failed: %s", savedPosition, guardSize, strerror(errno));
							}
							*/

							return true;
					}
					return false;
			}

			void repopulate() {
					// Perform an O(n) repopulation of this object cache using
					// freed objects located in the freeCache
					// If there are not enough objects in freeCache to fully perform
					// the repopulation, we should shift to using new objects from the
					// top of the heap (pointed to by _heapTop)

					PRDBG("*** beginning repopulation ***");

					ObjectSource * objSource;
					if(_freeCache->getNumObjects() > 0) {
							PRDBG("\tusing free cache as object source");
							objSource = _freeCache;
					} else {
							PRDBG("\tusing heap top as object source");
							objSource = this;
					}

					unsigned position = 0;
					#warning allocation buffer refill level set to 75%
					// Fills the cache back up to 75% available (25% used)
					unsigned refill_level = BIBOP_CACHE_SIZE >> 2;
					while(_numUsedObjects > refill_level) {
							if(_objects[position] == NULL) {
									//if((_objects[position] = objSource->getNext()) == NULL) {
									void * popObject = objSource->getNext();
									PRDBG("\t\tfree object %p -> _objects[%d] (cache entry %p, obj src = %p)",
											popObject, position, &_objects[position], objSource);
									// Write the next object from the free cache into this position.
									// If the free cache returned NULL then it is out of objects.
									if((_objects[position] = popObject) == NULL) {
											PRDBG("\t*** switching back to heap top as object source");
											objSource = this;
											// We do not increment position in this case because we want
											// the loop to attempt to fill this position again, but using
											// the heap as the object source instead of the free cache.
									} else {
											// Our object source returned a valid object -- decrement the
											// number of used objects, and increment the array position
											// to proceed with the next item
											//unsigned currentRegion = position & NUM_CACHE_REGIONS_MASK;
											unsigned currentRegion = position >> CACHE_REGION_SIZE_SHIFT_BITS;
											PRDBG("_regionCounters[%d]++ (index = %d)", currentRegion, position);
											_regionCounters[currentRegion]++;
											_numUsedObjects--;
											position++;
									}
							} else {
									// If the object at this position is alive,
									// simply move to the next object...
									position++;
							}
					}
			}

			uintptr_t getRandomObject(bool doReplacement = false) {
					unsigned index;
					//unsigned numTries = 1;
					void * object;

					// Obtain a random number between [0, opts.bibop_cache_size)
					index = getRandomNumber() & BIBOP_CACHE_SIZE_MASK;
					object = _objects[index];

					PRDBG("trying object %p at index %d...", object, index);
					// Find the next sequential cache region with objects available for use
					if(!object) {
							int i;
							unsigned cacheRegionNumber = index >> CACHE_REGION_SIZE_SHIFT_BITS;
							unsigned tryRegionNumber;

							PRDBG(" ... didn't work, current region = %d, searching regions...", cacheRegionNumber);
							for(i = cacheRegionNumber; i < cacheRegionNumber + NUM_CACHE_REGIONS; i++) {
									tryRegionNumber = i & NUM_CACHE_REGIONS_MASK;
									//numTries++;
									if(_regionCounters[tryRegionNumber] == UNINITIALIZED_CACHE_REGION) {
											initialPopulate();
											break;
									} else if(_regionCounters[tryRegionNumber] > 0) {
											PRDBG(" ... using region = %d, has %d objects", tryRegionNumber, _regionCounters[tryRegionNumber]);
											break;
									} else {
											PRDBG(" ... region %d has no objects, moving on...", tryRegionNumber);
									}
							}

							// Attempt to use a "random" object from this region
							// (add +1 to index in order to avoid rehecking the same object if the
							// same cache region is chosen by the for-loop above).
							index = (tryRegionNumber << CACHE_REGION_SIZE_SHIFT_BITS) + ((index + 1) & CACHE_REGION_SIZE_MASK);
							object = _objects[index];
							PRDBG("	...trying first object (%p) in region %d, has index %d...", object, tryRegionNumber, index);

							// Now walk through the region's objects to find an available one
							// (that is, if the first object is unavailable)...
							//numTries++;
							while(!object) {
									PRDBG("cache conflict on index %u (object = %p, num used=%d); trying next item...",
													index, object, _numUsedObjects);

									// Try the next adjacent index, wrapping around if necessary...
									index++;
									if((index & CACHE_REGION_SIZE_MASK) == 0) {
											index = tryRegionNumber << CACHE_REGION_SIZE_SHIFT_BITS;
									}

									object = _objects[index];
									//numTries++;
							}
					}
					unsigned currentRegion = index >> CACHE_REGION_SIZE_SHIFT_BITS;
					//PRINT("numTries %u numAvailObjs %u curRegion %d regionObjects %d",
					//				numTries, (BibopHeap::_cacheSize - _numUsedObjects), currentRegion, _regionCounters[currentRegion]);

					// If desired, we will replace the randomly selected object with a
					// fresh object from the free cache, if one is available to use.
					if(doReplacement && (_freeCache->getNumObjects() > 0)) {
							PRDBG("freecache has free objects, doing replacement of cache index %u", index);
							_objects[index] = _freeCache->getNext();
					} else {
							// mark the object as NULL in _objects array to indicate
							// it is no longer available
							PRDBG("writing NULL to used cache index: cache @ %p, entry @ %p equals %p; index=%u",
											_objects, &_objects[index], _objects[index], index);
							_objects[index] = NULL;
							_numUsedObjects++;
							
							PRDBG("_regionCounters[%d]-- (index = %d)", currentRegion, index);
							_regionCounters[currentRegion]--;
							assert(_regionCounters[currentRegion] >= 0);
					}

					PRDBG("getRandomObject() returning %p", object);
					return (uintptr_t)object;
			}

			bool markObjectUsed(uintptr_t object) {
					shadowObjectInfo * shadowMemAddr = BibopHeap::getInstance().getShadowObjectInfo((void *)object);
					shadowObjectInfo oldSmValue = *shadowMemAddr;
					*shadowMemAddr = ALLOC_SENTINEL;

					return (oldSmValue == FREE_SENTINEL);
			}
	};


	class alignas(CACHE_LINE_SIZE) PerThreadBag {
		public:
			BibopObjCache * cache;
			BibopFreeCache * freeCache;

			unsigned lastObjectIndex;		// currently populated but never used
			unsigned bagNum;
			unsigned threadIndex; 
			size_t classSize;
			size_t classMask;
			unsigned shiftBits;
	
			// Starting offset of the current bag in the current heap
			size_t startOffset;
			uintptr_t startShadowMem;

			#ifdef ENABLE_GUARDPAGE
      size_t guardsize;
      size_t guardoffset;
			#endif
	};

	PerThreadMap _threadMap[MAX_ALIVE_THREADS];
	PerThreadBag _threadBag[MAX_ALIVE_THREADS][BIBOP_NUM_BAGS];
	BibopObjCache _bagCache[MAX_ALIVE_THREADS][BIBOP_NUM_BAGS];
	BibopFreeCache _freeCache[MAX_ALIVE_THREADS][BIBOP_NUM_BAGS];
	BibopGlobalFreeCache _globalFreeCache[BIBOP_NUM_BAGS + LOG2(BIBOP_MIN_BLOCK_SIZE)];

public:
	static BibopHeap & getInstance() {
      static char buf[sizeof(BibopHeap)];
      static BibopHeap* theOneTrueObject = new (buf) BibopHeap();
      return *theOneTrueObject;
  }

	void * getHeapBegin() {
			return _heapBegin;
	}

	void * initialize() {
		unsigned threadNum, bagNum;
		size_t lastUsableBagSize;

		BibopHeap::_cacheSize = BIBOP_CACHE_SIZE;
		BibopHeap::_overProvObjBufSize = OVER_PROV_OBJ_BUF_SZ;

		#ifdef BIBOP_BAG_SIZE
		#warning BIBOP_BAG_SIZE in use: overrides randomized bag size
		_bibopBagSize = BIBOP_BAG_SIZE;
		#else		// randomized bag size
		unsigned randPower = getRandomNumber() % (LOG2(MAX_RANDOM_BAG_SIZE / MIN_RANDOM_BAG_SIZE) + 1);
		_bibopBagSize = MIN_RANDOM_BAG_SIZE << randPower;
		#endif

		if(_bibopBagSize > LARGE_OBJECT_THRESHOLD) {
				lastUsableBagSize = LARGE_OBJECT_THRESHOLD;
		} else {
				lastUsableBagSize = _bibopBagSize;
		}
		_numUsableBags = LOG2(lastUsableBagSize) - LOG2(BIBOP_MIN_BLOCK_SIZE) + 1;
		if(_numUsableBags > BIBOP_NUM_BAGS) {
				_numUsableBags = BIBOP_NUM_BAGS;
		}
		_lastUsableBag = _numUsableBags - 1;

		assert(BIBOP_HEAP_SIZE > 0);

		BibopHeap::_bagShiftBits = LOG2(_bibopBagSize);
		_threadShiftBits = LOG2((_bibopBagSize * BIBOP_NUM_BAGS));
		BibopHeap::_bagMask = _bibopBagSize - 1;

		PRINF("_bibopBagSize=0x%lx, _bagShiftBits=%ld, sizeof(PerThreadBag)=%zu",
			_bibopBagSize, BibopHeap::_bagShiftBits, sizeof(PerThreadBag));
		PRINF("BIBOP_NUM_BAGS=%u, _numUsableBags=%u", BIBOP_NUM_BAGS, _numUsableBags);
		PRINF("sizeof(PerThreadBag)=%zu, sizeof(BibopObjCache)=%zu, sizeof(BibopFreeCache)=%zu",
				sizeof(PerThreadBag), sizeof(BibopObjCache), sizeof(BibopFreeCache));

		// Bag size cannot be smaller than the large object threshold.
		assert(_bibopBagSize >= LARGE_OBJECT_THRESHOLD);

		// Allocate the heap all at once.
		allocHeap(BIBOP_HEAP_SIZE);

    unsigned long numBagObjects;
    unsigned long numCumObjects = 0;
    size_t unusableHeapSpace = (BIBOP_NUM_BAGS - _numUsableBags) * _bibopBagSize;

    // Initialize each thread bag's free list, and other information
    for(threadNum = 0; threadNum < MAX_ALIVE_THREADS; threadNum++) {
      size_t classSize = BIBOP_MIN_BLOCK_SIZE;

      for(bagNum = 0; bagNum < _numUsableBags; bagNum++) {
        numBagObjects = _bibopBagSize / classSize;

        #ifdef ENABLE_GUARDPAGE
            // We must perform this >1 test or else we will underflow this value
            // for bags which have 0 objects in them. Also, the last usable bag
            // will only contain a single object, but it will not be reduced to
            // make room for a guard page, but rather the next bag (which is
            // unusable) will be converted entirely into a guard page. 
            if(numBagObjects > 1) {
                if(classSize < PageSize) {
                    numBagObjects -= (PageSize / classSize);
                } else {
                    numBagObjects--;
                }
            }
        #endif

        // Update the following values; 
        numCumObjects += numBagObjects;
        classSize <<= 1;
      }
    }

		_shadowObjectInfoSizeShiftBits = LOG2(sizeof(shadowObjectInfo));
    _numBagsPerSubHeapMask = BIBOP_NUM_BAGS - 1;
    size_t numObjectsInHeap = numCumObjects;

		//unsigned freeCacheDivisor = 1;		// no reduction to deallocation buffer size
		unsigned freeCacheDivisor = 16;
		unsigned long numFreeAreaObjects = numObjectsInHeap / freeCacheDivisor;

		allocShadowMem(numObjectsInHeap);
		allocFreeArea(numFreeAreaObjects);
		allocGlobalFreeCache(numObjectsInHeap);

		// Allocate memory for use by each bag's object cache
		size_t objectCacheSize = OVER_PROV_OBJ_BUF_SZ + BIBOP_CACHE_SIZE;
		size_t objectCacheAreaSize = sizeof(uintptr_t) * objectCacheSize * BIBOP_NUM_BAGS * MAX_ALIVE_THREADS;
		uintptr_t * objectCacheStart = (uintptr_t *)MM::mmapAllocatePrivate(objectCacheAreaSize);
		uintptr_t * currentObjectCachePos = objectCacheStart;

		uintptr_t _uHeapStart = (uintptr_t)_heapBegin;
		uintptr_t _uShadowMemStart = (uintptr_t)_shadowMemBegin;
		uintptr_t _uFreeAreaBegin = (uintptr_t)_freeAreaBegin;
		unsigned long offsetShadowMem = 0;
		unsigned long offsetFreeArea = 0;
    unsigned long offsetBag = 0;

		// Initialize each thread bag's free list, and other information
		for(threadNum = 0; threadNum < MAX_ALIVE_THREADS; threadNum++) {
			PerThreadMap& curMap = _threadMap[threadNum];
			curMap.initialize(_bagShiftBits);

			for(bagNum = 0; bagNum < _numUsableBags; bagNum++) {
				unsigned shiftBits = curMap.getClassSize(bagNum);
				size_t classSize = (1U << shiftBits);
				if(threadNum == 0)
						PRDBG("bag %d classSize = %zu, shiftBits = %u", bagNum, classSize, shiftBits);
				PerThreadBag * curBag = &_threadBag[threadNum][bagNum];
				
				curBag->cache = &_bagCache[threadNum][bagNum];
				curBag->freeCache = &_freeCache[threadNum][bagNum];
				curBag->classSize = classSize;
				curBag->classMask = classSize - 1;
				curBag->shiftBits = shiftBits;
				curBag->bagNum = bagNum;
				curBag->threadIndex = threadNum; 

				numBagObjects = _bibopBagSize / classSize;
				uintptr_t bagStart = _uHeapStart + offsetBag;
				uintptr_t bagEnd = bagStart + _bibopBagSize;
				uintptr_t bagShadowMemStart = _uShadowMemStart + offsetShadowMem;
				uintptr_t bagFreeAreaStart = _uFreeAreaBegin + offsetFreeArea;

				//PRDBG("thread %d bag %d: heap start @ 0x%lx, shadow mem @ 0x%lx, free cache @ 0x%lx, Cache=%p, FreeCache=%p",
				//				threadNum, bagNum, bagStart, bagShadowMemStart, bagFreeAreaStart, curBag->cache, curBag->freeCache);

				#ifdef ENABLE_GUARDPAGE
						size_t guardsize = classSize > PAGESIZE ? classSize : PAGESIZE;
						size_t guardoffset = guardsize;
						if(bagNum == _lastUsableBag) {
								// If this bag can only fit one object,
								// forego the use of a guard object at the end of the bag.
								if(_bibopBagSize == lastUsableBagSize) {
										guardoffset = 0;
										guardsize = 0;
								}
								// Add to the guard size the amount of unusable space left on the heap.
								guardsize += (BIBOP_NUM_BAGS - LOG2(lastUsableBagSize) + LOG2(BIBOP_MIN_BLOCK_SIZE) - 1) * _bibopBagSize;

								//PRDBG("last usable bag: lastUsableBagSize=%zu, _bibopBagSize=%zu, guardsize=%zu, guardoffset=%zu",
								//		lastUsableBagSize, _bibopBagSize, guardsize, guardoffset);
						}
						curBag->guardsize = guardsize;
						curBag->guardoffset = guardoffset;
				#else
						size_t guardoffset = 0;
				#endif

				#ifdef ENABLE_GUARDPAGE
						// We must perform this >1 test or else we will underflow this value
						// for bags which have 0 objects in them. Also, the last usable bag
						// will only contain a single object, but it will not be reduced to
						// make room for a guard page, but rather the next bag (which is
						// unusable) will be converted entirely into a guard page. 
						if(numBagObjects > 1) {
								if(classSize < PageSize) {
										numBagObjects -= (PageSize / classSize);
								} else {
										numBagObjects--;
								}
						}
				#endif

				unsigned long bagFreeCacheCapacity = numBagObjects / freeCacheDivisor;

				curBag->startShadowMem = bagShadowMemStart;
				curBag->cache->initialize(bagStart, bagEnd, currentObjectCachePos, curBag->freeCache, shiftBits);
				// In order to prevent false sharing, do not utilize a global
				// free buffer for size classes smaller than the cache line size
				if(classSize >= CACHE_LINE_SIZE) {
						curBag->freeCache->initialize(bagFreeAreaStart, bagFreeCacheCapacity, NULL);
				} else {
						curBag->freeCache->initialize(bagFreeAreaStart, bagFreeCacheCapacity, &_globalFreeCache[shiftBits]);
				}

				currentObjectCachePos += objectCacheSize;

				curBag->startOffset = offsetBag;
				curBag->lastObjectIndex = numBagObjects - 1;

				// Update loop variables
				offsetBag += _bibopBagSize;
				offsetShadowMem += numBagObjects;
				offsetFreeArea += bagFreeCacheCapacity * sizeof(uintptr_t);
				}
			offsetBag += unusableHeapSpace;
		}

		#ifndef NDEBUG
		// DEBUG
		uintptr_t _uFreeAreaEnd = _uFreeAreaBegin + (numFreeAreaObjects * sizeof(uintptr_t));
		assert((_uFreeAreaBegin + offsetFreeArea) <= _uFreeAreaEnd);
		#endif

		_numBagsPerSubHeapMask = BIBOP_NUM_BAGS - 1;

		PRINF("_heapBegin=%p, _heapEnd=%p", _heapBegin, _heapEnd);
		PRINF("_shadowMemBegin=%p, _shadowMemEnd=%p, _freeAreaBegin=%p, _freeAreaEnd=%p",
						_shadowMemBegin, _shadowMemEnd, _freeAreaBegin, _freeAreaEnd);

		return _heapBegin;
	}

	void allocHeap(size_t heapSize) {
			_heapBegin = (char *)MM::mmapAllocatePrivate(heapSize);
			_heapEnd = _heapBegin + heapSize;
			madvise(_heapBegin, heapSize, MADV_NOHUGEPAGE);
	}

	void allocShadowMem(size_t numObjectsInHeap) {
			// Use one byte for each heap object
      size_t totalShadowMemSize = numObjectsInHeap;
      _shadowMemBegin = (char *)MM::mmapAllocatePrivate(totalShadowMemSize);
      _shadowMemEnd = _shadowMemBegin + totalShadowMemSize;
			madvise(_shadowMemBegin, totalShadowMemSize, MADV_NOHUGEPAGE);
	}

	void allocFreeArea(size_t numObjectsInHeap) {
			// Use eight bytes for each heap object
      size_t totalFreeAreaSize = numObjectsInHeap * sizeof(void *);
      _freeAreaBegin = (char *)MM::mmapAllocatePrivate(totalFreeAreaSize);
      _freeAreaEnd = _freeAreaBegin + totalFreeAreaSize;
			madvise(_freeAreaBegin, totalFreeAreaSize, MADV_NOHUGEPAGE);
	}

	// Initializes the global free cache area
	void allocGlobalFreeCache(unsigned numObjectsInHeap) {
			unsigned minClassSizePower = LOG2(BIBOP_MIN_BLOCK_SIZE);
			unsigned numClassSizePowers = BIBOP_NUM_BAGS + minClassSizePower - 1;
			unsigned long approxNumObjectsInSubHeap = (_bibopBagSize / (BIBOP_MIN_BLOCK_SIZE >> 1)) -
					(_bibopBagSize / (1U << numClassSizePowers));
			unsigned shiftBits;

			size_t globalFreeCacheSize = approxNumObjectsInSubHeap * sizeof(uintptr_t);
			uintptr_t myFreeCacheStart = (uintptr_t)MM::mmapAllocatePrivate(globalFreeCacheSize);

      unsigned long numObjectsInClass = _bibopBagSize / BIBOP_MIN_BLOCK_SIZE;
			for(shiftBits = minClassSizePower; shiftBits <= numClassSizePowers; shiftBits++) {
					_globalFreeCache[shiftBits].initialize(myFreeCacheStart, numObjectsInClass);
					myFreeCacheStart += (numObjectsInClass * POINTER_SIZE);
					numObjectsInClass >>= 1;
			}
	}

  size_t getObjectSize(void * addr) {
    void * objectStartAddr;
    PerThreadBag * bag;
    (void)getShadowObjectInfo(addr, &bag, &objectStartAddr);

    size_t classSize = bag->classSize;

    if(objectStartAddr != addr) {
        ptrdiff_t offset = (uintptr_t)addr - (uintptr_t)objectStartAddr;
        classSize -= offset;
    }

    #ifdef USE_CANARY
    return (classSize - 1);
    #else
    return classSize;
    #endif
  }

	// The major routine of allocate a small object 
	void * allocateSmallObject(size_t sz) {
		//PRDBG("allocateSmallObject(%zu)", sz);

		#ifdef CUSTOMIZED_STACK
		int threadIndex = getThreadIndex(&sz);
		#else
		int threadIndex = getThreadIndex();
		#endif

    #ifdef USE_CANARY
    sz++;   // make room for the buffer overflow canary
    #endif

		unsigned classSizePower;
    if(sz <= BIBOP_MIN_BLOCK_SIZE) {
      classSizePower = LOG2(BIBOP_MIN_BLOCK_SIZE);
    } else {
      classSizePower = N_64BITS - __builtin_clzl(sz - 1);
    }

		PerThreadMap& curMap = _threadMap[threadIndex]; 
		unsigned bagNum = curMap.getBagNum(classSizePower);
		BibopObjCache& curCache = _bagCache[threadIndex][bagNum]; 

		PRDBG("allocateSmallObject(%zu): threadIndex = %d, bagNum = %d, class size = %u",
						sz, threadIndex, bagNum, curCache.getClassSize());

		void * object = curCache.malloc();

		return object;
	}

	inline bool isObjectFree(shadowObjectInfo * shadowinfo) {
		return(*shadowinfo != ALLOC_SENTINEL);
	}

	inline void markObjectFree(shadowObjectInfo * shadowinfo) {
		*shadowinfo = FREE_SENTINEL;
	}

	void freeSmallObject(void * addr) {
		void * objectStartAddr;
		PerThreadBag * bag;
		#ifdef USE_CANARY
		PerThreadBag * ownerBag;
		shadowObjectInfo * shadowinfo = getShadowObjectInfo(addr, &bag, &objectStartAddr, &ownerBag);
		#else
		shadowObjectInfo * shadowinfo = getShadowObjectInfo(addr, &bag, &objectStartAddr);
		#endif

		BibopFreeCache * freeCache = bag->freeCache;

		PRDBG("\tfree(%p): smAddr %p (value=%d), threadIndex=%d, bagNum=%d, classSize=%zu, objectStart=%p",
						addr, shadowinfo, *shadowinfo, bag->threadIndex, bag->bagNum, bag->classSize, objectStartAddr);

		if(isObjectFree(shadowinfo)) {
			PRERR("Double free or invalid free problem found on object %p (sm %p)", addr, shadowinfo);
      printCallStack();
      exit(EXIT_FAILURE);
		} 

		#ifdef DESTROY_ON_FREE
		#ifdef USE_CANARY
		size_t objectSizeNoCanary = bag->classSize - 1;
		#else
		size_t objectSizeNoCanary = bag->classSize;
		#endif
		#endif

		#ifdef USE_CANARY
		char * canary = (char *)objectStartAddr + bag->classSize - 1;
		if(*canary != CANARY_SENTINEL) {
				FATAL("canary value for object %p not intact; canary @ %p, value=0x%x",
								addr, canary, (unsigned)*canary);
		}
		#if (NUM_MORE_CANARIES_TO_CHECK > 0)
		for(int move = LEFT; move <= RIGHT; move++) {
				shadowObjectInfo * canaryShadow = shadowinfo;
				for(int pos = 0; pos < NUM_MORE_CANARIES_TO_CHECK; pos++) {
						if((canaryShadow = getNextCanaryNeighbor(canaryShadow, ownerBag, (direction)move))) {
								char * neighborAddr = (char *)getAddrFromShadowInfo(canaryShadow, ownerBag);
								char * canary = neighborAddr + bag->classSize - 1;
								// We will only inspect the canary of objects currently in-use; if the
								// object is free, then it has already been checked previously.
								PRDBG("checking canary value for object %p (neighbor of %p); classSize=%zu, canary @ %p",
												neighborAddr, objectStartAddr, bag->classSize, canary);
								if(!isObjectFree(canaryShadow) && (*canary != CANARY_SENTINEL)) {
										FATAL("canary value for object %p (neighbor of %p) not intact; canary @ %p, value=0x%x",
														neighborAddr, objectStartAddr, canary, (unsigned)*canary);
								}
						} else {
								// getNextCanaryNeighbor will only return null when we attempt to move
								// left or right from the first or last object in a bag.
								break;
						}
				}
		}
		#endif
		#endif
		#ifdef DESTROY_ON_FREE
		destroyObject(objectStartAddr, objectSizeNoCanary);
		#endif

		markObjectFree(shadowinfo);

		//#warning madvise turned off
		if(bag->classSize >= 16 * PAGESIZE) {
				madvise(objectStartAddr, bag->classSize, MADV_DONTNEED);
		}

		freeCache->add(objectStartAddr);
	}

	bool isSmallObject(void * addr) {
		return ((char *)addr >= _heapBegin && (char *)addr <= _heapEnd);
	}


private:
	uintptr_t getBagShadowMemStart(unsigned threadNum, unsigned bagNum) {
			return _threadBag[threadNum][bagNum].startShadowMem;
	}

	#ifdef DESTROY_ON_FREE
	inline void destroyObject(void * addr, size_t classSize) {
			#warning destroy-on-free only applies to objects <= 2KB in size
				if(classSize <= TWO_KILOBYTES) {
						memset(addr, 0, classSize);
				}
	}
	#endif

	static inline int getRandomNumber() {
		int retVal;

    #ifdef SSE2RNG
    #warning using sse2rng routine rather than libc rand
    unsigned randNum[4];
    rand_sse(randNum);
		retVal = randNum[0];
    #elif ARC4RNG
    #warning using arc4rng routine rather than libc rand
    retVal = arc4random_uniform(RAND_MAX);
    #else
    #warning using libc random number generator
    retVal = rand();
    #endif

		return retVal;
	}

  inline shadowObjectInfo * getNextCanaryNeighbor(shadowObjectInfo * shadowinfo, PerThreadBag * bag, direction move) {
      ptrdiff_t shadowOffset = (uintptr_t)shadowinfo - bag->startShadowMem;
      unsigned long objectindex = shadowOffset >> _shadowObjectInfoSizeShiftBits;

      //PRDBG("getneighbor: t%3u/b%2u, sm %p, objectindex %lu, dir=%u",
      //  bag->threadIndex, bag->bagNum, shadowinfo, objectindex, move);

      if(move == LEFT) {
					// Check whether we are physically capable of moving to the left; if not, return null
          if(objectindex == 0) {
							return NULL;
          } else {
              shadowinfo--;
          }
      } else {
          // Check to see if we reached the index of the last object in this bag
          if(objectindex == bag->lastObjectIndex) {
							return NULL;
          } else {
              shadowinfo++;
          }
      }

      return shadowinfo;
  }

	inline char * getLastOfBag(char * start, size_t guardoffset, size_t classSize) {
			return start + _bibopBagSize - guardoffset - classSize;
	}

	inline shadowObjectInfo * getShadowObjectInfo(void * addr, PerThreadBag ** bag = NULL,
					void ** objectStart = NULL, PerThreadBag ** ownerBag = NULL) {
		unsigned long offset = (char *)addr - _heapBegin;
    unsigned long localBagOffset = offset & _bagMask;
		unsigned long globalBagNum = offset >> _bagShiftBits;
		unsigned long origOwnerTindex = offset >> _threadShiftBits;
		unsigned long origBagNum = globalBagNum & _numBagsPerSubHeapMask;

		PerThreadBag * origBag = &_threadBag[origOwnerTindex][origBagNum];

		if(bag) {
				unsigned objectSize = _threadMap[origOwnerTindex].getClassSize(origBagNum);
				unsigned currentThread = getThreadIndex(&currentThread);
				unsigned bagNum = _threadMap[currentThread].getBagNum(objectSize);
				*bag = &_threadBag[currentThread][bagNum];
		}

		if(ownerBag) {
				*ownerBag = origBag;
		}

		if(objectStart) {
				unsigned long objectStartOffset = localBagOffset & ~origBag->classMask;
				*objectStart = (void *)(_heapBegin + origBag->startOffset + objectStartOffset);
		}

		shadowObjectInfo * shadowinfo = (shadowObjectInfo *)(origBag->startShadowMem);

		shadowObjectInfo * retval = &shadowinfo[localBagOffset >> origBag->shiftBits];
		//PRDBG("getShadowObjectInfo(%p) == smAddr %p, local bag offset = 0x%lx, shift bits = %zu",
		//				addr, retval, localBagOffset, origBag->shiftBits);
		return retval;
	}

  inline void * getAddrFromShadowInfo(shadowObjectInfo * shadowaddr, PerThreadBag * bag, bool debug = false) {
		// Calculate the object number relative to the original bag's shadow mem start
    ptrdiff_t localShadowOffset = (uintptr_t)shadowaddr - bag->startShadowMem;
    unsigned long objectindex = localShadowOffset >> _shadowObjectInfoSizeShiftBits;
    return (void *)(_heapBegin + bag->startOffset + (objectindex << bag->shiftBits));
  }

	#ifdef ENABLE_GUARDPAGE
  inline int setGuardPage(void * bagStartAddr, size_t guardsize, size_t guardoffset) {
    if(guardsize == 0) { return 0; }

    uintptr_t guardaddr = (uintptr_t)bagStartAddr + _bibopBagSize;
		guardaddr -= guardoffset;

		//uintptr_t endAddr = guardaddr + guardsize;
		//ptrdiff_t diff = endAddr - guardaddr;
		//PRDBG("setGuardPage: mprotect region 0x%lx ~ 0x%lx, size=%lu", guardaddr, endAddr, diff);

		/*
    int mresult = mprotect((void *)guardaddr, guardsize, PROT_NONE); 
		if(mresult == -1) {
				PRERR("mprotect failed: %s", strerror(errno));
		}
		return mresult;
		*/

    return mprotect((void *)guardaddr, guardsize, PROT_NONE); 
  }
	#endif

	inline bool isInvalidAddr(void * addr) {
		return !((char *)addr >= _heapBegin && (char *)addr <= _heapEnd);
	}
};

size_t BibopHeap::_bagMask = 0;
unsigned long BibopHeap::_bagShiftBits = 0UL;
size_t BibopHeap::_bibopBagSize = 0;
unsigned BibopHeap::_cacheSize;
unsigned BibopHeap::_overProvObjBufSize;
#endif
