#if !defined(DOUBLETAKE_LIST_H)
#define DOUBLETAKE_LIST_H

/*
 * @file   list.h
 * @brief  Something about list etc.
 * @author Tongping Liu <http://www.cs.umass.edu/~tonyliu>
 */

#include <stdlib.h>

typedef struct list {
  struct list* prev;
  struct list* next;
} my_list;

// Initialize a node
inline void nodeInit(my_list* node) { node->next = node->prev = node; }

inline void listInit(my_list* node) { nodeInit(node); }

// Whether a list is empty
inline bool isListEmpty(my_list* head) { return (head->next == head); }

// Next node of current node
inline my_list* nextEntry(my_list* cur) { return cur->next; }

// Previous node of current node
inline my_list* prevEntry(my_list* cur) { return cur->prev; }

// We donot check whetehr the list is empty or not?
inline my_list* tailList(my_list* head) {
  my_list* tail = NULL;
  if(!isListEmpty(head)) {
    tail = head->prev;
  }

  return tail;
}

// Insert one entry to two consequtive entries
inline void __insert_between(my_list* node, my_list* prev, my_list* next) {
  // fprintf(stderr, "line %d: prev %p next %p\n", __LINE__, prev, next);
  // fprintf(stderr, "line %d: prev now %lx next %p\n", __LINE__, *((unsigned long *)prev), next);
  // fprintf(stderr, "line %d: prev->next %lx next %p\n", __LINE__, *((unsigned long *)((unsigned
  // long)prev + 0x8)), next);
  node->next = next;
  node->prev = prev;
  prev->next = node;
  next->prev = node;
}

// Insert one entry to after specified entry prev (prev, prev->next)
inline void listInsertNode(my_list* node, my_list* prev) { __insert_between(node, prev, prev->next); }

// Insert one entry to the tail of specified list.
// Insert between tail and head
inline void listInsertTail(my_list* node, my_list* head) {
  // fprintf(stderr, "node %p head %p head->prev %p\n", node, head, head->prev);
  __insert_between(node, head->prev, head);
}

// Insert one entry to the head of specified list.
// Insert between head and head->next
inline void listInsertHead(my_list* node, my_list* head) { __insert_between(node, head, head->next); }

// Internal usage to link p with n
// Never use directly outside.
inline void __list_link(my_list* p, my_list* n) {
  p->next = n;
  n->prev = p;
}

// We need to verify this
// Insert one entry to the head of specified list.
// Insert the list between where and where->next
inline void listInsertList(my_list* list, my_list* where) {
  // Insert after where.
  __list_link(where, list);

  // Then modify other pointer
  __list_link(list->prev, where->next);
}

// Insert one list between where->prev and where, however,
// we don't need to insert the node "list" itself
inline void listInsertListTail(my_list* list, my_list* where) {
#if 0
  // Link between where->prev and first node of list.
  my_list* origtail = where->prev;
  my_list* orighead = where;
  my_list* newhead = list->next;
  my_list* newtail = list->prev;

  origtail->next = newhead;
  newhead->prev = origtail;

  newtail->next = orighead;
  orighead->prev = newtail;
    
    p->next = n;
    n->prev = p;
#else
  __list_link(where->prev, list->next);

  // Link between last node of list and where.
  __list_link(list->prev, where);
#endif
}

// Delete an entry and re-initialize it.
inline void listRemoveNode(my_list* node) {
  __list_link(node->prev, node->next);
  nodeInit(node);
}

// Check whether current node is the tail of a list
inline bool isListTail(my_list* node, my_list* head) { return (node->next == head); }

// Retrieve the first item form a list
// Then this item will be removed from the list.
inline my_list* listRetrieveItem(my_list* list) {
  my_list* first = NULL;

  // Retrieve item when the list is not empty
  if(!isListEmpty(list)) {
    first = list->next;
    listRemoveNode(first);
  }

  return first;
}

// Retrieve all items from a list and re-initialize all source list.
inline void listRetrieveAllItems(my_list* dest, my_list* src) {
  my_list* first, *last;
  first = src->next;
  last = src->prev;

  first->prev = dest;
  last->next = dest;
  dest->next = first;
  dest->prev = last;

  // reinitialize the source list
  listInit(src);
}

// Print all entries in the link list
inline void listPrintItems(my_list* head, int num) {
  int i = 0;
  my_list* first, *entry;
  entry = head->next;
  first = head;

  while(entry != first && i < num) {
    //    fprintf(stderr, "%d: ENTRY %d: %p (prev %p). HEAD %p\n", getpid(), i++, entry,
    // entry->prev, head);
    entry = entry->next;
  }

  // PRINF("HEAD %p Head->prev %p head->next %p\n", head, head->prev, head->next);
}

/* Get the pointer to the struct this entry is part of
 *
 */
#define listEntry(ptr, type, member) ((type*)((char*)(ptr) - (unsigned long)(&((type*)0)->member)))

#endif
