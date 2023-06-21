#ifndef _LIST_
#define _LIST_

#include "container_of.h"

struct list_head {
    struct list_head *next, *prev;
};

static inline void __list_add(struct list_head *newh,
	struct list_head *prev,
	struct list_head *next)
{
    next->prev = newh;
    newh->next = next;
    newh->prev = prev;
    prev->next = newh;
}

static volatile unsigned long __list_entry_flow_ptr_in;
static volatile unsigned long __list_entry_flow_type_out;

static void __attribute_noinline__ list_add(struct list_head *newh, struct list_head *head)
{
    __list_add(newh, head, head->next);
}

#define list_entry(ptr, type, member) ({ \
    type* __tmp_ptr_out; \
    __list_entry_flow_ptr_in   = (unsigned long)ptr; \
    __tmp_ptr_out = container_of(ptr, type, member); \
    __list_entry_flow_type_out = (unsigned long)&__tmp_ptr_out; \
    (type*)__tmp_ptr_out;  })

#endif
