#ifndef _CONTAINER_OF_
#define _CONTAINER_OF_

#define __uncontained_container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	((type *)(__mptr - offsetof(type, member))); })

static volatile unsigned long __container_of_flow_ptr_in;
static volatile unsigned long __container_of_flow_type_in;
static volatile unsigned long __container_of_flow_type_out;

#define container_of(ptr, type, member) ({ \
    typeof(ptr) __tmp_type_in; \
    type* __tmp_ptr_out; \
    __container_of_flow_ptr_in   = (unsigned long)ptr; \
    __container_of_flow_type_in  = (unsigned long)&__tmp_type_in; \
    __tmp_ptr_out = __uncontained_container_of(ptr, type, member); \
    __container_of_flow_type_out = (unsigned long)&__tmp_ptr_out; \
    (type*)__tmp_ptr_out;  })

#endif
