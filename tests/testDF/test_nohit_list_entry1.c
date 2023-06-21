#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

struct list_head {
	struct list_head *next, *prev;
};

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	((type *)(__mptr - offsetof(type, member))); })
void* __attribute__((weak)) __attribute_noinline__ __uncontained_list_entry_source(void* ptr);
void* __attribute__((weak)) __attribute_noinline__ __uncontained_list_entry_source(void* ptr) {
    return ptr;
}
#define list_entry(ptr, type, member)({ \
	type* __tmp_ptr_out = container_of(ptr, type, member); \
	(type*)__uncontained_list_entry_source((void*)__tmp_ptr_out);})
#define list_next_entry(pos, member) \
	({ list_entry((pos)->member.next, typeof(*(pos)), member);})
int __attribute__((weak)) __attribute_noinline__ __uncontained_list_entry_is_head(int res);
int __attribute__((weak)) __attribute_noinline__ __uncontained_list_entry_is_head(int res) {
    return res;
}
#define list_entry_is_head(pos, head, member)				\
	({ __uncontained_list_entry_is_head(&((typeof(pos)) ((void*)pos))->member == (head));})

#define list_first_entry(ptr, type, member) \
	({ list_entry((ptr)->next, type, member);})
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

struct S {
    struct list_head list;
    int i;
};

int dummy = 0;
int* dummy_addr = &dummy;
int* volatile out;

static LIST_HEAD(glob_list);
static __attribute_noinline__ int func(void *op)
{
	struct S *_op;

	list_for_each_entry(_op, &glob_list, list) {
		if (op == _op)
			return _op->i;
	}
	return 0;
}

int main(int argc, char*argv[]) {
    int* ptr = dummy_addr;
    return func(ptr);
}
