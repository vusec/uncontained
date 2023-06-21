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

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member);\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = n = list_next_entry(pos, member), n = list_next_entry(n, member))

static __attribute_noinline__ int list_is_head(const struct list_head *list, const struct list_head *head)
{
	return list == head;
}

#define list_for_each(pos, head) \
	for (pos = (head)->next; \
	     !list_is_head(pos, (head)); \
	     pos = pos->next)

static __attribute_noinline__ int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}
static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

struct S {
    struct list_head list;
    int i;
};

static LIST_HEAD(glob_list);
// fake variable that tracks list size
static volatile int list_size = 1;
static __attribute_noinline__ int func()
{
	struct S *_op, *tmp;

	_op = list_entry(glob_list.next, struct S, list);
	return _op->i;
}

int main(int argc, char*argv[]) {
	if (list_size)
		return func();
	else
		return 0;
}
