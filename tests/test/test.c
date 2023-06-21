#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

/* Are two types/vars the same type (ignoring qualifiers)? */
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define static_assert _Static_assert

#ifndef likely
# define likely(x)		__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

#define STRINGIFY(a) #a
#define SSTRINGIFY(x) STRINGIFY(x)

// _Pragma( SSTRINGIFY( message (SSTRINGIFY(typeof(*(ptr))) " -> " SSTRINGIFY(type))) )

__attribute__((no_sanitize_address)) static volatile unsigned long __container_of_type_in;
__attribute__((no_sanitize_address)) static volatile unsigned long __container_of_type_out;
__attribute__((no_sanitize_address)) static volatile unsigned long __container_of_ptr_in;
__attribute__((no_sanitize_address)) static volatile unsigned long __container_of_ptr_out;
__attribute__((no_sanitize_address)) static volatile unsigned long __container_of_ptr_diff;

#define container_of(ptr, type, member) ({ \
    typeof(ptr) __tmp_type_in; \
    type* __tmp_ptr_out = __container_of(ptr, type, member); \
    __container_of_ptr_in   = (unsigned long)ptr; \
    __container_of_type_in  = (unsigned long)&__tmp_type_in; \
    __container_of_type_out = (unsigned long)&__tmp_ptr_out; \
    __container_of_ptr_out  = (unsigned long) __tmp_ptr_out; \
    __container_of_ptr_diff = (unsigned long) offsetof(type, member); \
    printf("container_of - from: %p to: %p\n", ptr, __tmp_ptr_out);\
    (type*)__container_of_ptr_out;})

#define __container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	static_assert(__same_type(*(ptr), ((type *)0)->member) ||	\
		      __same_type(*(ptr), void),			\
		      "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })


struct S1 {
    int mem1;
    char mem2;
};

struct S2 {

    long mem1;
    short mem2;
    struct S1 inner;
    long mem3;
};

typedef struct member_s {
    unsigned x;
    unsigned y;
    struct member_s* m;
} member_t;

typedef struct {
    unsigned z;
    member_t m;
    int data[16];
} container_t;

typedef struct {
    unsigned z;
    container_t cont;
    char data[16];
} outer1_container_t;

typedef struct {
    unsigned z;
    char data[16];
    container_t cont;
    int i;
} outer2_container_t;

typedef struct {
    unsigned z;
    outer1_container_t outer1;
    char data[16];
} outer_outer_container_t;


struct OP_test {
    int a;
    char b;
};
#define llist_entry(ptr, type, member)		\
    container_of(ptr, type, member)
#define member_address_is_nonnull(ptr, member)	\
    ((unsigned long)(ptr) + offsetof(typeof(*(ptr)), member) != 0)
#define llist_for_each_entry(pos, node, member)				\
    for ((pos) = llist_entry((node), typeof(*(pos)), member);	\
        member_address_is_nonnull(pos, member);			\
        (pos) = llist_entry((pos)->member.next, typeof(*(pos)), member))
struct llist_head {
    struct llist_node *first;
};

struct llist_node {
    struct llist_node *next;
};
struct outer_list {
    int i;
    struct llist_node   list;
};

struct list_head {
	struct list_head *next, *prev;
};
struct pcpu_chunk {
    struct {
        int j;
        struct list_head list;
    };
    int i;
};

container_t cont1;
outer1_container_t outer1;

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)
#define list_next_entry(pos, member) \
	({ /*puts("next entry");*/\
    list_entry((pos)->member.next, typeof(*(pos)), member);})
#define list_entry_is_head(pos, head, member)				\
	({ /*printf("is head: %d\n", (&(pos)->member == (head))? 1 : 0);*/\
    (&((typeof(pos)) ((void*)pos))->member == (head));})
#define list_first_entry(ptr, type, member) \
	({ /*puts("first entry");*/\
    list_entry((ptr)->next, type, member);})
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = n, n = list_next_entry(n, member))

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
static inline _Bool IS_ERR_OR_NULL(const void *ptr)
{
	return unlikely(!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}


static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}



#define SHADOW_SCALE 3
void __asan_get_shadow_mapping(unsigned long *shadow_scale, unsigned long *shadow_offset);
volatile _Bool kasan_ready = 1;
static __attribute_noinline__ _Bool kasan_arch_is_ready_visible(void)	{ return kasan_ready; }
#define MEM_TO_SHADOW(mem, off) (((mem) >> SHADOW_SCALE) + (off))
// _Bool __attribute_noinline__ kasan_byte_accessible(const void *addr)
// {
    // unsigned long base;
    // __asan_get_shadow_mapping(NULL, &base);
// 	char shadow_byte = (*(char *)MEM_TO_SHADOW((unsigned long)addr, base));
// 	_Bool res = shadow_byte >= 0 && shadow_byte < (1ULL << SHADOW_SCALE);
//     printf("addr: %p, shadow addr: %p, shadow val: %hhx, res: %hhx\n", addr, ((void *)MEM_TO_SHADOW((unsigned long)addr, base)), shadow_byte, res);
//     return res;
// }
_Bool __attribute_noinline__ kasan_memory_is_accessible(void* addr)
{
    unsigned long base;
    __asan_get_shadow_mapping(NULL, &base);
    char shadow_value = *(char *)MEM_TO_SHADOW(((unsigned long)addr), base);
    _Bool res;

    if ((shadow_value)) {
        char last_accessible_byte = ((unsigned long)addr) & 7;
        res = (last_accessible_byte < shadow_value);
    } else {
        res = 1;
    }
    printf("addr: %p, shadow addr: %p, shadow val: %hhx, res: %hhx\n", addr, ((void *)MEM_TO_SHADOW((unsigned long)addr, base)), shadow_value, res);

    return res;
}

void __asan_report_load1_noabort(unsigned long addr);
_Bool __attribute_noinline__ uncontained_type_check(char* orig_addr, char* addr, unsigned long size) {

  printf("check: %p, size: %ld\n", addr, size);

  // bail out if `addr` == NULL, since we may be in a path not strictly coming
  // from a container_of, but a forwarded use that may depend on something else
  // e.g., return phi(container_of: found_bb, NULL: not_found_bb)
  if (unlikely(IS_ERR_OR_NULL((void*) orig_addr) || (unsigned long) orig_addr < 0x1000)) {
    return 1;
  }

  // report if the address may overflow
  if (unlikely(addr + size < addr)) {
    return 0;
  }

  // report if the address has no kasan mapping
//   if (unlikely((void *)addr <
//       kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
//     kasan_report((unsigned long) addr, 1, false, __RET_IP__);
//     return;
//   }

  if (unlikely(
    // check for first byte of left redzone
    kasan_memory_is_accessible(addr - 1) || 
    // check for the valid start
    !kasan_memory_is_accessible(addr) || 
    // check for the last byte valid
    !kasan_memory_is_accessible(addr + size - 1) || 
    // check for the first byte of redzone
    kasan_memory_is_accessible(addr + size) 
  )) {
    return 0;
  }
  return 1;
}

_Bool __attribute_noinline__ uncontained_type_maybe_check(char* orig_addr, char* addr, unsigned long size, _Bool should_check) {
    if (should_check) {
    return uncontained_type_check(orig_addr, addr, size);
  } else {
    return 1;
  }
}

void __attribute_noinline__ uncontained_type_maybe_report(char* addr, unsigned long size, _Bool is_safe) {
  if (!is_safe) {
    __asan_report_load1_noabort((unsigned long) addr);
  }
}

#define noinline __attribute__((__noinline__))
static noinline void* uncontained_whitelist_use(void* use) {
    printf("skipping check %p\n", use);
    asm volatile (
        ""
        : "+r" (use)
    );
    return use;
}

void foo(struct S1* s1) ;
int main1(int argc, char*argv[]);

static LIST_HEAD(glob_pcpu_chunk_list);
static noinline _Bool optprobe_queued_unopt(struct pcpu_chunk *op)
{
	struct pcpu_chunk *_op;

	list_for_each_entry(_op, &glob_pcpu_chunk_list, list) {
		if (op == _op)
			return 1;
	}

	return 0;
}

int main(int argc, char*argv[]) {

    struct S2 s2;
    container_t cont;
    outer1_container_t outer1_cont;
    outer2_container_t outer2_cont;
    outer_outer_container_t outer_outer_cont;

    struct S1* s1 = &s2.inner;
    s2.mem1 = 0x1111111111;
    s2.mem2 = 0x2222;
    s2.mem3 = 0x3333333333;
    if (!kasan_memory_is_accessible(main)) {
        volatile _Bool c = 0;
        char* volatile f = (char*) main;
        volatile int s = 1;
        uncontained_type_check(f, f, s);
        uncontained_type_maybe_check(f, f, s, c);
        uncontained_type_maybe_report(f, 1, !c);
        return 1;
    }
    if (!kasan_arch_is_ready_visible()) return 1;

    // member_t *m_ptr = (member_t*)main;
    member_t *m_ptr = (member_t*)&cont.m;
    // printf("%lx\n", (unsigned long)&container_of((member_t*)s1, container_t, m)->z);
    puts("[+] simple container_of");
    printf("%lx\n", (unsigned long)&container_of((member_t*)m_ptr, container_t, m)->z);

    puts("[+] multi-level container_of");
    member_t *m_ptr_outer1 = (member_t*)&outer1_cont.cont.m;
    member_t *m_ptr_outer2 = (member_t*)&outer2_cont.cont.m;
    member_t *m_ptr_outer_outer = (member_t*)&outer_outer_cont.outer1.cont.m;
    printf("%lx\n", (unsigned long)&container_of((member_t*)m_ptr_outer1, container_t, m)->z);
    printf("%lx\n", (unsigned long)&container_of((member_t*)m_ptr_outer2, container_t, m)->z);
    printf("%lx\n", (unsigned long)&container_of((member_t*)m_ptr_outer_outer, container_t, m)->z);
    // struct OP_test *op_ptr = (struct OP_test*)foo;
    // printf("%lx\n", (unsigned long)op_ptr->a);
    foo(&s2.inner);
    main1(0, NULL);

    char* ptr = malloc(11);
    printf("malloc tests:\n");
    kasan_memory_is_accessible(ptr);
    kasan_memory_is_accessible(ptr+1);
    kasan_memory_is_accessible(ptr+10);
    kasan_memory_is_accessible(ptr+11);
    kasan_memory_is_accessible(ptr+12);
    free(ptr);

    puts("[+] list for each entry");
    struct outer_list elem1 = {0};
    struct outer_list elem2 = {0};
    elem1.i = 1;
    elem2.i = 2;
    elem1.list.next = &elem2.list;
    struct outer_list *lptr;
    struct llist_node *start = &elem1.list;
    llist_for_each_entry(lptr, start, list) {
        printf("list: %lx %d\n", (unsigned long)lptr, lptr->i);
    }

    puts("[+] list for each entry safe");
    struct list_head pcpu_chunk_lists[3] = {0};
    for (int i = 0; i < 3; i++) {
        pcpu_chunk_lists[i].next = &pcpu_chunk_lists[i];
        pcpu_chunk_lists[i].prev = &pcpu_chunk_lists[i];
    }
    struct pcpu_chunk *chunk, *next;
    printf("list vector: %p\n", &pcpu_chunk_lists);

    struct pcpu_chunk entry = {0};
    entry.i = 123;
    list_add(&entry.list, &pcpu_chunk_lists[1]);
    struct pcpu_chunk *res = NULL;

    for (int i = 0; i < 3; i++) {
        printf("slot: %d - head: %p\n", i, &pcpu_chunk_lists[i]);
        list_for_each_entry_safe(chunk, next, &pcpu_chunk_lists[i], list) {
            printf("list: 0x%lx %d\n", (unsigned long)chunk, chunk->i);
            if (chunk->i == 0x1337) res = chunk;
        }
    }
    printf("res: 0x%lx\n", (unsigned long)res);

    puts("[+] list for each entry cmp combine");
    printf("res: %hhd\n", optprobe_queued_unopt(&entry));

    puts("[+] merge test");
    volatile int i = 1;
    volatile unsigned int *merged;
    volatile unsigned int other_var = 0x1234;
    if (i) {
        merged = &container_of((member_t*)m_ptr, container_t, m)->z;
    } else {
        merged = &other_var;
    }
    printf("%x\n", *merged);

    puts("[+] container_of iteration test");
    container_t cont2;
    member_t *m_ptr2 = (member_t*)&cont2.m;
    container_t* ct = container_of((member_t*)m_ptr2, container_t, m);
    char* _ptr = (char*)ct->data;
    for (volatile int i = 0; i < 16; i++) {
        *_ptr = i;
        ++_ptr;
    }

    return 0;
}

void foo(struct S1* s1) {
    puts("[+] second container_of");
    printf("%lx\n", container_of(s1, struct S2, inner)->mem3);
    puts("[+] third container_of");
    printf("%lx\n", container_of(uncontained_whitelist_use((void*)s1), struct S2, inner)->mem3);
    // printf("%lx\n", (container_of(s1, struct S2, inner)->mem2));
}