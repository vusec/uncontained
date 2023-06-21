#include <stdio.h>
#include <stddef.h>

/* Are two types/vars the same type (ignoring qualifiers)? */
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define static_assert _Static_assert

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

struct S21;
struct S21_operations {

    int (*func1)(struct S21 *);
    int (*func2)(struct S21 *);
    int (*func3)(struct S21 *);
};

struct S21 {

    long mem1;
    short mem2;
    struct S1 inner;
    long mem3;
    struct S21_operations *ops;
};

typedef struct member_s {
    unsigned x;
    unsigned y;
    struct member_s* m;
} member_t;

typedef struct {
    unsigned z;
    member_t m;
} container_t;

struct S21 s21;

struct OP_test;

void foo1(struct S1* s1);


int main1(int argc, char*argv[]) {
    
    struct S1* s1 = &s21.inner;
    member_t mem;
    container_t cont1;
    printf("%lx\n", (unsigned long)&mem);

    // member_t *m_ptr = (member_t*)main1;
    member_t *m_ptr = (member_t*)&cont1.m;
    struct OP_test *op_ptr = (struct OP_test*)foo1;
    printf("%lx\n", (unsigned long)&container_of(m_ptr, container_t, m)->z);
    printf("%lx\n", (unsigned long)&op_ptr);
    foo1(&s21.inner);
    return 0;
}

void foo1(struct S1* s1) {
    printf("%lx\n", container_of(s1, struct S21, inner)->mem3);
    // printf("%lx\n", (container_of(s1, struct S2, inner)->mem2));
}