#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

int dummy = 0;
int* dummy_addr = &dummy;
int* volatile out;

int __attribute_noinline__ __test_sanitizer(void* ptr) {
    return *(int*)ptr;
}

void __attribute_noinline__ __test_sink(void* ptr) {
    out = ptr;
}

int* __attribute_noinline__ __test_source() {
    int* volatile res = dummy_addr;
    return res;
}

int* __attribute_noinline__ func4(void* ptr) {
    return ptr;
}

int* __attribute_noinline__ func3(void* ptr) {
    return func4(ptr);
}

int* __attribute_noinline__ func2(void* ptr) {
    return func3(ptr);
}

int* __attribute_noinline__ func1(void* ptr) {
    return func2(ptr);
}

int main(int argc, char*argv[]) {
    int* ptr = __test_source();
    if (__test_sanitizer(ptr))
        __test_sink(func1(ptr));
    return 0;
}
