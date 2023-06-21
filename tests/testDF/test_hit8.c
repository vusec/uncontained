#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

int dummy = 0;
int* dummy_addr = &dummy;
int* volatile out;

int __attribute_noinline__ __test_sanitizer(void* ptr) {
    return *(int*)ptr;
}

int __attribute_noinline__ wrapper_sanitizer(void* ptr) {
    return __test_sanitizer(ptr);
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
    // FIXME: this is a false positive, due to the function
    // being wrapped. Do we want to detect this?
    if (wrapper_sanitizer(ptr))
        __test_sink(func1(ptr));
    return 0;
}
