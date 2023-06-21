#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

int dummy = 0;
int* dummy_addr = &dummy;
int* volatile out;

int* __attribute_noinline__ __inet_lookup_established() {
    int* volatile res = dummy_addr;
    return res;
}

int* __attribute_noinline__ func4(void* ptr) {
    out = ptr;
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
    int* ptr = __inet_lookup_established();
    func1(ptr);
    return 0;
}
