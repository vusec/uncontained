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

int* __attribute_noinline__ func4() {
    int* ptr = __inet_lookup_established();
    return ptr;
}

int* __attribute_noinline__ func3() {
    return func4();
}

int* __attribute_noinline__ func2() {
    return func3();
}

int* __attribute_noinline__ func1() {
    return func2();
}

int* __attribute_noinline__ func7(void* ptr) {
    out = ptr;
    return ptr;
}

int* __attribute_noinline__ func6(void* ptr) {
    func7(ptr);
    return ptr;
}

int* __attribute_noinline__ func5(void* ptr) {
    func6(ptr);
    return ptr;
}

int main(int argc, char*argv[]) {
    int* ptr = func1();
    func5(ptr);
    return 0;
}
