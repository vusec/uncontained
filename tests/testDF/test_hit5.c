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
    out = ptr;
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

int main(int argc, char*argv[]) {
    out = func1();
    return 0;
}
