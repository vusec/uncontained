#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

struct sock_common {
    /* skc_daddr and skc_rcv_saddr must be grouped on a 8 bytes aligned
    * address on 64bit arches : cf INET_MATCH()
    */
    struct {
        unsigned int	skc_daddr;
        unsigned int	skc_rcv_saddr;
    };
    unsigned int	skc_hash;
    /* skc_dport && skc_num must be grouped as well */
    struct {
        unsigned short	skc_dport;
        unsigned short	skc_num;
    };

    unsigned short		skc_family;
    volatile unsigned char	skc_state;
    unsigned char		skc_reuse:4;
    unsigned char		skc_reuseport:1;
    unsigned char		skc_ipv6only:1;
    unsigned char		skc_net_refcnt:1;
};

int dummy = 0;
int* dummy_addr = &dummy;
int* volatile out;

struct sock_common* __attribute_noinline__ __inet_lookup_established() {
    int* volatile res = dummy_addr;
    return (struct sock_common*)res;
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
    struct sock_common* ptr = __inet_lookup_established();
    // this should not hit since it is not a load
    if (&ptr->skc_state == (volatile unsigned char *)0x1000)
        out = func1(ptr);
    return 0;
}
