#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#include "container_of.h"


struct socket {
    uint64_t other;
};

struct sock {
    uint64_t sk_uid;
    uint64_t other1;
};

struct inode {
    uint64_t i_uid;
};

struct socket_alloc {
    struct inode vfs_inode;
    struct socket socket;
    uint64_t other;
};

struct tun_file {
    struct sock sk;
    struct socket socket;
    uint64_t other;
};

static inline struct inode *SOCK_INODE(struct socket *socket)
{
    return &container_of(socket, struct socket_alloc, socket)->vfs_inode;
}

void sock_init_data(struct socket *sock, struct sock *sk)
{
    if (sock) {
	sk->sk_uid	=	SOCK_INODE(sock)->i_uid;
    }
}

volatile struct socket_alloc salloc_storage;

static void __attribute_noinline__ tun_chr_open()
{
    struct socket_alloc *salloc = (struct socket_alloc *)&salloc_storage;
    struct sock sk;
    sock_init_data(&salloc->socket, &sk);
    *((uint64_t volatile *)&salloc_storage.other) = 12;
}

void __attribute_noinline__ func2() {
}

void __attribute_noinline__ func1() {
    func2();
}

int main(int argc, char*argv[]) {
    tun_chr_open();
    return 0;
}
