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

struct intermediate {
    struct socket socket;
};

struct socket_alloc {
    struct inode vfs_inode;
    struct intermediate intermediate;
};

struct tun_file {
    struct sock sk;
    struct socket socket;
    uint64_t other;
};

static inline struct inode *SOCK_INODE(struct socket *socket)
{
    return &container_of(socket, struct socket_alloc, intermediate.socket)->vfs_inode;
}

void sock_init_data(struct socket *sock, struct sock *sk)
{
    if (sock) {
        sk->sk_uid	=	SOCK_INODE(sock)->i_uid;
    }
}

volatile struct tun_file tfile_storage;

static void __attribute_noinline__ tun_chr_open()
{
    struct tun_file *tfile = (struct tun_file *)&tfile_storage;
    sock_init_data(&tfile->socket, &tfile->sk);
    *((uint64_t volatile *)&tfile_storage.other) = 12;
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
