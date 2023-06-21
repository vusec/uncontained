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
    uint64_t other;
    struct socket socket;
};

struct socket_alloc {
    struct inode vfs_inode;
    struct intermediate intermediate;
    uint64_t other;
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

volatile struct socket_alloc salloc_storage;

static void __attribute_noinline__ tun_chr_open(struct intermediate *intermediate)
{
    struct sock sk;
    sock_init_data(&intermediate->socket, &sk);
    *((uint64_t volatile *)&salloc_storage.intermediate.other) = 12;
}

uint64_t rand_uint64_slow(void) {
  uint64_t r = 0;
  for (int i=0; i<64; i++) {
    r = r*2 + rand()%2;
  }
  return r;
}

void __attribute_noinline__ func1() {
    tun_chr_open((struct intermediate *)rand_uint64_slow());
}

int main(int argc, char*argv[]) {
    struct socket_alloc *salloc = (struct socket_alloc *)&salloc_storage;
    tun_chr_open(&salloc->intermediate);
    *((uint64_t volatile *)&salloc_storage.other) = 12;

    func1();
    return 0;
}

