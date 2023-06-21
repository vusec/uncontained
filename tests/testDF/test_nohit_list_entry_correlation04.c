#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#include "list.h"

/* list_add is using the same struct type than preceeding list_entry */

struct test {
    uint64_t other;
    struct list_head list;
};

struct test1 {
    uint64_t other1;
    uint64_t other2;
    struct list_head list;
};

struct test test_storage;
struct test1 test1_storage;

static void __attribute_noinline__ func3(struct list_head *head)
{
    list_add(&test_storage.list, head);
}

static void __attribute_noinline__ func2(struct list_head *head)
{
    struct test1 *test = list_entry(head, struct test, list);
    printf("test: %p\n", test);
    func3(head);
}

static void __attribute_noinline__ func1()
{
    struct list_head test_list;
    list_add(&test_storage.list, &test_list);
    func2(&test_list);
}


/* without this list_add does not have any arguments after optimizations :( */
struct list_head test_list_decoy;
struct test test_decoy_storage;

int main(int argc, char*argv[]) {
    func1();

    // break optimizations
    list_add(&test_decoy_storage.list, &test_list_decoy);
    func2(&test_list_decoy);
    return 0;
}

