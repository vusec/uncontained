#ifndef _KOBJ_
#define _KOBJ_

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

struct kobject {
    uint64_t other;
};

struct other_container {
    struct kobject kobj;
};

struct cpufreq_policy {
    uint64_t other;
    struct kobject kobj;
};

struct outer_container {
    uint64_t other;
    struct cpufreq_policy policy;
};

struct outer_container2 {
    uint64_t other;
    struct other_container container;
};

struct attribute {
    const char		*name;
};

struct sysfs_ops {
    ssize_t	(*show)(struct kobject *, struct attribute *, char *);
    ssize_t	(*store)(struct kobject *, struct attribute *, const char *, size_t);
};

struct kobj_type {
    uint64_t first;
    const struct sysfs_ops *sysfs_ops;
};

#endif

