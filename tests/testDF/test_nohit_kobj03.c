#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#include "container_of.h"
#include "kobj.h"

/* the second container_of should not trigger */

void __attribute_noinline__ func1(void* ptr) {
    struct outer_container *other = container_of(ptr, struct outer_container, policy);
    printf("other: %p\n", other);
}

static ssize_t show(struct kobject *kobj, struct attribute *attr, char *buf)
{
    struct cpufreq_policy *other = container_of(kobj, struct cpufreq_policy, kobj);
    printf("other: %p\n", other);
    func1(other);
    return 0;
}

static ssize_t store(struct kobject *kobj, struct attribute *attr,
		     const char *buf, size_t count)
{
    return 0;
}

static const struct sysfs_ops sysfs_ops = {
    .show	= show,
    .store	= store,
};

static struct kobj_type ktype_cpufreq = {
    .sysfs_ops	= &sysfs_ops,
};

int kobject_init_and_add(struct kobject *kobj, const struct kobj_type *ktype) {
    printf("%p\n", kobj);
    printf("%p\n", ktype);
    return 0;
}

int __attribute_noinline__ func2(struct cpufreq_policy *policy) {
    int ret = kobject_init_and_add(&policy->kobj, &ktype_cpufreq);
    return ret;
}

struct outer_container outer_storage;

int main(int argc, char*argv[]) {
    struct cpufreq_policy *policy = &outer_storage.policy;
    return func2(policy);
}

