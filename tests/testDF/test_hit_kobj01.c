#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#include "container_of.h"
#include "kobj.h"

/* kobj is contained in another type */

static ssize_t show(struct kobject *kobj, struct attribute *attr, char *buf)
{
    struct other_container *other = container_of(kobj, struct other_container, kobj);
    printf("other: %p\n", other);
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

struct cpufreq_policy policy_storage;

int main(int argc, char*argv[]) {
    struct cpufreq_policy *policy = &policy_storage;
    int ret = kobject_init_and_add(&policy->kobj, &ktype_cpufreq);
    return ret;
}
