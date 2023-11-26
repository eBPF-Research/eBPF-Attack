#ifndef __SEC_HOOK_H
#define __SEC_HOOK_H

#ifdef CONFIG_SECURITY

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
#define OLD_SEC
#endif

#define SEC_HOOK1(name, t, ...) SEC_HOOKx(1, _##name, t, __VA_ARGS__)
#define SEC_HOOK2(name, t, ...) SEC_HOOKx(2, _##name, t, __VA_ARGS__)
#define SEC_HOOK3(name, t, ...) SEC_HOOKx(3, _##name, t, __VA_ARGS__)
#define SEC_HOOK4(name, t, ...) SEC_HOOKx(4, _##name, t, __VA_ARGS__)
#define SEC_HOOK5(name, t, ...) SEC_HOOKx(5, _##name, t, __VA_ARGS__)
#define SEC_HOOK6(name, t, ...) SEC_HOOKx(6, _##name, t, __VA_ARGS__)

#define SEC_HOOKx(x, name, type, ...) \
    static type sec##name(__MAP(x, __SC_DECL, __VA_ARGS__))

#ifndef OLD_SEC
#include <linux/lsm_hooks.h>

#define SEC_HOOK_INIT(HEAD)                                         \
    {                                                               \
        .head = (void *)offsetof(struct security_hook_heads, HEAD), \
        .hook = {.HEAD = (void *)sec_##HEAD }                       \
    }

static inline void security_add_hooks_fix(struct security_hook_list *hooks, int count)
{
    int i;

    enable_write();

    for (i = 0; i < count; i++)
    {
        hooks[i].head = (void *)((unsigned long)hooks[i].head + (unsigned long)global_param->security_hook_heads_addr);

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 17, 0)
        hlist_add_tail_rcu(&hooks[i].list, hooks[i].head);
#else
        list_add_tail_rcu(&hooks[i].list, hooks[i].head);
#endif
    }
    disable_write();
}

static inline void security_delete_hooks_fix(struct security_hook_list *hooks, int count)
{
    int i;

    for (i = 0; i < count; i++)
    {
        enable_write();
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 17, 0)
        hlist_del_rcu(&hooks[i].list);
#else
        list_del_rcu(&hooks[i].list);
#endif
        disable_write();
    }
}

#endif

#endif
#endif
