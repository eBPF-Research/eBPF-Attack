#ifndef __OLD_SEC_H
#define __OLD_SEC_H

#ifdef CONFIG_SECURITY
#ifdef OLD_SEC

#include <linux/security.h>

#define SEC_HOOK_INIT(ops, func) \
    ops.func = sec_##func

void security_delete_hooks_fix(void)
{
    *(struct security_operations **)global_param->security_ops_addr = (struct security_operations *)global_param->default_security_ops_addr;
}

struct security_operations old_sec_inserts = {};

void security_add_hooks_fix(void)
{
    memcpy((void *)&old_sec_inserts, (void *)global_param->default_security_ops_addr, sizeof(old_sec_inserts));

#ifdef POV_MONITOR
    SEC_HOOK_INIT(old_sec_inserts, sb_mount),
    SEC_HOOK_INIT(old_sec_inserts, path_chroot),
    
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 2, 0)
    SEC_HOOK_INIT(move_mount),
#endif

#ifdef CONFIG_SECURITY_NETWORK
    SEC_HOOK_INIT(old_sec_inserts, socket_sendmsg);
#endif
#endif

#ifdef POV_LPE_VUL
    SEC_HOOK_INIT(old_sec_inserts, file_open);
    SEC_HOOK_INIT(old_sec_inserts, path_chmod);
    SEC_HOOK_INIT(old_sec_inserts, path_chown);
#endif

#ifdef CONFIG_SECURITY_NETWORK
    SEC_HOOK_INIT(old_sec_inserts, socket_recvmsg);
#endif

    *(struct security_operations **)global_param->security_ops_addr = &old_sec_inserts;
}

INIT_VOID_INSERTS(old_sec)
{
    pr_debug("old_sec register\n");
    security_add_hooks_fix();
}

INIT_VOID_UNINSERTS(old_sec)
{
    security_delete_hooks_fix();
}

#endif
#endif

#endif
