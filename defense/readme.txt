- This is the experimental prototype for the mitigation model, to restrict ebpf.

- Capbit can be used as patch, and deployed in linux-v6.1.

```
git clone --branch v6.1 https://github.com/torvalds/linux.git
cd linux
git apply  /path/to/experimental-mitigate-model/Capit/0001-Experimental-BPF-Restrict.patch
# adjust the kernel config
```

- lsm-demo is also for linux-v6.1, but may need to export the some functions as following:

```
diff --git a/kernel/kallsyms.c b/kernel/kallsyms.c
index 60c20f301..76b8f4ec7 100644
--- a/kernel/kallsyms.c
+++ b/kernel/kallsyms.c
@@ -209,7 +209,7 @@ unsigned long kallsyms_lookup_name(const char *name)
        }
        return module_kallsyms_lookup_name(name);
 }
-
+EXPORT_SYMBOL(kallsyms_lookup_name);
```

