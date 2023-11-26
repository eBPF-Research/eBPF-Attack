#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <asm/fcntl.h>
#include <asm/processor.h>
#include <linux/init.h>
#include <asm/paravirt.h>
#include <linux/kallsyms.h>
#include <linux/uidgid.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/moduleparam.h>
#include <linux/kthread.h>
#include <linux/elf.h>
#include <linux/bpf.h>
#include <linux/pid_namespace.h>
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */
#include <asm/uaccess.h>	/* for copy_from_user */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/trace_events.h>

//static char symbol[KSYM_NAME_LEN] = "trace_call_bpf";
//module_param_string(symbol, symbol, KSYM_NAME_LEN, 0644);


#define MAX_SYMBOL_LEN	64
#define PROCFS_NAME 		"bpf_security_prog"
#define PROCFS_NAME_WHITELIST 		"bpf_security_whitelist"

#define BUFSIZE			0x10

#define RT_BIT			0   // 1<<0 = 1
#define RT_W_BIT		1   // 1<<1 = 2
#define TP_BIT			2   // 1<<2 = 4
#define KP_BIT			3   // 1<<3 = 8
#define MAP_BIT			4   // 1<<4 = 16
#define TRACE_NS_ESCAPE_BIT	5   // 1<<5 = 32
#define ALLOW_BIT		6   // 1<<6 = 64 
#define PROCESS_CHECK		0
#define N 0x500



unsigned long control_vector = 0;   /* control_vector is used for restrict the types of bpf prog which can be loaded in isolated environment */

struct process_control_node
{
    unsigned long pid;
    unsigned long process_control_vector;
    struct hlist_node hlistNode;
};

struct hashlist{
    struct hlist_head hlistHead;
};

struct hashlist phead;
struct process_control_node pnode;

static void inline set_hlist_all(unsigned long control_vector) {
    struct hlist_node *pos;
    struct process_control_node *p;
    hlist_for_each(pos,&phead.hlistHead){
        p =   hlist_entry(pos,struct process_control_node,hlistNode);
//        printk("Node %d data:%d\n",i,p->num);
	p->process_control_vector = control_vector;
    }
    return;
}

static void inline set_init_process_control_vector(struct process_control_node *node,unsigned long value) {
    if(!value)
	node->process_control_vector = control_vector;
    else
	node->process_control_vector = value;
    return;
}
static void inline hlist_init(void) {
    //struct hlist_node *pos;
    struct process_control_node* listnode;
    int i;

    INIT_HLIST_HEAD(&phead.hlistHead);
    for ( i = 0; i < N; ++i) {
        listnode = (struct process_control_node *)kmalloc(sizeof(struct process_control_node),GFP_KERNEL);
        listnode->pid = 0;
        hlist_add_head(&(listnode->hlistNode),&phead.hlistHead);
//        printk("Node %d has added to the hash list...\n",i+1);
    }
    return;
}

static struct process_control_node* search_process_node(unsigned long pid) {
    struct hlist_node *pos;
    struct process_control_node *p;
    hlist_for_each(pos,&phead.hlistHead){
        p = hlist_entry(pos,struct process_control_node,hlistNode);
	if (p->pid == pid) {
	    //printk("process has been added");
	    return p;
	}
    }
    printk(KERN_ALERT "error in search_process_node");
    return NULL; /* shouldn't reach here */
}

static struct process_control_node* get_empty_node_from_hlist(unsigned long current_pid) {
    struct hlist_node *pos;
    struct process_control_node *p;
    struct process_control_node *target_p;
    int if_found = 0;
    hlist_for_each(pos,&phead.hlistHead){
        p = hlist_entry(pos,struct process_control_node,hlistNode);
	/* if the process has been add */
	if (p->pid == current_pid) {
	    //printk("process has been added");
	    return NULL;
	}
	/* get the first empty node we searched */
	if (!if_found && p->pid == 0) {
	    target_p = p;
	    if_found = 1;
	}
    }
    return target_p;
}
int if_check = 1;

unsigned int process_whitelist[0x1000];
static struct proc_dir_entry *ent;

static struct proc_dir_entry *ent_whitelist;

static ssize_t bpf_prog_security_proc_write(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	char buf[BUFSIZE];
	int num = 0;
	int read_size = 8;
	int c;
	
	/* In isolated environment, can not write the configure */
	if (!task_is_in_init_pid_ns(current))
		return -EPERM;
	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,read_size))
		return -EFAULT;
	num = sscanf(buf,"%ld",&control_vector);
	c = strlen(buf);
	*ppos = c;
	//set_hlist_all(control_vector);		// sync to pnode in hlist
	return c;
}
static ssize_t bpf_prog_security_proc_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char buf[BUFSIZE];
	int len = 0;
	/* In isolated environment, can not read the configure */
	if (!task_is_in_init_pid_ns(current))
		return -EPERM;
	if(*ppos > 0 || count < BUFSIZE)
		return 0;
	len += sprintf(buf,"%ld\n",control_vector);
	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	
	return len;
}

static struct proc_ops prog_sec_ops = 
{
	.proc_read = bpf_prog_security_proc_read,
	.proc_write = bpf_prog_security_proc_write,
};

static inline int find_uuid(unsigned int uuid)
{
    /* if the process is in white list, we won't do bpf control*/
    for (int i=0;i<0x1000;i++) {
	if (process_whitelist[i] == uuid)
	    return 0;
    }
    return 1;
}
static ssize_t bpf_whitelist_proc_write(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	char buf[0x8];
	unsigned int uuid = 0;
	int read_size = 8;
	int c = 8;

	/* In isolated environment, can not write the configure */
	if (!task_is_in_init_pid_ns(current))
		return -EPERM;
	if(copy_from_user(buf,ubuf,read_size))
		return -EFAULT;
	
	sscanf(buf,"%u",&uuid);
	for (int i=0;i<0x1000;i++) {
	   if(process_whitelist[i] == 0) {
		process_whitelist[i] = uuid; 
		goto out;
	   }
	}
out:
	*ppos = c;
	return c;
} 

static struct proc_ops whitelist_ops = 
{
	.proc_write = bpf_whitelist_proc_write,
};

struct task_struct *pid_1_task;

void trigger_err(void) {
	unsigned int *addr;
	unsigned int err;
	printk(KERN_ALERT "[Hook bpf]\n");
	addr = (unsigned int *)0xdeadbeef;
	err = *addr;
	printk("%u\n",err);
}
int my_bpf(int cmd, union bpf_attr *attr, unsigned int size) {
	return 0;
}


static bool inline check_prog_bit(unsigned int bit,unsigned long pid) {
    struct process_control_node *p;
    unsigned long current_control_vector;
    bool res;
    p = search_process_node(pid);

    if (p)
	current_control_vector = p->process_control_vector;
    else 
	current_control_vector = control_vector;
    
    res = (current_control_vector & (1 << bit));
    return res;
}


static inline ssize_t get_uuid_from_process(struct task_struct *process) {
    /* fake get, need extra vm run time support or kernel support, should read from PCB or uuid files */
    return 12345678;
}

/* Call through bpf_prog_load() recored namespace infomation */
int security_bpf_prog_alloc(struct bpf_prog_aux *aux) {
    struct pid_namespace * tmp = task_active_pid_ns(current);
    
    aux->load_ns = tmp;
        //printk(KERN_ALERT "aux->load_ns: %#llx\n",(unsigned long long)aux->load_ns);
    return 0;
}

int security_bpf_enter(int cmd, union bpf_attr *attr, unsigned int size) {
    int res;
    enum bpf_prog_type prog_type;
    struct process_control_node *p;
    pid_t current_pid;

#if PROCESS_CHECK
    unsigned int fake_uuid = get_uuid_from_process(current);
    /* if the process uuid is in white list, we won't check it */
    if (if_check == 0) return 0;
    if (find_uuid(fake_uuid) == 0) {
	if_check = 0;
	return 0;
    }
#endif

    res = 0;
    /* Once a process trigger bpf syscall, we add it to hash list, the process could be add to another ns  */ 
    current_pid = task_pid_nr(current);
    p = get_empty_node_from_hlist(current_pid);
    if(p) {
	p->pid = current_pid;
	set_init_process_control_vector(p,0);		// init to global control vec
	//printk("ADD %lu to control list\n",p->pid);
    }

    
    if (task_is_in_init_pid_ns(current) || cmd == BPF_MAP_CREATE) { return 0;}	// if the current process is outside, and we don't restrict map create

    if (cmd == BPF_MAP_GET_FD_BY_ID || cmd == BPF_MAP_FREEZE || cmd == BPF_MAP_LOOKUP_ELEM || cmd == BPF_MAP_UPDATE_ELEM || cmd == BPF_MAP_DELETE_ELEM) {
	    /* if the process in container, and not set the MAP_BIT */
	    if (!check_prog_bit(MAP_BIT,current_pid)) {
		printk(KERN_ALERT "MAP check failed\n");
		res = -1;
		return res;
	    }

	    	    
    } 
    else if (cmd == BPF_PROG_LOAD) {
	prog_type = attr->prog_type; 
	 /* If a process is in isolation environemnt(e.g. container) then we restrict it load some types of BPF_PROG */
	    if (prog_type == BPF_PROG_TYPE_RAW_TRACEPOINT) {
		if (!check_prog_bit(RT_BIT,current_pid)) {
		    res = -1;
		}
	    } else if (prog_type == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE) {
		if (!check_prog_bit(RT_W_BIT,current_pid)) {
		    res = -1;
		}
	    } else if (prog_type == BPF_PROG_TYPE_TRACEPOINT) {
		if (!check_prog_bit(TP_BIT,current_pid)) {
		    res = -1;
		}
	    } else if (prog_type == BPF_PROG_TYPE_KPROBE) {
		if (!check_prog_bit(KP_BIT,current_pid)) {
		    res = -1;
		}
	    }
	    return res;
	}
    return res;
}
struct security_hook_list hooks[] =
{
	LSM_HOOK_INIT(bpf, security_bpf_enter),		// __sys_bpf
	LSM_HOOK_INIT(bpf_prog_alloc_security, security_bpf_prog_alloc),	// __sys_bpf -> bpf_prog_load -> bpf_prog_new_fd

};
void my_security_add_hooks(struct security_hook_list *hooks, int count,
				char *lsm)
{
	int i;
	for (i = 0; i < count; i++) {
		hooks[i].lsm = lsm;
		hlist_add_tail_rcu(&hooks[i].list, hooks[i].head);
	}
}

// $rdi = struct bpf_prog *prog;
static struct kprobe kp_for___bpf_trace_run = {
        .symbol_name    = "bpf_trace_run2",
};
static struct kprobe kp_for_trace_call_bpf = {
	.symbol_name = "trace_call_bpf",
};

static int lsm_init(void)
{
	
	printk(KERN_ALERT "[LSM_INIT]\n");
        my_security_add_hooks(hooks,ARRAY_SIZE(hooks),"bpf_strict");
	ent = proc_create(PROCFS_NAME,0660,NULL,&prog_sec_ops);	
	ent_whitelist = proc_create(PROCFS_NAME_WHITELIST,0666,NULL,&whitelist_ops);
    
	hlist_init();

	//kp_for_trace_call_bpf.pre_handler = pre_kprobe;
	//kp_for___bpf_trace_run.post_handler = post_raw_trace;

		
	//register_kprobe(&kp_for_trace_call_bpf);
	//register_kprobe(&kp_for___bpf_trace_run);
	pr_info("Planted kprobe at %p\n", kp_for___bpf_trace_run.addr);
	pr_info("Planted kprobe at %p\n", kp_for_trace_call_bpf.addr);
	return 0;
}

static void lsm_exit(void)
{
        
	int i;
	int count=ARRAY_SIZE(hooks);
	proc_remove(ent);	
	printk(KERN_ALERT "[LSM_EXIT]\n");
	
	//unregister_kprobe(&kp_for_trace_call_bpf);
	//unregister_kprobe(&kp_for___bpf_trace_run);

        for (i = 0; i < count; i++)
                hlist_del_rcu(&hooks[i].list);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("test");
MODULE_DESCRIPTION("A lsm security module demo.");

module_init(lsm_init);
module_exit(lsm_exit);
