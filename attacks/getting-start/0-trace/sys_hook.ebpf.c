// +build ignore

/*
开启 bpf_log 
*/
#define DEBUG_LOG

#include "my_def.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16

// for message counter
struct bpf_map_def SEC("maps") raw_tracepoint_map_1 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = TASK_COMM_LEN,
	.max_entries = 2,
};

SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	// step-1: get process pid, name, args, syscall_id
	char comm[TASK_COMM_LEN] = {0};
	bpf_get_current_comm(&comm, sizeof(comm));
	u32 key = 0;
	bpf_map_update_elem(&raw_tracepoint_map_1, &key, comm, BPF_ANY);
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx) {

	return 0;
}