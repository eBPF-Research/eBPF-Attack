
#include "common.h"

// 全局变量存到map中
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10);
	__type(key, __u32);   // global_id
	__type(value, __u64); // value
} global_val_kv SEC(".maps");

// struct bpf_map_def SEC("maps") global_val_kv = {
// 	.type = BPF_MAP_TYPE_ARRAY,
// 	.key_size = sizeof(u32),
// 	.value_size = 0x40,
// 	.max_entries = 10,
// };

struct bpf_map_def SEC("maps") global_buf_kv = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = 0x40,
	.max_entries = 10,
};

static __inline void save_global_val(u32 key, u64 val) {
	bpf_map_update_elem(&global_val_kv, &key, &val, BPF_ANY);
}

static __inline u64 get_global_val(u32 key) {
	u64 val;
	void* ptr = bpf_map_lookup_elem(&global_val_kv, &key);
	bpf_probe_read(&val, sizeof(val), ptr);
	return val;
}

static __inline void save_global_buf(u32 key, void *ptr) {
	bpf_map_update_elem(&global_buf_kv, &key, ptr, BPF_ANY);
}

static __inline void* get_global_buf(u32 key) {
	return bpf_map_lookup_elem(&global_buf_kv, &key);
}

