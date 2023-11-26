#pragma once

#include "my_def.h"

#define MAX_ENVENT 256
// event_comm必须是整数Byte
#define LOG_ENTRY_SIZE (92 - 5)

// 全局变量存到map中
// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, 10);
// 	__type(key, __u32);   // global_id
// 	__type(value, __u64); // packet count
// } global_var_kv SEC(".maps");

struct bpf_map_def SEC("maps") global_var_kv = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 10,
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

enum GlobalRBKey {
	GLOBAL_TICK1 = 0,
	GLOBAL_RINGBUFFER_WRITE,
	GLOBAL_RINGBUFFER_ROUND,
	GLOBAL_PROC,
};

enum RBEventId {
	EVENT_LOG = 0,
};


// Force emitting struct event into the ELF.
struct event_comm {
	int val;
	u8 log[LOG_ENTRY_SIZE];
	u8 event_id;
};
const struct event_comm *unused __attribute__((unused));

// 持续的收集log
struct bpf_map_def SEC("maps") events_rb = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct event_comm),
	.max_entries = MAX_ENVENT,
};


static __inline void send_event(const struct event_comm *event) {
	int write_index = fetch_global_int(GLOBAL_RINGBUFFER_WRITE);
	bpf_map_update_elem(&events_rb, &write_index, event, 0);

	// update key
	u32 next_key = write_index + 1;
	if (next_key >= MAX_ENVENT) {
		int round = fetch_global_int(GLOBAL_RINGBUFFER_ROUND) + 1;
		save_global_val(GLOBAL_RINGBUFFER_ROUND, round);
		next_key = 0;
	}
	save_global_val(GLOBAL_RINGBUFFER_WRITE, next_key);
}

static __inline void send_event_log(int eid, int val, const char *log) {
	// 同一log只上传一次
	int last = fetch_global_int(GLOBAL_RINGBUFFER_WRITE) - 1;
	if (last >= 0) {
		struct event_comm *event = (struct event_comm *) bpf_map_lookup_elem(&events_rb, &last);
		if (event != NULL) {
			if (event->val == val && memcmp(event->log, log, LOG_ENTRY_SIZE) == 0) {
				// bpf_log("IGNORE--->%d %s\n", event->val, event->log);
				return;
			} else {
				// bpf_log("ADD--->%d %s\n", val, log);
			}
		}
	}

	struct event_comm event;
	event.event_id = eid;
	event.val = val;
	memcpy(event.log, log, LOG_ENTRY_SIZE);
	send_event(&event);
}
