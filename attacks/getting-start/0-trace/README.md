
### Trace教程
获取容器外的进程。  
详细见attacks里面的代码。  

####  创建基本程序骨架。利用eBPF抓取进程的系统调用信息。  
首先我们创建一个最简eBPF项目：  
```
// 文件目录结构
getting-start \
	|-- main.go  // go eBPF控制代码，用来加载eBPF程序，以及从eBPF程序获取信息
	|-- sys_hook.ebpf.c  // eBPF代码
```
[eBPF文件](getting-start/sys_hook.ebpf.c)，需要注意的是第一行注释 + build ignore，
是有Go语义的（go build会读取），不能随便删除：
``` c
// +build ignore
#include "common.h"
#include "bpf_helpers.h"
#include "my_std.h"

// for message counter
struct bpf_map_def SEC("maps") raw_tracepoint_map_1 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
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
```
这里我们使用`bpf_get_current_comm` helper函数来获取进程信息，comm字段含义是executable name excluding path。
由于我们的eBPF-C代码需要零依赖自己编译，
所以我们在[headers/bpf_helper_defs.h](../headers/bpf_helper_defs.h)里面定义了这些函数，这样不需要
依赖Linux系统自带头文件。  
Kernel eBPF里面helper[实现代码](https://elixir.bootlin.com/linux/v5.18/source/kernel/bpf/helpers.c#L221)如下：
``` c
BPF_CALL_2(bpf_get_current_comm, char *, buf, u32, size) {
	struct task_struct *task = current;
	/* Verifier guarantees that size > 0 */
	strscpy(buf, task->comm, size);
	// ...
	return 0;
}
```
由于这段代码是直接在Kernel中执行的，因此不需要调用`copy_to_user`，直接`strcpy`就行。  

编译eBPF代码：  
``` bash
cd getting-start
export BPF_CLANG=clang-13
go generate

# 执行go generate会调用 main.go中开始几行注释中的go generate注释，这个注释后面就是实际命令  
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf sys_hook.ebpf.c -- -I../headers

# 这个命令的功能是，利用cillum-bpf2go，调用clang-llvm生成eBPF字节码，并且把字节码嵌入到go代码中，生成loader函数。

# 编译成功之后，多了：bpf_bpfeb.go和bpf_bpfel.go，这两个文件会load eBPF字节码
```

接下来在`main.go`里面加载这段eBPF代码：
``` go
func main() {
	log.Printf("hello eBPF!\n")
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	link_1, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.RawTpSysEnter,
	})
	CHECK_ERR(err, "sys_enter attach failed")
	defer link_1.Close()
	ticker := time.NewTicker(1 * time.Second)
	count := 0
	const mapKey uint32 = 0
	for range ticker.C {
		count += 1
		if count == 60 {
			return
		}
		var value string
		if err := objs.RawTracepointMap1.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map1: %v", err)
		}
		log.Println("Tick: ", count, value)
		time.Sleep(1)
	}
}
```

编译和运行go代码：
``` bash
$bash compile.sh
$sudo ../bin/start 
2022/06/20 09:21:23 hello eBPF!
2022/06/20 09:21:24 Tick:  1 cpptools
2022/06/20 09:21:25 Tick:  2 sshd
2022/06/20 09:21:26 Tick:  3 node
2022/06/20 09:21:27 Tick:  4 node
2022/06/20 09:21:28 Tick:  5 sshd
```
