//go:build linux
// +build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags  $BPF_CFLAGS -type event_comm bpf sys_hook.ebpf.c -- -I../../headers

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	// "strconv"

	ebpf_helper "ebpf_attack/go-common"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const Ti = 600

func main() {
	log.Printf("hello eBPF!\n")
	ebpf_helper.Ctrl_c_Exit()
	go ebpf_helper.Dump_bpf_log()

	ebpf_helper.Set_memlock()

	// 1. 加eBPF 程序
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	link_1, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.RawTpSysEnter,
	})
	ebpf_helper.CHECK_ERR(err, "sys_enter attach failed")
	defer link_1.Close()

	link_2, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: objs.RawTpSysExit,
	})
	ebpf_helper.CHECK_ERR(err, "sys_exit attach failed")
	defer link_2.Close()

	// tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointSyscallsSysEnterOpen)
	// CHECK_ERR(err, "sys_enter_open attach failed")
	// defer tp.Close()

	// 收集进程信息
	go trace_comm(objs)

	// 收集

	// 2. 让eBPF程序持续运行
	ticker := time.NewTicker(time.Second)
	count := 0
	for range ticker.C {
		count += 1
		if count == Ti {
			panic("Timeout! Exit!")
			return
		}
		log.Println("Tick: ", count)
		time.Sleep(1 * time.Millisecond)
	}
}

// -------------------------------------
const RB_SIZE = 256
const (
	EVENT_COMM      = 1
	EVENT_OPEN_FILE = 2
	EVENT_EXECVE    = 3
	EVENT_SYSCALL   = 4
)

func trace_comm(objs bpfObjects) {
	outComm, err := os.OpenFile("comm_log.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	ebpf_helper.CHECK_ERR(err, "Failed to create comm log file")
	defer outComm.Close()

	openSnoop, err := os.OpenFile("openat_log.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	ebpf_helper.CHECK_ERR(err, "Failed to create open log file")
	defer openSnoop.Close()

	execSnoop, err := os.OpenFile("execve_log.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	ebpf_helper.CHECK_ERR(err, "Failed to create execve log file")
	defer execSnoop.Close()

	syscallSnoop, err := os.OpenFile("syscall_log.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	ebpf_helper.CHECK_ERR(err, "Failed to create syscall log file")
	defer syscallSnoop.Close()

	var commMap map[string]int = make(map[string]int)
	const mapKey_RB uint32 = 1 // GLOBAL_RINGBUFFER_WRITE
	// ringbuffer读了多少轮次
	const mapKey_Round uint32 = 2 // GLOBAL_RINGBUFFER_ROUND

	// unix.ByteSliceToString
	var lost_data int64 = 0
	var read_index int64 = 0
	var event bpfEventComm
	for {
		var writeIndex int64
		var round int64
		if err := objs.GlobalVarKv.Lookup(mapKey_RB, &writeIndex); err != nil {
			log.Printf("[Error] reading GlobalVarKv: %v", err)
		}
		if err := objs.GlobalVarKv.Lookup(mapKey_Round, &round); err != nil {
			log.Printf("[Error] reading GlobalVarKv: %v", err)
		}
		var item_count = round*RB_SIZE + writeIndex

		if read_index >= item_count {
			// time.Sleep(1 * time.Nanosecond)
			// log.Println("read", read_index, item_count, round)
			// read_index = item_count
			continue
		}

		// 说明writeIndex已经超过read_index一轮了
		if (item_count - read_index) > RB_SIZE {
			lost_data += item_count - read_index
			log.Println("[Wran] Ringbuffer lost data:", item_count-read_index, read_index, item_count, round, "Total:", lost_data)
			// panic("Ringbuffer lost data")
			read_index = item_count
		}

		var value string
		if err := objs.EventsRb.Lookup(int32(read_index%RB_SIZE), &value); err != nil {
			log.Printf("[Error] reading ring buffer: %v", err)
		}
		read_index++

		// Parse the event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer([]byte(value)), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		// log.Println("[LOG]", event.EventId, event.Log)

		if event.EventId == EVENT_COMM {
			data := unix.ByteSliceToString(event.Log[:])
			_, has := commMap[data]
			if !has {
				// os.WriteFile(outComm, []byte(comm+"\n"), 0666)
				outComm.WriteString(data + "\n")
				log.Println("[COMM]", data)
			}
			commMap[data] = int(event.Val)
		} else if event.EventId == EVENT_OPEN_FILE {
			// data := string(event.Log[:])
			data := unix.ByteSliceToString(event.Log[:])
			_, has := commMap[data]
			if !has {
				log.Println("[OPEN_FILE]", data)
				openSnoop.WriteString(data + "\n")
			}
			commMap[data] = int(event.Val)
		} else if event.EventId == EVENT_EXECVE {
			log.Println("[EXECVE]", string(event.Log[:]), event.Val)
			if event.Val == 1 {
				log.Println("[EXECVE MODIFIABLE]", string(event.Log[:]), event.Val)
				execSnoop.WriteString(string(event.Log[:]) + "\n")
			}
		} else if event.EventId == EVENT_SYSCALL {
			comm := unix.ByteSliceToString(event.Log[:])
			sys_info := translate_syscall(event.Val)
			if sys_info == "" {
				sys_info = fmt.Sprint(event.Val)
			}
			line := comm + "\t" + sys_info
			log.Println(line)
			// 去掉重复的
			_, has := commMap[line]
			if !has {
				syscallSnoop.WriteString(line + "\n")
			}
			commMap[line] = 1
		}
	}
}

func translate_syscall(sysid int32) string {
	fi, err := os.Open("/usr/include/x86_64-linux-gnu/asm/unistd_64.h")
	defer fi.Close()
	if err != nil {
		log.Printf("[Error] open unistd.h: %v", err)
		return ""
	}
	scanner := bufio.NewScanner(fi)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#define") && strings.HasSuffix(line, fmt.Sprint(sysid)) {
			return strings.TrimSpace(strings.TrimPrefix(line, "#define"))
		}
	}
	return ""
}
