//go:build linux
// +build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event_comm bpf sys_hook.ebpf.c -- -I../../headers

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
)

const Ti = 600

func main() {
	log.Printf("hello eBPF!\n")
	ctrl_c_Exit()
	go dump_bpf_log()

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
	CHECK_ERR(err, "sys_enter attach failed")
	defer link_1.Close()

	link_2, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: objs.RawTpSysExit,
	})
	CHECK_ERR(err, "sys_exit attach failed")
	defer link_2.Close()

	// 收集进程信息
	go trace_events(objs)

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

func CHECK_ERR(err error, msg string) {
	if err != nil {
		log.Fatalf("Error Exit: %s! %v", msg, err)
	}
}

func dump_bpf_log() {
	logFile, err := os.OpenFile("start_log.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)
	log.Println("Start to read trace_pipe:")

	const trace_pipe = "/sys/kernel/debug/tracing/trace_pipe"
	fd, err := os.Open(trace_pipe)
	if err != nil {
		// log.Fatalf("Failed to open trace_pipe: %v", trace_pipe)
		log.Printf("Error: Failed to open trace_pipe: %v\n", trace_pipe)
		return
	}

	buf := bufio.NewReader(fd)
	for {
		line, _, err := buf.ReadLine()
		if err != nil {
			log.Fatalf("Failed to read from trace_pipe: %v", err)
			return
		}
		log_buf := strings.Split(string(line), "[SEP]")
		log.Printf("[LOG] %v", log_buf[len(log_buf)-1])
		log.Printf("[LOG] %s", string(line))
	}
}

func ctrl_c_Exit() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		// 为了确保defer能执行，ebpf能正常dettach，不能直接exit
		// os.Exit(0)
		panic("Exit!-With Ctrl-C!")
		// runtime.Goexit()
	}()
}

const RB_SIZE = 256
const (
	EVENT_LOG = 0
)

func trace_events(objs bpfObjects) {
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

		// log.Println("read", read_index, item_count, round, writeIndex)
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

		if event.EventId == EVENT_LOG {
			data := string(event.Log[:])
			_, has := commMap[data]
			if !has {

			}
			commMap[data] = int(event.Val)
			log.Println("[EVENT-Log]", data, event.Val)
		}

	}
}
