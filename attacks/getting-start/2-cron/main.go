//go:build linux
// +build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf sys_hook.ebpf.c -- -I../../headers

package main

import (
	"bufio"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const Ti = 120

func main() {
	log.Printf("hello eBPF!\n")
	ctrl_c_Exit()
	go dump_bpf_log()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

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

	ticker := time.NewTicker(1 * time.Second)
	count := 0
	for range ticker.C {
		count += 1
		if count == Ti {
			return
		}
		// log.Println("Tick: ", count, value, ret)
		time.Sleep(time.Microsecond)
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
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)
	log.Println("Start to read trace_pipe:")

	const trace_pipe = "/sys/kernel/debug/tracing/trace_pipe"
	fd, err := os.Open(trace_pipe)
	if err != nil {
		log.Printf("Failed to open trace_pipe: %v\n", trace_pipe)
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
		// log.Printf("[LOG] %s", string(line))
	}
}

func ctrl_c_Exit() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		// os.Exit(0) // defer is not executed
		panic("Exit!-With Ctrl-C!")
		// runtime.Goexit()
	}()
}
