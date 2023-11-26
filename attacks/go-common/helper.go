package ebpf_helper

import (
	"bufio"
	"time"

	// "bytes"
	// "encoding/binary"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func Set_memlock() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Rlimit Error: %v\n", err)
	}
	err := syscall.Setreuid(65535, -1)
	if err != nil {
		log.Printf("Setreuid: %v\n", err)
	}
}

func CHECK_ERR(err error, msg string) {
	if err != nil {
		log.Fatalf("Error Exit: %s! %v", msg, err)
	}
}

func Dump_bpf_log() {
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

func Ctrl_c_Exit() {
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

// panic会触发同一个gocrotine内的defer，所以需要和main在同一个协程
func Run_For_Ticks(timeout int) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	tick := 1
	for {
		select {
		case <-stopper:
			panic("Exit!-With Ctrl-C!")
		case <-time.NewTimer(1 * time.Second).C:
			log.Println("Tick: ", tick)
			tick += 1
			if tick > timeout {
				panic("Timeout Finish Programs")
			}
		}
	}
}
