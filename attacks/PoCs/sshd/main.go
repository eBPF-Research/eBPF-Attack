//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"github.com/cilium/ebpf/link"
	// "github.com/cilium/ebpf/rlimit"
	"log"
	"syscall"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf sshd.c -- -I../../headers

//const mapKey uint32 = 0

const Ti = 600

func main() {
	err := syscall.Setreuid(65535, -1)
	if err != nil {
		log.Fatalf("Setreuid: %v", err)
	}
	// Name of the kernel function to trace.
	fn := "sys_enter"

	// // Allow the current process to lock memory for eBPF resources.
	// if err := rlimit.RemoveMemlock(); err != nil {
	// 	log.Fatal(err)
	// }

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	link_1, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    fn,
		Program: objs.RawTpSysEnter,
	},
	)
	if err != nil {
		log.Fatalf(("attach faield"))
	}
	defer link_1.Close()

	link_2, err_2 := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: objs.RawTpSysExit,
	},
	)
	if err_2 != nil {
		log.Fatalf(("attach faield"))
	}
	defer link_2.Close()

	// fn_2 := "sys_exit"
	// link_2, err_2 := link.AttachRawTracepoint(link.RawTracepointOptions{
	// 	Name:    fn_2,
	// 	Program: objs.RawTpSysExit,
	// })
	// if err_2 != nil {
	// 	log.Fatalf(("attach faield"))
	// }
	// defer link_2.Close()

	ticker := time.NewTicker(1 * time.Second)

	//log.Println("Waiting for events..")
	count := 0
	for range ticker.C {
		time.Sleep(1)
		count += 1
		if count == Ti {
			return
		}
		log.Printf("%d", count)
	}
}
