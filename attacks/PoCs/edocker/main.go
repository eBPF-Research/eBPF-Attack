//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"syscall"
	"time"
	// "github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf leak.c -- -I../../headers

//const mapKey uint32 = 0

func main() {

	err := syscall.Setreuid(65535, -1)
	if err != nil {
		log.Fatalf("Setreuid: %v", err)
	}

	// Name of the kernel function to trace.
	fn := "sys_enter"

	// Allow the current process to lock memory for eBPF resources.
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
	//count := 0

	log.Println("Waiting for events..")
	const mapKey uint32 = 0
	const mapKey_execve uint32 = 1
	const mapKey_read uint32 = 2
	const mapKey_write uint32 = 3
	for range ticker.C {
		// count += 1
		// if count == 60 {
		// 	return
		// }
		var value string
		var value_execve string
		var value_read string
		var value_write string
		if err := objs.RawTracepointMap2.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		if err := objs.RawTracepointMap2.Lookup(mapKey_execve, &value_execve); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		if err := objs.RawTracepointMap2.Lookup(mapKey_read, &value_read); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		if err := objs.RawTracepointMap2.Lookup(mapKey_write, &value_write); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		time.Sleep(1)
		log.Printf("BIN: %s", value_execve)
		log.Printf("docker OPENAT: %s", value)
		log.Printf("\n\033[32m docker READ: \033[0m\n%s\n", value_read)
		log.Printf("\n\033[36m docker WRITE: \033[0m\n%s\n", value_write)
	}
}
