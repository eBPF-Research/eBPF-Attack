package ebpf_helper

import (
	"log"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// 模仿 data-dog ebpf/manager 和 ehis库来实现一个简单的eBPF声明周期管理
// https://github.com/cilium/ebpf/blob/master/examples/kprobe/main.go

type EbpfManger struct {
	// Objs  interface{}
	links map[string][]link.Link
}

func InitManger() *EbpfManger {
	m := EbpfManger{}
	// m.Objs = objs
	m.links = make(map[string][]link.Link)

	// output trace-pipe
	go Dump_bpf_log()

	//
	Set_memlock()

	return &m
}

func (m *EbpfManger) AddHook(hook string, prog *ebpf.Program) {
	items := strings.Split(hook, "/")
	subsys := items[0]
	var link_1 link.Link
	var err error
	switch subsys {
	case "raw_tracepoint":
		{
			if len(items) != 2 {
				log.Fatal("Uncorrent hook path: raw_tracepoint/sys_*")
			}
			link_1, err = link.AttachRawTracepoint(link.RawTracepointOptions{
				Name:    items[1],
				Program: prog,
			})
			CHECK_ERR(err, "Failed to attach RawTracepoint: "+strings.Join(items[1:], "/"))
			break
		}

	case "tp":
		{
			if len(items) != 3 {
				log.Fatal("Uncorrent hook path: tp/systemcalls/sys_*")
			}
			link_1, err = link.Tracepoint(items[1], items[2], prog)
			CHECK_ERR(err, "Failed to attach RawTracepoint: "+strings.Join(items[1:], "/"))
			break
		}

	case "kretprobe":
		{
			if len(items) != 2 {
				log.Fatal("Uncorrent hook path: kretprobe/sys_*")
			}
			link_1, err = link.Kretprobe(items[1], prog)
			CHECK_ERR(err, "Failed to attach Kretprobe: "+strings.Join(items[1:], "/"))
		}
	default:
		{
			return
		}
	}

	if link_1 != nil {
		// m.links = append(m.links, link_1)
		// _, has := m.links[hook]
		// if !has {
		// 	m.links[hook] = make([]link.Link, 1)
		// }
		m.links[hook] = append(m.links[hook], link_1)
	}
}

func (m *EbpfManger) Uninstall() {
	// m.Objs.Close()
	log.Println("Uninstall Hooks")
	for hook, links := range m.links {
		log.Println("Uninstall links for hook:" + hook)
		for i, link := range links {
			log.Printf("\tUninstall link: %d\n", i)
			link.Close()
		}
	}
}
