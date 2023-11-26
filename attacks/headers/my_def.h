#pragma once

// #define BPF_NO_GLOBAL_DATA

#include "common.h"
#include <string.h>

// avoid compiling warning: -Wincompatible-library-redeclaration
#define memcmp __memcmp
#define memcpy __memcpy

// 0: equal
static __inline int __memcmp(const void* s1, const void* s2, u64 cnt){
	const char *t1 = (const char *) s1;
	const char *t2 = (const char *) s2;
	int res = 0;
	#pragma clang loop unroll(full)
	while(cnt-- > 0){
		if(*t1 > *t2){
			res =1;
			break;
		}
		else if(*t1 < *t2){
			res = -1;
			break;
		}
		else{
			t1++;
			t2++;
		}
	}
	return res;
}

static __inline void *__memcpy(void* dest, const void* src, u64 count) {
	char* pdest =(char*) dest;
	const char* psrc =(const char*) src;
	if (psrc > pdest || pdest >= psrc + count) {
		#pragma clang loop unroll(full)
		while (count--)
			*pdest++ = *psrc++;
	} else {
		#pragma clang loop unroll(full)
		while (count--) {
			*(pdest + count) = *(psrc + count);
		}
	}
	return dest;
}

static __inline void fill_space(char *str, int len) {
	#pragma clang loop unroll(full)
	while (--len >= 0) {
		if (str[len] == 0)
			str[len] = ' ';
	}
}

// __inline int string_len(char *str) {
// 	int len = 0;
// 	int pos = 20;
// 	while (--pos > 0) {
// 		if (str[len] == '\0') {
// 			break;
// 		}
// 		len++;
// 		str++;
// 	}
// 	return len;
// }

// __inline int string_append(char *dest, int off, char *str) {
// 	int len = 0;
// 	while (*str) {
// 		len++;
// 		str++;
// 	}
// 	__memcpy(dest + off, str, len);
// 	return len;
// }


#ifdef DEBUG_LOG
	#undef bpf_log
	// copy from bpf_printk
	// [SEP] is used for string split in Go
	#define bpf_log(fmt, args...) ___bpf_pick_printk(args)("[SEP]" fmt, ##args)
#else
	#define bpf_log(fmt, args...) do {} while(0);
#endif

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

typedef long long __kernel_long_t;
typedef unsigned long long __kernel_ulong_t;
struct stat {
	__kernel_ulong_t st_dev;
	__kernel_ulong_t st_ino;
	__kernel_ulong_t st_nlink;
	unsigned int st_mode;
	unsigned int st_uid;
	unsigned int st_gid;
	unsigned int __pad0;
	__kernel_ulong_t st_rdev;
	__kernel_long_t st_size;
	__kernel_long_t st_blksize;
	__kernel_long_t st_blocks;
	__kernel_ulong_t st_atime;
	__kernel_ulong_t st_atime_nsec;
	__kernel_ulong_t st_mtime;
	__kernel_ulong_t st_mtime_nsec;
	__kernel_ulong_t st_ctime;
	__kernel_ulong_t st_ctime_nsec;
	__kernel_long_t __unused[3];
};

// bpf_raw_tracepoint_args

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};


// https://raw.githubusercontent.com/iovisor/bcc/master/libbpf-tools/x86/vmlinux_505.h