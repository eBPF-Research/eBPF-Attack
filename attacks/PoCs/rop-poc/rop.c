/* cat hello.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "hello.skel.h"

//#define DEBUGFS "/sys/kernel/debug/tracing/"

/* logging function used for debugging */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}
// /* read trace logs from debug fs */
// void read_trace_pipe(void)
// {
//     int trace_fd;

//     trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
//     if (trace_fd < 0)
//         return;

//     while (1) {
//         static char buf[4096];
//         ssize_t sz;

//         sz = read(trace_fd, buf, sizeof(buf) - 1);
//         if (sz> 0) {
//             buf[sz] = 0;
//             puts(buf);
//         }
//     }
// }

/* set rlimit (required for every app) */
static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur	= RLIM_INFINITY,
        .rlim_max	= RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}
static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

int main(int argc, char **argv)
{

    int ret;
    if ((ret=setreuid(65535, -1)) != 0)
    {
         printf("setreuid failed: %d\n", ret);
         return 0;
     }
    struct hello_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    //bump_memlock_rlimit();

    /* Open BPF application */
    skel = hello_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = hello_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = hello_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

    printf("Hello BPF started, hit Ctrl+C to stop!\n");

    while (!stop) {
		fprintf(stderr, ".");
		sleep(1);
	}

    //read_trace_pipe();

cleanup:
    hello_bpf__destroy(skel);
    return -err;
}
