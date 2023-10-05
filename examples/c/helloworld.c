// helloworld.c

#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "helloworld.skel.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct helloworld_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = helloworld_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }   

    /* my addition: ensure BPF program only handles write() syscalls from our process */
    skel->bss->my_pid = getpid();

    /* Load & verify BPF programs */
    err = helloworld_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = helloworld_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    for (;;) {
        /* trigger our BPF program */
        fprintf(stderr, ".");
        sleep(1);

        
        // int status;
        // char *args[2];
        // args[0] = "/bin/ls";        // first arg is the full path to the executable
        // args[1] = NULL; 
        // if ( fork() == 0 )
        //     execv( args[0], args ); // child: call execv with the path and the args
        // else
        //     wait( &status );
    }

cleanup:
    helloworld_bpf__destroy(skel);
    return -err;
}