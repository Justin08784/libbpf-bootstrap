// trigger_by_exec.bpf.c 

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Globals */
int curr_child_pid = 0;

SEC("tracepoint/syscalls/sys_enter_execve") // trigger on any system execve

int bpf_prog(void *ctx) 
{   
    int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != curr_child_pid)
        /* ignore writes not from a child of a running trigger_by_exec.c */
		return 0;

    char msg[] = "Hello, World!";
    bpf_printk("invoke bpf_prog: %s\n", msg);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";