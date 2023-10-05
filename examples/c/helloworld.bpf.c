// helloworld.bpf.c 

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Globals */
int my_pid = 0;

/* SEC(...) must be done after any global declarations */
SEC("tracepoint/syscalls/sys_enter_write") // trigger on any system write

int bpf_prog(void *ctx) 
{   
    int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
        /* ignore writes not from a running helloworld.c */
		return 0;


    char msg[] = "Hello, World!";
    bpf_printk("invoke bpf_prog: %s\n", msg);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";