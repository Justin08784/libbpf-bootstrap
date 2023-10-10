// looptests.bpf.c 

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Globals */
int my_pid = 0;

/* Static Types/Variables */
enum LOOP_TYPE {
    NO_LOOP,
    BOUNDED_LOOP,
    INFINITE_LOOP,
    CUSTOM1,
    CUSTOM2,
    CUSTOM3, 
    CUSTOM4
};
static int test_type = NO_LOOP; 

/*
Interestingly, an error is thrown is test_type is not static. 
In ebpf <or just libbpf-bootstrap?>, if a variable declared in the epbf program 
is not static, then it is a global visible to the user program.

ebpf globals are added by libbpf <?> as fields to the ebpf program struct in
the auto-generated skel.h header. (Try removing static from int test_type and
compiling; a new "int test_type" field will appear in the struct. This is also 
why there is a my_pid field in the struct.)

I think the verifier complains if test_type is not static because this means that
the user program, with test_type being accessible via skel->bss->test_type, might
edit test_type to INFINITE_LOOP, which triggers an infinite loop. Simply put,
the verifier is guarding against possible malicious behavior by the user program.
*/


/* SEC(...) must be done after any global declarations */
SEC("tracepoint/syscalls/sys_enter_write") // trigger on any system write

void custom1_infinite_loop()
{
    for (int i = 0; i < i + 1; i++) {}
}

void custom2_infinite_loop()
{
    for (int i = 0; i < 5;) {}
}

void custom3_bounded_loop()
{
    /* An attempt of using a condition based on arithmetic
    to confuse the verifier into thinking an infinite loop may execute. 
    
    Tests if the verifier is conservative and bans anything that seems 
    suspiciously loopy. */
    int x = 3;
    int y = x + x - x;
    y = ((x + 1) * (x + 1) - x * x - 1) / 2;
    // find some computationally expensive operation to set y
    if (x == y) {
        return;
    } else {
        // should never execute
        for (;;) {}
    }
    return;
}

void custom4_empty_body_loop()
{
    /* An infinite loop with an empty body. This executes without problem,
    strangely. */
    for (;;) {}
}

int bpf_prog(void *ctx) 
{   
    int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
        /* ignore writes not from a running looptests.c */
		return 0;

    char msg[] = "Hello, World!";

    switch (test_type) {
        case NO_LOOP: {
            /* should pass */
            bpf_printk("invoke bpf_prog: %s\n", msg);
            return 0;
        }
        case BOUNDED_LOOP: {
            /* should pass */
            for (int i = 0; i < 4; i++)
                bpf_printk("invoke bpf_prog: %s\n", msg);
            return 0;
        }
        case INFINITE_LOOP: {
            /* should fail */
            for (;;)
                bpf_printk("invoke bpf_prog: %s\n", msg);
            return 0;
        }
        case CUSTOM1:
            custom1_infinite_loop();
            break;
        case CUSTOM2:
            custom2_infinite_loop();
            break;
        case CUSTOM3:
            custom3_bounded_loop();
            break;
        case CUSTOM4:
            custom4_empty_body_loop();
            break;
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";