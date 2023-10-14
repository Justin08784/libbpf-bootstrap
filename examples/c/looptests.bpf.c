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
    CUSTOM4,
    CUSTOM5,
    CUSTOM6,
    CUSTOM7,
    CUSTOM8,
    CUSTOM9
};
const static int test_type = CUSTOM9; 

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
        case CUSTOM1: {
            for (int i = 0; i < i + 1; i++) {
                bpf_printk("invoke bpf_prog: %s\n", msg);
            }
            break;
        }
        case CUSTOM2: {
            for (int i = 0; i < 5;) {
                bpf_printk("invoke bpf_prog: %s\n", msg);
            }
            break;
        }
        case CUSTOM3: {
            /* An attempt of using a condition based on arithmetic
            to confuse the verifier into thinking an infinite loop may execute. */
            int x = 3;
            int y = x + x - x;
            y = ((x + 1) * (x + 1) - x * x - 1) / 2;
            // find some computationally expensive operation to set y
            if (x == y) {
                break;
            } else {
                // should never execute
                for (;;)
                    bpf_printk("invoke bpf_prog: %s\n", msg);
            }
            break;
        }
        case CUSTOM4: {
            /* An infinite loop with an empty body. 
            Fails as expected */
            for (;;) {}
            break;
        }
        case CUSTOM5: {
            //C1: Loop will not execute due to floating-point errors
            double x = 0.1;
            double y = ((x + 1) * (x + 1) - x * x - 1) / 2;
            if (x == y) { 
                for (;;) {}
            } 
            break;
        }
        case CUSTOM6: {
            //C2: Loop will  execute
            double x = 0.1;
            double y = ((x + 1) * (x + 1) - x * x - 1) / 2;
            if (x != y) { 
                for (;;) {}
            }
            break;
        }
        case CUSTOM7: {
            // deadcode
            if (0) {
                int x = 2;
                bpf_printk("This print should not execute. %d\n", x);

                for (;;) {}
            }


            bpf_printk("invoke bpf_prog: %s\n", msg);
            break;
        }

        case CUSTOM8: {
            // nested loops
            int nest_factor = 2;

            for (int i1 = 0; i1 < nest_factor; ++i1)
                for (int i2 = 0; i2 < nest_factor; ++i2)
                    for (int i3 = 0; i3 < nest_factor; ++i3)
                        for (int i4 = 0; i4 < nest_factor; ++i4)
                            for (int i5 = 0; i5 < nest_factor; ++i5) 
                                bpf_printk("Hi\n");
            break;
        }

        case CUSTOM9: {
            // An infinite print of an ascending value
            /*
            The verifier does not immediately detect the infinite loop,
            for some reason?

            It runs for 10 seconds before printing:

            BPF program is too large. Processed 1000001 insn
            processed 1000001 insns (limit 1000000) max_states_per_insn 4 total_states 16668 peak_states 16668 mark_read 1
            -- END PROG LOAD LOG --
            libbpf: prog 'bpf_prog': failed to load: -7
            libbpf: failed to load object 'looptests_bpf'
            libbpf: failed to load BPF skeleton 'looptes
            */

            for (int i = 0; ; ++i) 
                bpf_printk("%d\n", i);

            /* the result is equivalent for... */
            // for (int i = 0; ; ++i)
            //     bpf_printk("Hi\n", i);
            break;
        }

    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";