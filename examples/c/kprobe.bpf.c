// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// SEC("kprobe/handle_mm_fault")
// int BPF_KPROBE(handle_mm_fault, struct vm_area_struct *vma, unsigned long address, unsigned int flags, struct pt_regs *regs)
// {
// 	pid_t pid;
// 	const char *filename;
// 
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	// filename = BPF_CORE_READ(name, name);
// 	// bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
// 	bpf_printk("KPROBE ENTRY pid = %d, address = %lx, flags = %d\n", pid, address, flags);
// 	return 0;
// }

// SEC("kprobe/__handle_mm_fault")
// int BPF_KPROBE(__handle_mm_fault, struct vm_area_struct *vma, unsigned long address, unsigned int flags)
// {
// 	pid_t pid;
// 	const char *filename;
// 
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	// filename = BPF_CORE_READ(name, name);
// 	// bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
// 	bpf_printk("KPROBE ENTRY pid = %d, address = %lx, flags = %d\n", pid, address, flags);
// 	return 0;
// }

// SEC("kprobe/do_swap_page")
// int BPF_KPROBE(do_swap_page, struct vm_fault *vmf)
// {
// 	pid_t pid;
// 	const char *filename;
// 
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	bpf_printk("KPROBE ENTRY pid = %d, p = %lx", pid, vmf);
// 	return 0;
// }

// SEC("kprobe/wakeup_kswapd")
// int BPF_KPROBE(wakeup_kswapd, struct zone *zone, gfp_t gfp_flags, int order,
// 		   enum zone_type highest_zoneidx)
// {
// 	static int i = 0;
// 	if (i++ > 100)
// 		return 0;
// 	pid_t pid;
// 	const char *filename;
// 
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	struct zone *zone_ptr = (struct zone *)PT_REGS_PARM1(ctx);
// 	gfp_t gfp_flags_val = (gfp_t)PT_REGS_PARM2(ctx);
// 	int order_val = (int)PT_REGS_PARM3(ctx);
// 	enum zone_type highest_zoneidx_val = (enum zone_type)PT_REGS_PARM4(ctx);
// 
// 	// bpf_printk("0KPROBE ENTRY pid = %d, zone = %x, gfp_flags = %x",
// 	//     pid, zone_ptr, gfp_flags_val);
// 	// bpf_printk("1KPROBE ENTRY pid = %d, order = %d, zone_type = %d",
// 	//     pid, order_val, highest_zoneidx_val);
// 
// 	pg_data_t *pgdat = BPF_CORE_READ(zone, zone_pgdat);
// 	bpf_printk("2KPROBE ENTRY pid = %d, present = %lu, spanned = %lu",
// 	    pid, BPF_CORE_READ(pgdat, node_present_pages), BPF_CORE_READ(pgdat, node_spanned_pages));
// 
// 
// 	return 0;
// }

SEC("kprobe/shrink_page_list")
//unsigned long page_addr[100];
int BPF_KPROBE(shrink_page_list, struct list_head *page_list,
               struct pglist_data *pgdat, struct scan_control *sc,
               struct reclaim_stat *stat, bool ignore_references)
{
    struct list_head *pos = page_list;
	static call_num = 0;
    struct page *page;
	size_t iter_limit = 100;
	size_t i = 0;

    // Iterate over the list manually
    while ((pos != NULL) && (i++ < iter_limit)) {
        // Retrieve the 'page' structure from the 'list_head' pointer using BPF_CORE_READ
        page = (struct page *)((char *)pos - offsetof(struct page, lru));

        // Safely read fields from the struct page
        unsigned long flags = BPF_CORE_READ(page, flags);
        int refcount = BPF_CORE_READ(page, _refcount.counter);
        int mapcount = BPF_CORE_READ(page, _mapcount.counter);

        // Log details about the page
        // bpf_printk("Reclaiming page: addr=%lx, flags=%lx, refcount=%d, mapcount=%d",
        //            (unsigned long)page, flags, refcount, mapcount);
        bpf_printk("(%d) Reclaiming page: addr=%lx",
                   call_num, (unsigned long)page);

        // Move to the next element in the list
        pos = BPF_CORE_READ(pos, next);

        // // If we reach the start of the list again, break to avoid an infinite loop
        // if (pos == page_list)
        //     break;
    }
	bpf_printk("(%d) Num reps: %d", call_num++, i);
    return 0;
}

// SEC("kretprobe/do_page_fault")
// int BPF_KRETPROBE(do_page_fault_exit, long ret)
// {
// 	pid_t pid;
// 
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
// 	return 0;
// }
