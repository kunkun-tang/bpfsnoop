// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Liang Tang */

#ifndef __BPFSNOOP_ARENA_H_
#define __BPFSNOOP_ARENA_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

#include "bpfsnoop.h"

/* The fields of struct bpf_arena that bpfsnoop reads. Older vmlinux.h lack the
 * struct, and CO-RE relocates the fields for the running kernel.
 */
struct bpf_arena___bpfsnoop {
    __u64 user_vm_start;
    struct vm_struct *kern_vm;
} __attribute__((preserve_access_index));

/* bpfsnoop_arena_addr returns the kernel address of the arena address addr,
 * which bpf_probe_read_kernel() can read. NULL stays NULL.
 *
 * Pointers into an arena hold addresses in the user space mapping of its
 * owner. The kernel maps the page of user address addr at
 *
 *     kern_vm->addr + GUARD_SZ / 2 + (u32) addr
 *
 * see arena_vm_fault(). GUARD_SZ depends on the page size, so bpfsnoop passes
 * GUARD_SZ / 2 as guard_half. arena is the map pointer of the arena, through
 * which the verifier lets read its struct bpf_arena.
 */
__stub __u64
bpfsnoop_arena_addr(struct bpf_arena___bpfsnoop *arena, __u64 addr, __u32 guard_half)
{
    if (!addr)
        return 0;

    return (__u64) arena->kern_vm->addr + guard_half + (__u32) addr;
}

#endif // __BPFSNOOP_ARENA_H_
