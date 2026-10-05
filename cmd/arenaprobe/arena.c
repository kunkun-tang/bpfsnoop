// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Leon Hwang */

//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

/* A BPF arena is memory shared by a BPF program and user space, allocated in
 * pages. Unlike a map, it has no keys or values: it's plain memory, so both
 * sides can build data structures in it with real pointers.
 *
 * The user-space side mmaps it. A pointer stored in the arena holds the user
 * address of its target, so user space can follow it as is. The kernel maps
 * the same pages at its own address, and the JIT translates arena pointers in
 * BPF code to it.
 *
 * Here arenaprobe mmaps the arena and builds a two-node list in it, then runs
 * arena_main, which passes the head to arena_probe and arena_probe_val for
 * bpfsnoop to trace.
 */
struct {
    __uint(type, 33 /* BPF_MAP_TYPE_ARENA, may be absent from older vmlinux.h */);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 1); /* pages */
} arena SEC(".maps");

/* A pointer into the arena, address space 1 for the compiler. */
#define __arena __attribute__((address_space(1)))
/* Tells the verifier, and bpfsnoop through BTF, that an argument of a global
 * function points into the arena.
 */
#define __arg_arena __attribute((btf_decl_tag("arg:arena")))

/* Keep in sync with main.go. */
struct arena_node {
    int val;
    char name[12];
    struct arena_node __arena *next;
    struct task_struct *task; /* a kernel pointer, stored in the arena */
};

/* The user address of the first node, set by arenaprobe before loading. */
volatile const __u64 head;

/* Traced by the arena tests. Global, so the verifier checks it on its own and
 * honors the arg:arena tag.
 */
__noinline int arena_probe(struct arena_node __arena *n __arg_arena)
{
    return n != NULL;
}

/* Like arena_probe, with a number pointer, whose pointee bpfsnoop prints. */
__noinline int arena_probe_val(int __arena *val __arg_arena)
{
    return val != NULL;
}

SEC("xdp")
int arena_main(struct xdp_md *ctx)
{
    int ret;

    /* Associate the arena with this program: a program can use one arena,
     * and it must reference the arena map.
     */
    asm volatile("" :: "r"(&arena));

    ret = arena_probe((struct arena_node __arena *) head);
    asm volatile("" :: "r"(ret));
    ret = arena_probe_val((int __arena *) head);
    asm volatile("" :: "r"(ret));

    /* Refer to a member of struct task_struct, so its BTF is complete instead
     * of a forward declaration, and bpfsnoop can follow node->task.
     */
    asm volatile("" :: "r"(bpf_core_field_offset(struct task_struct, comm)));

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
