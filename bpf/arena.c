// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

/* The fields of struct bpf_arena to read. It's private to kernel/bpf/arena.c,
 * but in kernel BTF. The flavor suffix keeps it apart from vmlinux.h, which
 * lacks it before kernel 6.9.
 */
struct bpf_arena___bpfsnoop {
    struct bpf_map map;
    __u64 user_vm_start;
    __u64 user_vm_end;
    struct vm_struct *kern_vm;
} __attribute__((preserve_access_index));

/* Keep in sync with arenaVM in internal/bpfsnoop/arena.go. */
struct arena_vm {
    __u64 user_vm_start;
    __u64 user_vm_end;
    __u64 kern_vm_addr;
};

volatile const __u32 target_map_id;

SEC("iter/bpf_map")
int arena_vm(struct bpf_iter__bpf_map *ctx)
{
    struct bpf_arena___bpfsnoop *arena;
    struct bpf_map *map = ctx->map;
    struct arena_vm vm;

    if (!map || map->id != target_map_id)
        return 0;

    arena = (void *) map - bpf_core_field_offset(struct bpf_arena___bpfsnoop, map);
    vm.user_vm_start = BPF_CORE_READ(arena, user_vm_start);
    vm.user_vm_end = BPF_CORE_READ(arena, user_vm_end);
    vm.kern_vm_addr = (__u64) BPF_CORE_READ(arena, kern_vm, addr);
    bpf_seq_write(ctx->meta->seq, &vm, sizeof(vm));

    return 0;
}

char __license[] SEC("license") = "GPL";
