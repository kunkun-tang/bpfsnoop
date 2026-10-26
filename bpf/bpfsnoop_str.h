// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Liang Tang */

#ifndef __BPFSNOOP_STR_H_
#define __BPFSNOOP_STR_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

#include "bpfsnoop_cfg.h"

/* The most bytes of a string compared with a literal, with its NUL. A literal
 * takes this many bytes in .rodata.strlit, with its NUL and zero padding.
 *
 * The string is read to the stack of bpfsnoop_str_eq(), which adds to the
 * stacks of the prog and of the stub calling it: the kernel limits them to 512
 * bytes together, and older kernels round each up to 32 bytes.
 */
#define BPFSNOOP_STRLIT_SIZE 128

/* The string literals that str() is compared with, and their lengths with the
 * NUL. bpfsnoop sizes and fills them when loading the prog.
 */
const volatile char bpfsnoop_strlit[1] SEC(".rodata.strlit");
const volatile __u32 bpfsnoop_strlit_len[1] SEC(".rodata.strlit.length");

/* bpfsnoop_str_eq reports whether the string at src, of at most size bytes with
 * its NUL, equals string literal idx. The insns of 'str(x) == "..."' call it.
 *
 * The string is read once, and its length tells most differences. Then it's
 * compared with bpf_strncmp(), or 8 bytes at a time without it. A NULL or
 * unreadable string equals no literal.
 *
 * No C code calls it, so it's in a section of its own, which keeps it in the
 * bpf obj: bpfsnoop adds it to the progs whose insns call it.
 */
SEC(".text.bpfsnoop_str_eq") static __noinline bool
bpfsnoop_str_eq(const void *src, __u32 size, __u32 idx)
{
    const volatile __u32 *lens = bpfsnoop_strlit_len;
    const volatile char *lits = bpfsnoop_strlit;
    char s[BPFSNOOP_STRLIT_SIZE] __attribute__((aligned(8)));

    /* The arrays are resized when loading: hide their size from the
     * compiler, which would take idx for 0 otherwise.
     */
    barrier_var(lens);
    barrier_var(lits);

    const volatile char *lit = lits + idx * BPFSNOOP_STRLIT_SIZE;
    __u32 len = lens[idx];

    if (len == 0 || len > sizeof(s))
        return false;
    if (size > sizeof(s))
        size = sizeof(s);

    /* bpf_probe_read_kernel_str() leaves the bytes after the NUL as they are.
     * Zero the last 8 bytes to compare, which hold the NUL, first.
     */
    *(__u64 *) &s[(len - 1) & ~7] = 0;

    if (bpf_probe_read_kernel_str(s, size, src) != len)
        return false;

    /* has_strncmp tells whether the kernel has bpf_strncmp(), since 5.17: the
     * verifier drops the code of the other case. The literal must be at a
     * constant offset in .rodata.strlit: idx is a constant in the insns
     * calling this func.
     */
    if (cfg->flags.has_strncmp)
        return bpf_strncmp(s, sizeof(s), (const char *) lit) == 0;

    for (__u32 i = 0; i < len; i += 8) {
        if (*(__u64 *) &s[i] != *(const volatile __u64 *) &lit[i])
            return false;
    }

    return true;
}

#endif // __BPFSNOOP_STR_H_
