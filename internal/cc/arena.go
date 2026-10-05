// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import "github.com/cilium/ebpf/asm"

// ArenaInfo describes the BPF arena of a traced BPF prog.
//
// Pointers stored in an arena hold addresses in the user space mapping of its
// owner, [UserStart, UserEnd). The kernel maps the same pages at
// KernStart + (u32)addr.
type ArenaInfo struct {
	UserStart uint64
	UserEnd   uint64
	KernStart uint64
}

// ArenaTranslate returns insns that translate the address in reg, if it's in
// the arena's user range, to the arena's kernel mapping, which
// bpf_probe_read_kernel() can read. Other addresses, like kernel pointers,
// are left as is. The insns use R5 as a scratch register, or R4 if reg is R5.
func ArenaTranslate(reg asm.Register, arena *ArenaInfo) asm.Instructions {
	if arena == nil {
		return nil
	}

	tmp := asm.R5
	if reg == asm.R5 {
		tmp = asm.R4
	}

	// Compare reg with the range instead of subtracting UserStart from it:
	// reg may hold a pointer, which the verifier allows to compare, but not
	// to offset by a scalar this large. Jump offsets count instruction
	// slots, and ld_imm64 takes two.
	return asm.Instructions{
		asm.LoadImm(tmp, int64(arena.UserStart), asm.DWord),
		JmpReg(asm.JLT, reg, tmp, 7),
		asm.LoadImm(tmp, int64(arena.UserEnd), asm.DWord),
		JmpReg(asm.JGE, reg, tmp, 4),
		asm.Mov.Reg32(reg, reg), // keep the arena offset, (u32)addr
		asm.LoadImm(tmp, int64(arena.KernStart), asm.DWord),
		asm.Add.Reg(reg, tmp),
	}
}
