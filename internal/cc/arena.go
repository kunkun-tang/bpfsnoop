// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"slices"

	"github.com/cilium/ebpf/asm"
)

// ArenaInfo describes the BPF arena of a traced BPF prog.
//
// Pointers stored in an arena hold addresses in the user space mapping of its
// owner, [UserStart, UserEnd). The kernel maps the same pages at
// KernStart + (u32)addr.
type ArenaInfo struct {
	UserStart uint64
	UserEnd   uint64
	KernStart uint64

	// Params are the params of the traced func that point into the arena,
	// i.e. that are tagged __arg_arena.
	Params []string
}

// isParam reports whether param name points into the arena.
func (a *ArenaInfo) isParam(name string) bool {
	return a != nil && slices.Contains(a.Params, name)
}

// ArenaTranslate returns insns that translate the arena address in reg to the
// arena's kernel mapping, which bpf_probe_read_kernel() can read. The caller
// knows reg holds an arena address by its origin, e.g. an __arg_arena param.
// NULL is kept as is. The insns use R5 as a scratch register, or R4 if reg is
// R5.
func ArenaTranslate(reg asm.Register, arena *ArenaInfo) asm.Instructions {
	if arena == nil {
		return nil
	}

	tmp := asm.R5
	if reg == asm.R5 {
		tmp = asm.R4
	}

	// Jump offsets count instruction slots, and ld_imm64 takes two.
	return asm.Instructions{
		JmpOff(asm.JEq, reg, 0, 4),
		asm.Mov.Reg32(reg, reg), // keep the arena offset, (u32)addr
		asm.LoadImm(tmp, int64(arena.KernStart), asm.DWord),
		asm.Add.Reg(reg, tmp),
	}
}

// isArenaBase reports whether val is based on a param that points into the
// arena, see ArenaInfo.Params.
func (c *compiler) isArenaBase(val exprValue) bool {
	return val.isPending() && val.varIndex >= 0 && val.varIndex < len(c.vars) && c.arena.isParam(c.vars[val.varIndex])
}

// isArenaAddr reports whether val is an address in the arena: based on an
// arena param, without a deref on the way.
func (c *compiler) isArenaAddr(val exprValue) bool {
	return c.isArenaBase(val) && !slices.ContainsFunc(val.offsets, func(o pendingOffset) bool { return o.deref })
}

// arenaOffsets marks the first deref of the offsets of an arena param to
// translate its address. A pointer loaded from the arena isn't translated, as
// its origin isn't known: it may as well be a kernel pointer.
func arenaOffsets(offsets []pendingOffset) []pendingOffset {
	i := slices.IndexFunc(offsets, func(o pendingOffset) bool { return o.deref })
	if i == -1 {
		return offsets
	}

	offsets = slices.Clone(offsets)
	offsets[i].arena = true
	return offsets
}
