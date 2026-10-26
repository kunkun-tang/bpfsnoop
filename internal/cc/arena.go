// Copyright 2026 Liang Tang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"
	"os"
	"slices"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"

	"github.com/bpfsnoop/bpfsnoop/internal/mathx"
)

// arenaMaxSize is the most bytes of an arena that arena() covers, and its
// default size.
const arenaMaxSize = 4096

// arenaGuardSize is GUARD_SZ in kernel/bpf/arena.c. The kernel maps an arena
// at kern_vm->addr + GUARD_SZ/2, which bpf_arena_get_kern_vm_start() returns.
func arenaGuardSize(pageSize int) int {
	return mathx.Align(1<<16, 2*pageSize)
}

// arenaOffsets are the offsets of the fields of struct bpf_arena and struct
// vm_struct that locate the kernel mapping of an arena.
type arenaOffsets struct {
	userVMStart int16 // struct bpf_arena, user_vm_start
	kernVM      int16 // struct bpf_arena, kern_vm
	vmAddr      int16 // struct vm_struct, addr
}

func arenaStructOffsets(krnl btfSpecer) (arenaOffsets, error) {
	var offs arenaOffsets

	offset := func(structName, member string) (int16, error) {
		typ, err := krnl.AnyTypeByName(structName)
		if err != nil {
			return 0, fmt.Errorf("failed to find struct %s: %w", structName, err)
		}
		strct, ok := typ.(*btf.Struct)
		if !ok {
			return 0, fmt.Errorf("%s is not a struct", structName)
		}
		off, err := mybtf.StructMemberOffset(strct, member)
		if err != nil {
			return 0, fmt.Errorf("failed to find %s of struct %s: %w", member, structName, err)
		}
		return int16(off), nil
	}

	var err error
	if offs.userVMStart, err = offset("bpf_arena", "user_vm_start"); err != nil {
		return offs, err
	}
	if offs.kernVM, err = offset("bpf_arena", "kern_vm"); err != nil {
		return offs, err
	}
	if offs.vmAddr, err = offset("vm_struct", "addr"); err != nil {
		return offs, err
	}
	return offs, nil
}

// evaluateArenaCall evaluates arena(<map>, [<size>, [<offset>]]) to the <size>
// bytes of the arena at <offset>, as a u8 array at their kernel address.
//
// Pointers into an arena hold addresses in its user space mapping, which
// bpf_probe_read_kernel() can't read. But the kernel maps the page of user
// address addr at kern_vm_start + (u32)addr, see arena_vm_fault(). Read
// user_vm_start and kern_vm of the arena's struct bpf_arena at run time,
// through the map pointer, which the verifier checks against kernel BTF.
func (c *compiler) evaluateArenaCall(expr *cc.Expr) (exprValue, error) {
	mapID, err := expr2mapID(expr)
	if err != nil {
		return exprValue{}, err
	}

	size := int64(arenaMaxSize)
	if len(expr.List) >= 2 {
		size, err = parseExprNumber(expr.List[1])
		if err != nil {
			return exprValue{}, fmt.Errorf("%s() size must be a number: %w", arenaFn, err)
		}
		if size <= 0 || size > arenaMaxSize {
			return exprValue{}, fmt.Errorf("%s() size must be in (0, %d]", arenaFn, arenaMaxSize)
		}
	}
	var offset int64
	if len(expr.List) == 3 {
		offset, err = parseExprNumber(expr.List[2])
		if err != nil {
			return exprValue{}, fmt.Errorf("%s() offset must be a number: %w", arenaFn, err)
		}
	}

	m, ok := c.maps[mapID]
	if !ok {
		return exprValue{}, fmt.Errorf("%s(%s): map has not been opened", arenaFn, mapID)
	}
	if m.Type != ebpf.Arena {
		return exprValue{}, fmt.Errorf("%s(%s): map is not an arena but %s", arenaFn, mapID, m.Type)
	}

	pageSize := os.Getpagesize()
	arenaSize := int64(m.MaxEntries) * int64(pageSize)
	if offset < 0 || offset > arenaSize-size {
		return exprValue{}, fmt.Errorf("%s(%s): %d bytes at offset %d are out of the arena of %d bytes",
			arenaFn, mapID, size, offset, arenaSize)
	}

	offs, err := arenaStructOffsets(c.krnlSpec)
	if err != nil {
		return exprValue{}, fmt.Errorf("%s(%s): %w", arenaFn, mapID, err)
	}

	reg, err := c.regalloc.Alloc()
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to allocate register for %s(): %w", arenaFn, err)
	}
	tmp, err := c.regalloc.Alloc()
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to allocate register for %s(): %w", arenaFn, err)
	}
	defer c.regalloc.Free(tmp)

	// Equivalent pseudo C code:
	//
	// struct bpf_arena *arena = map_ptr;
	// u64 user_vm_start = arena->user_vm_start;
	// struct vm_struct *kern_vm = arena->kern_vm;
	// if (!kern_vm)
	//     goto exit;
	//
	// u8 *addr = kern_vm->addr;
	// addr += (u32)(user_vm_start + offset);
	// addr += arena_guard_size(page_size) / 2;
	c.emit(
		asm.LoadMapPtr(reg, m.FD), // the arena's struct bpf_arena
		asm.LoadMem(tmp, reg, offs.userVMStart, asm.DWord),
		asm.LoadMem(reg, reg, offs.kernVM, asm.DWord),
		asm.JEq.Imm(reg, 0, c.labelExit),
		asm.LoadMem(reg, reg, offs.vmAddr, asm.DWord),
		asm.Add.Imm32(tmp, int32(uint32(offset))), // (u32)(user_vm_start + offset)
		asm.Add.Reg(reg, tmp),
		asm.Add.Imm(reg, int32(arenaGuardSize(pageSize)/2)),
	)
	c.labelExitUsed = true

	return newMaterialized(reg, &btf.Array{
		Index:  &btf.Int{Name: "unsigned int", Size: 4},
		Type:   &btf.Int{Name: "u8", Size: 1},
		Nelems: uint32(size),
	}), nil
}

// ArenaInfo describes the BPF arena of a traced bpf prog, see
// ArenaTranslate().
type ArenaInfo struct {
	// FD is the arena map, which the compiled insns reference. The caller
	// keeps it open until they've been loaded.
	FD int

	// Params are the params of the traced func that point into the arena,
	// i.e. that are tagged __arg_arena.
	Params []string

	kernVM    int16 // offset of kern_vm in struct bpf_arena
	vmAddr    int16 // offset of addr in struct vm_struct
	guardHalf int32 // GUARD_SZ/2
}

// NewArenaInfo returns the ArenaInfo of the arena map fd, with the offsets of
// the fields of struct bpf_arena from kernel BTF.
func NewArenaInfo(fd int, krnl btfSpecer) (*ArenaInfo, error) {
	offs, err := arenaStructOffsets(krnl)
	if err != nil {
		return nil, err
	}

	return &ArenaInfo{
		FD:        fd,
		kernVM:    offs.kernVM,
		vmAddr:    offs.vmAddr,
		guardHalf: int32(arenaGuardSize(os.Getpagesize()) / 2),
	}, nil
}

// isParam reports whether param name points into the arena.
func (a *ArenaInfo) isParam(name string) bool {
	return a != nil && slices.Contains(a.Params, name)
}

// ArenaTranslate returns insns that translate the arena address in reg to the
// arena's kernel mapping, which bpf_probe_read_kernel() can read:
//
//	kern_vm->addr + GUARD_SZ/2 + (u32)addr
//
// That's where the kernel maps the page of user address addr, see
// arena_vm_fault(). kern_vm is read from the arena's struct bpf_arena through
// the map pointer at run time. NULL is kept as is. tmp is clobbered.
func ArenaTranslate(reg, tmp asm.Register, arena *ArenaInfo) asm.Instructions {
	if arena == nil {
		return nil
	}

	// Jump offsets count instruction slots, and ld_imm64 takes two.
	return asm.Instructions{
		JmpOff(asm.JEq, reg, 0, 7),
		asm.Mov.Reg32(reg, reg), // the arena offset, (u32)addr
		asm.LoadMapPtr(tmp, arena.FD),
		asm.LoadMem(tmp, tmp, arena.kernVM, asm.DWord),
		asm.LoadMem(tmp, tmp, arena.vmAddr, asm.DWord),
		asm.Add.Reg(reg, tmp),
		asm.Add.Imm(reg, arena.guardHalf),
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

// markArenaDeref marks the first deref of the offsets of an arena param to
// translate its address. A pointer loaded from the arena isn't translated, as
// its origin isn't known: it may as well be a kernel pointer.
func markArenaDeref(offsets []pendingOffset) []pendingOffset {
	i := slices.IndexFunc(offsets, func(o pendingOffset) bool { return o.deref })
	if i == -1 {
		return offsets
	}

	offsets = slices.Clone(offsets)
	offsets[i].arena = true
	return offsets
}
