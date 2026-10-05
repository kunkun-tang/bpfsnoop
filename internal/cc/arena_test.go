// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
)

func testArena() *ArenaInfo {
	return &ArenaInfo{
		UserStart: 0x7f0000000000,
		UserEnd:   0x7f0000100000,
		KernStart: 0xffffc90000008000,
	}
}

func arenaTranslateInsns(reg, tmp asm.Register, arena *ArenaInfo) asm.Instructions {
	return asm.Instructions{
		asm.LoadImm(tmp, int64(arena.UserStart), asm.DWord),
		JmpReg(asm.JLT, reg, tmp, 7),
		asm.LoadImm(tmp, int64(arena.UserEnd), asm.DWord),
		JmpReg(asm.JGE, reg, tmp, 4),
		asm.Mov.Reg32(reg, reg),
		asm.LoadImm(tmp, int64(arena.KernStart), asm.DWord),
		asm.Add.Reg(reg, tmp),
	}
}

// assertTranslatedReads checks that every probe read of insns reads an
// address translated just before its args are set up, and returns the count.
func assertTranslatedReads(t *testing.T, insns asm.Instructions, arena *ArenaInfo) int {
	t.Helper()

	want := arenaTranslateInsns(r3, asm.R5, arena)
	reads := 0
	for i, ins := range insns {
		if !ins.IsBuiltinCall() {
			continue
		}
		reads++
		// r2 = size; r1 = rfp; r1 += -8; call
		end := i - 3
		test.AssertTrue(t, end-len(want) >= 0)
		test.AssertEqualSlice(t, insns[end-len(want):end], want)
	}
	return reads
}

func TestArenaTranslate(t *testing.T) {
	arena := testArena()

	t.Run("no arena", func(t *testing.T) {
		test.AssertEmptySlice(t, ArenaTranslate(r3, nil))
	})

	t.Run("r3", func(t *testing.T) {
		test.AssertEqualSlice(t, ArenaTranslate(r3, arena), arenaTranslateInsns(r3, asm.R5, arena))
	})

	t.Run("r5", func(t *testing.T) {
		test.AssertEqualSlice(t, ArenaTranslate(asm.R5, arena), arenaTranslateInsns(asm.R5, asm.R4, arena))
	})

	t.Run("jump offsets", func(t *testing.T) {
		slots := func(insns asm.Instructions) int16 {
			n := 0
			for _, ins := range insns {
				n += int(ins.Size() / asm.InstructionSize)
			}
			return int16(n)
		}

		// Both jumps skip to the end of the translation.
		insns := ArenaTranslate(r3, arena)
		test.AssertEqual(t, insns[1].Offset, slots(insns[2:]))
		test.AssertEqual(t, insns[3].Offset, slots(insns[4:]))
	})
}

func TestArenaReads(t *testing.T) {
	arena := testArena()

	t.Run("probe read", func(t *testing.T) {
		c := prepareCompiler(t)
		c.arena = arena

		_, err := c.materialize(prepareExprVal(t, c, "skb->dev->ifindex"))
		test.AssertNoErr(t, err)

		test.AssertEqual(t, assertTranslatedReads(t, c.insns, arena), 2) // skb->dev, dev->ifindex
	})

	t.Run("core read of a program-local struct", func(t *testing.T) {
		c := prepareCompilerCoreRead(t)
		c.arena = arena

		intTyp, err := testBtf.AnyTypeByName("int")
		test.AssertNoErr(t, err)
		node := &btf.Pointer{Target: &btf.Struct{
			Name:    "arena_node",
			Size:    4,
			Members: []btf.Member{{Name: "val", Type: intTyp}},
		}}
		c.vars = append(c.vars, "node")
		c.btfs = append(c.btfs, node)

		_, err = c.materialize(prepareExprVal(t, c, "node->val"))
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, append(append(asm.Instructions{
			asm.LoadMem(r8, argsReg, 48, dword), // node
			asm.Mov.Reg(r1, r8),
			asm.Mov.Reg(r3, r1),
		}, arenaTranslateInsns(r3, asm.R5, arena)...),
			asm.Mov.Imm(r2, 8),
			asm.Mov.Reg(r1, rfp),
			asm.Add.Imm(r1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(r8, rfp, -8, dword), // node->val
			asm.LSh.Imm(r8, 32),
			asm.ArSh.Imm(r8, 32),
		))
	})

	t.Run("filter expr", func(t *testing.T) {
		insns, err := CompileFilterExpr(CompileExprOptions{
			Expr:      "skb->len == 0",
			LabelExit: "__label_exit",
			Spec:      testBtf,
			Kernel:    testBtf,
			Params:    []btf.FuncParam{{Name: "skb", Type: getSkbBtf(t)}},
			Arena:     arena,
		})
		test.AssertNoErr(t, err)
		test.AssertEqual(t, assertTranslatedReads(t, insns, arena), 1) // skb->len
	})
}
