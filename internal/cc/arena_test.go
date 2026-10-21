// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"slices"
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
		Params:    []string{"node"},
	}
}

func arenaTranslateInsns(reg, tmp asm.Register, arena *ArenaInfo) asm.Instructions {
	return asm.Instructions{
		JmpOff(asm.JEq, reg, 0, 4),
		asm.Mov.Reg32(reg, reg),
		asm.LoadImm(tmp, int64(arena.KernStart), asm.DWord),
		asm.Add.Reg(reg, tmp),
	}
}

// addArenaNode adds var node, an __arg_arena param pointing to
//
//	struct arena_node { int val; struct arena_node *next; struct task_struct *task; };
func addArenaNode(t *testing.T, c *compiler) {
	t.Helper()

	intTyp, err := testBtf.AnyTypeByName("int")
	test.AssertNoErr(t, err)
	taskTyp, err := testBtf.AnyTypeByName("task_struct")
	test.AssertNoErr(t, err)

	node := &btf.Struct{Name: "arena_node", Size: 24}
	node.Members = []btf.Member{
		{Name: "val", Type: intTyp},
		{Name: "next", Type: &btf.Pointer{Target: node}, Offset: 64},
		{Name: "task", Type: &btf.Pointer{Target: taskTyp}, Offset: 128},
	}
	c.vars = append(c.vars, "node")
	c.btfs = append(c.btfs, &btf.Pointer{Target: node})
}

// translations returns the indexes of the arena translations in insns.
func translations(insns asm.Instructions, arena *ArenaInfo) []int {
	var idx []int
	for i, ins := range insns {
		if ins.OpCode.IsDWordLoad() && ins.Constant == int64(arena.KernStart) {
			idx = append(idx, i)
		}
	}
	return idx
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

	t.Run("null is kept", func(t *testing.T) {
		slots := 0
		insns := ArenaTranslate(r3, arena)
		for _, ins := range insns[1:] {
			slots += int(ins.Size() / asm.InstructionSize)
		}
		// The NULL check skips to the end of the translation.
		test.AssertEqual(t, insns[0].Offset, int16(slots))
	})
}

func TestArenaReads(t *testing.T) {
	arena := testArena()

	for _, tt := range []struct {
		name  string
		expr  string
		core  bool
		reads int // translations
	}{
		{name: "arena param", expr: "node->val", reads: 1},
		{name: "only the first read", expr: "node->next->val", reads: 1},
		{name: "kernel pointer stored in the arena", expr: "node->task->pid", reads: 1},
		{name: "kernel pointer stored in the arena, core read", expr: "node->task->pid", core: true, reads: 1},
		{name: "not an arena param", expr: "skb->dev->ifindex"},
		{name: "not an arena param, core read", expr: "skb->dev->ifindex", core: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := prepareCompiler(t)
			if tt.core {
				c = prepareCompilerCoreRead(t)
			}
			c.arena = arena
			addArenaNode(t, c)

			_, err := c.materialize(prepareExprVal(t, c, tt.expr))
			test.AssertNoErr(t, err)

			idx := translations(c.insns, arena)
			test.AssertEqual(t, len(idx), tt.reads)
			if tt.reads != 0 {
				// The translation comes before the first read.
				first := slices.IndexFunc(c.insns, func(ins asm.Instruction) bool { return ins.IsBuiltinCall() })
				test.AssertTrue(t, idx[0] < first)
			}
		})
	}

	t.Run("core read of a program-local struct", func(t *testing.T) {
		c := prepareCompilerCoreRead(t)
		c.arena = arena
		addArenaNode(t, c)

		_, err := c.materialize(prepareExprVal(t, c, "node->val"))
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

	t.Run("eval result", func(t *testing.T) {
		c := prepareCompiler(t)
		addArenaNode(t, c)
		params := []btf.FuncParam{
			{Name: "skb", Type: getSkbBtf(t)},
			{Name: "node", Type: c.btfs[len(c.btfs)-1]},
		}

		for _, tt := range []struct {
			expr  string
			arena bool // the result is an address in the arena
		}{
			{expr: "node", arena: true},
			{expr: "*node", arena: true},
			{expr: "node->next"},
			{expr: "*node->next"},
			{expr: "skb->dev"},
		} {
			res, err := CompileEvalExpr(CompileExprOptions{
				Expr: tt.expr, Params: params, Spec: testBtf, Kernel: testBtf,
				LabelExit: "__label_exit", Arena: arena,
			})
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.Arena, tt.arena)
		}
	})

	t.Run("filter expr", func(t *testing.T) {
		c := prepareCompiler(t)
		addArenaNode(t, c)

		insns, err := CompileFilterExpr(CompileExprOptions{
			Expr:      "node->next->val == 2 && skb->len == 0",
			LabelExit: "__label_exit",
			Spec:      testBtf,
			Kernel:    testBtf,
			Params: []btf.FuncParam{
				{Name: "skb", Type: getSkbBtf(t)},
				{Name: "node", Type: c.btfs[len(c.btfs)-1]},
			},
			Arena: arena,
		})
		test.AssertNoErr(t, err)
		test.AssertEqual(t, len(translations(insns, arena)), 1) // node->next
	})
}
