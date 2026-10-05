// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
	"github.com/bpfsnoop/bpfsnoop/internal/cc"
)

// arenaVM is struct arena_vm in bpf/arena.c.
type arenaVM struct {
	UserVMStart uint64
	UserVMEnd   uint64
	KernVMAddr  uint64
}

// progArena returns the arena of a BPF prog, or nil if it has none.
func progArena(id ebpf.ProgramID, info *ebpf.ProgramInfo) (*cc.ArenaInfo, error) {
	mapID, ok, err := progArenaMapID(info)
	if err != nil || !ok {
		return nil, err
	}

	vm, err := readArenaVM(mapID)
	if err != nil {
		return nil, fmt.Errorf("failed to read arena map %d: %w", mapID, err)
	}

	arena := &cc.ArenaInfo{
		UserStart: vm.UserVMStart,
		UserEnd:   vm.UserVMEnd,
		KernStart: vm.KernVMAddr + arenaGuardSize()/2,
	}
	if err := checkArenaKernStart(info, arena.KernStart); err != nil {
		return nil, fmt.Errorf("arena map %d: %w", mapID, err)
	}

	VerboseLog("Prog %d uses arena map %d: user [%#x, %#x), kern %#x",
		id, mapID, arena.UserStart, arena.UserEnd, arena.KernStart)

	return arena, nil
}

// progArenaMapID returns the ID of the arena map of a BPF prog. A prog uses
// one arena at most.
func progArenaMapID(info *ebpf.ProgramInfo) (ebpf.MapID, bool, error) {
	ids, ok := info.MapIDs()
	if !ok {
		return 0, false, nil
	}

	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return 0, false, fmt.Errorf("failed to open map %d: %w", id, err)
		}

		mi, err := m.Info()
		_ = m.Close()
		if err != nil {
			return 0, false, fmt.Errorf("failed to get info of map %d: %w", id, err)
		}

		if mi.Type == ebpf.Arena {
			return id, true, nil
		}
	}

	return 0, false, nil
}

// readArenaVM reads the address ranges of an arena from its struct bpf_arena,
// by iterating over the maps.
func readArenaVM(id ebpf.MapID) (arenaVM, error) {
	var vm arenaVM

	spec, err := bpf.LoadArena()
	if err != nil {
		return vm, fmt.Errorf("failed to load arena bpf spec: %w", err)
	}

	if err := spec.Variables["target_map_id"].Set(uint32(id)); err != nil {
		return vm, fmt.Errorf("failed to set target_map_id: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return vm, fmt.Errorf("failed to create arena collection: %w", err)
	}
	defer coll.Close()

	it, err := link.AttachIter(link.IterOptions{
		Program: coll.Programs["arena_vm"],
	})
	if err != nil {
		return vm, fmt.Errorf("failed to attach map iterator: %w", err)
	}
	defer it.Close()

	rd, err := it.Open()
	if err != nil {
		return vm, fmt.Errorf("failed to open map iterator: %w", err)
	}
	defer rd.Close()

	data, err := io.ReadAll(rd)
	if err != nil {
		return vm, fmt.Errorf("failed to read map iterator: %w", err)
	}

	if len(data) != binary.Size(vm) {
		return vm, fmt.Errorf("unexpected %d bytes from map iterator", len(data))
	}

	err = binary.Read(bytes.NewReader(data), binary.NativeEndian, &vm)
	return vm, err
}

// arenaGuardSize is GUARD_SZ in kernel/bpf/arena.c. The kernel maps an arena
// at kern_vm->addr + GUARD_SZ/2, which bpf_arena_get_kern_vm_start() returns.
func arenaGuardSize() uint64 {
	align := 2 * uint64(os.Getpagesize())
	return (1<<16 + align - 1) / align * align
}

// checkArenaKernStart cross-checks the computed kern_vm_start of the arena
// with the prog's JITed code. On x86, the JIT loads kern_vm_start into r12 for
// arena access, with movabs r12, imm64.
func checkArenaKernStart(info *ebpf.ProgramInfo, kernStart uint64) error {
	if runtime.GOARCH != "amd64" {
		VerboseLog("Skipped checking arena kern_vm_start %#x on %s", kernStart, runtime.GOARCH)
		return nil
	}

	insns, ok := info.JitedInsns()
	if !ok {
		return errors.New("failed to get jited insns to check kern_vm_start")
	}

	movabs := binary.NativeEndian.AppendUint64([]byte{0x49, 0xbc}, kernStart)
	if !bytes.Contains(insns, movabs) {
		return fmt.Errorf("kern_vm_start %#x not found in the jited prog", kernStart)
	}

	return nil
}
