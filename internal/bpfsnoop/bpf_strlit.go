// Copyright 2026 Liang Tang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/cc"
)

// The sections of the string literals of bpf/bpfsnoop_str.h.
const (
	strLitSection    = ".rodata.strlit"
	strLitLenSection = ".rodata.strlit.length"
)

// linkStrEq adds bpfsnoop_str_eq() of bpf/bpfsnoop_str.h to prog if its insns
// call it. As no C code calls it, it's in a section of its own, so it's a prog
// of spec, which NewCollection() skips as it has no prog type.
func linkStrEq(spec *ebpf.CollectionSpec, prog *ebpf.ProgramSpec) error {
	if !slices.ContainsFunc(prog.Instructions, func(ins asm.Instruction) bool {
		return ins.IsFunctionCall() && ins.Reference() == cc.StrEqFunc
	}) {
		return nil
	}

	strEq, ok := spec.Programs[cc.StrEqFunc]
	if !ok {
		return fmt.Errorf("%s not found", cc.StrEqFunc)
	}
	prog.Instructions = append(prog.Instructions, strEq.Instructions...)
	return nil
}

// dropUnusedStrLits drops the .rodata.strlit sections from spec if no prog
// uses them, so that no map is created for them.
func dropUnusedStrLits(spec *ebpf.CollectionSpec) {
	for _, prog := range spec.Programs {
		for _, ins := range prog.Instructions {
			if ref := ins.Reference(); ref == strLitSection || ref == strLitLenSection {
				return
			}
		}
	}

	delete(spec.Maps, strLitSection)
	delete(spec.Maps, strLitLenSection)
	for name, v := range spec.Variables {
		if v.SectionName == strLitSection || v.SectionName == strLitLenSection {
			delete(spec.Variables, name)
		}
	}
}

// injectStrLits puts the string literals of the str() comparisons compiled
// into prog in the .rodata.strlit sections of spec, for bpfsnoop_str_eq() in
// bpf/bpfsnoop_str.h, which it adds to prog. Without any, the sections are
// dropped if no other prog uses them.
func injectStrLits(spec *ebpf.CollectionSpec, prog *ebpf.ProgramSpec, strLits *cc.StrLits) error {
	if err := linkStrEq(spec, prog); err != nil {
		return err
	}

	lits := strLits.Lits()
	if len(lits) == 0 {
		dropUnusedStrLits(spec)
		return nil
	}

	// A literal takes cc.StrLitSize bytes, with its NUL and zero padding.
	data := make([]byte, len(lits)*cc.StrLitSize)
	lens := make([]byte, 0, len(lits)*4)
	for i, lit := range lits {
		copy(data[i*cc.StrLitSize:], lit)
		lens = binary.NativeEndian.AppendUint32(lens, uint32(len(lit)+1))
	}

	if err := setArraySection(spec, strLitSection, data); err != nil {
		return err
	}
	return setArraySection(spec, strLitLenSection, lens)
}

// setArraySection sets the contents of a data section that holds one array,
// resizing the array to them.
func setArraySection(spec *ebpf.CollectionSpec, name string, data []byte) error {
	ms, ok := spec.Maps[name]
	if !ok {
		return fmt.Errorf("section %s not found", name)
	}

	ds, ok := ms.Value.(*btf.Datasec)
	if !ok || len(ds.Vars) != 1 {
		return fmt.Errorf("section %s doesn't hold one variable", name)
	}
	v, ok := ds.Vars[0].Type.(*btf.Var)
	if !ok {
		return fmt.Errorf("section %s doesn't hold a variable", name)
	}
	arr, ok := btf.UnderlyingType(v.Type).(*btf.Array)
	if !ok {
		return fmt.Errorf("variable %s of section %s isn't an array", v.Name, name)
	}
	elemSize, err := btf.Sizeof(arr.Type)
	if err != nil || elemSize == 0 || len(data)%elemSize != 0 {
		return fmt.Errorf("can't hold %d bytes in variable %s of section %s: %v", len(data), v.Name, name, err)
	}

	size := uint32(len(data))
	resized := &btf.Var{
		Name:    v.Name,
		Type:    &btf.Array{Index: arr.Index, Type: arr.Type, Nelems: size / uint32(elemSize)},
		Linkage: v.Linkage,
	}

	ms = ms.Copy()
	ms.ValueSize = size
	ms.Contents = []ebpf.MapKV{{Key: uint32(0), Value: data}}
	ms.Value = &btf.Datasec{
		Name: ds.Name,
		Size: size,
		Vars: []btf.VarSecinfo{{Type: resized, Size: size}},
	}
	spec.Maps[name] = ms

	// The variable's value goes over the contents when loading.
	if vs, ok := spec.Variables[v.Name]; ok {
		vs = vs.Copy()
		vs.Value = slices.Clone(data)
		vs.Type = resized
		spec.Variables[v.Name] = vs
	}
	return nil
}
