// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

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
