// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

// Command arenaprobe runs a BPF program whose data lives in a BPF arena, for
// the arena tests.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
)

// struct arena_node in arena.c.
const (
	nodeSize    = 32
	nodeNameLen = 12
)

func putNode(b []byte, val int32, name string, next, task uint64) {
	binary.NativeEndian.PutUint32(b[0:], uint32(val))
	copy(b[4:4+nodeNameLen], name)
	binary.NativeEndian.PutUint64(b[16:], next)
	binary.NativeEndian.PutUint64(b[24:], task)
}

// kallsyms returns the address of a kernel symbol, or 0.
func kallsyms(name string) uint64 {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == name {
			addr, _ := strconv.ParseUint(fields[0], 16, 64)
			return addr
		}
	}
	return 0
}

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadArena()
	assert.NoErr(err, "Failed to load arena spec: %v")

	arena, err := ebpf.NewMap(spec.Maps["arena"])
	assert.NoErr(err, "Failed to create arena: %v")
	defer arena.Close()

	// The first mmap of an arena fixes its user address range. Faulting a
	// page in from user space allocates it for both sides.
	mem, err := unix.Mmap(arena.FD(), 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	assert.NoErr(err, "Failed to mmap arena: %v")
	defer unix.Munmap(mem)

	base := uint64(uintptr(unsafe.Pointer(&mem[0])))
	initTask := kallsyms("init_task")
	putNode(mem[0:], 1, "first", base+nodeSize, initTask)
	putNode(mem[nodeSize:], 2, "second", 0, 0)

	assert.NoErr(spec.Variables["head"].Set(base), "Failed to set head: %v")

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"arena": arena},
	})
	assert.NoVerifierErr(err, "Failed to load arena collection: %v")
	defer coll.Close()

	log.Printf("Running arena_main, arena at %#x", base)

	data := make([]byte, 64)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, err := coll.Programs["arena_main"].Run(&ebpf.RunOptions{Data: data})
			assert.NoErr(err, "Failed to run arena_main: %v")
		}
	}
}
