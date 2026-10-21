# Tracing data in a BPF arena

A BPF arena is memory shared by a BPF program and the user space process that owns it. Programs build their own data structures in it, with plain pointers, instead of in maps. bpfsnoop can read the arena in `--filter-arg` and `--output-arg` expressions of a traced BPF program (`-p`), through the params that point into it:

```sh
bpfsnoop -p 'n:arena_main:arena_probe' -m entry \
  --output-arg 'n->val' \
  --output-arg 'str(n->name)' \
  --output-arg 'str(n->task->comm)'
```

```
→ arena_probe[bpf] args=((struct arena_node __arena *)n=0x7fc02ccf9000) ...
Arg attrs: (int)'n->val'=1, (array(char[12]))'str(n->name)'="first", (array(char[16]))'str(n->task->comm)'="swapper/0"
```

A param points into the arena if it's tagged `__arg_arena`, and it's printed with an `__arena` type. Nothing has to be enabled: bpfsnoop handles the arena whenever the traced program uses one.

## How it works

Pointers stored in an arena hold addresses in the owner's user space mapping, e.g. `0x7f...`, so user space can follow them as is. The kernel maps the same pages at `kern_vm_start + (u32)addr`. `bpf_probe_read_kernel()` rejects the user address.

For each traced program, bpfsnoop finds its arena map and reads `user_vm_start`, `user_vm_end` and `kern_vm` from the arena's `struct bpf_arena` with a BPF map iterator. `-v` prints the arena of each traced program:

```
Prog 631148 uses arena map 723229: user [0x7fc02ccf9000, 0x7fc02ccfa000), kern 0xffffc90260606000
```

BTF doesn't keep the arena address space of a pointer, so bpfsnoop tells an arena pointer by its origin: an `__arg_arena` param. The first memory read through it translates the address to the kernel mapping. A pointer loaded from the arena isn't translated, as it may as well be a kernel pointer stored in the arena, like `n->task` above.

`kern_vm_start` is computed the way the kernel does it. On x86, bpfsnoop checks it against the JITed code of the program. If they don't match, it warns and reads the program's memory as if it had no arena.

## Limitations

- BPF arenas need kernel 6.9 or newer. `bpfsnoop --detect-features` reports `arena`.
- Pointers loaded from the arena aren't followed yet: `n->next->val` reads 0.
- Arena global variables (the `.addr_space.1` section) can't be named in expressions yet.
- The function graph (`-g`) doesn't translate the pointee of number pointer args of BPF subprogs.
- Arena pages that were never allocated read as 0.
- If a program never uses a kernel struct it stores pointers to, its BTF only declares the struct. Cast the pointer to read its members, e.g. `((struct task_struct *)n->task)->comm`.
