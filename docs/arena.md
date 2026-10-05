# Tracing data in a BPF arena

A BPF arena is memory shared by a BPF program and the user space process that owns it. Programs build their own data structures in it, with plain pointers, instead of in maps. bpfsnoop can follow those pointers in `--filter-arg` and `--output-arg` expressions of a traced BPF program (`-p`):

```sh
bpfsnoop -p 'n:arena_main:arena_probe' -m entry \
  --output-arg 'n->next->val' \
  --output-arg 'str(n->next->name)' \
  --output-arg '*n'
```

```
→ arena_probe[bpf] args=((struct arena_node __arena *)n=0x7f7cdeeb8000) ...
Arg attrs: (int)'n->next->val'=2, (array(char[12]))'str(n->next->name)'="second", (struct arena_node)'*n'={"val": 1, "name": "first", "next": 0x7f7cdeeb8018}
```

Arena pointers are printed with an `__arena` type. A function parameter is one if it's tagged `__arg_arena`, or if its value is in the arena. Nothing has to be enabled: bpfsnoop handles the arena whenever the traced program uses one.

## How it works

Pointers stored in an arena hold addresses in the owner's user space mapping, e.g. `0x7f...`, so user space can follow them as is. The kernel maps the same pages at `kern_vm_start + (u32)addr`. `bpf_probe_read_kernel()` rejects the user address.

For each traced program, bpfsnoop finds its arena map and reads `user_vm_start`, `user_vm_end` and `kern_vm` from the arena's `struct bpf_arena` with a BPF map iterator. Then, before each memory read of an expression, it translates an address in the arena's user range to the kernel mapping. Other addresses, like kernel pointers, are read as before, so an expression can go from arena memory to a kernel pointer stored in it and back. `-v` prints the arena of each traced program:

```
Prog 144177 uses arena map 143697: user [0x7f7cdeeb8000, 0x7f7cdeeb9000), kern 0xffffc90260675000
```

`kern_vm_start` is computed the way the kernel does it. On x86, bpfsnoop checks it against the JITed code of the program. If they don't match, it warns and reads the program's memory as if it had no arena.

## Limitations

- BPF arenas need kernel 6.9 or newer. `bpfsnoop --detect-features` reports `arena`.
- Arena global variables (the `.addr_space.1` section) can't be named in expressions yet.
- The function graph (`-g`) doesn't translate the pointee of number pointer args of BPF subprogs.
- Arena pages that were never allocated read as 0.
- If a program never uses a kernel struct it stores pointers to, its BTF only declares the struct. Cast the pointer to read its members, e.g. `((struct task_struct *)n->task)->comm`.
