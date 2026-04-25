# ropsorter

Categorize and rank ROP gadgets from rp++ output. Built for OSED prep.

## What It Does

- Sorts gadgets into category files (pivots, writers, readers, loaders, etc.)
- Ranks by cleanliness — fewest side effects first
- Tracks source file — output shows which module each gadget came from
- Supports multiple input files at once
- Nothing is lost — every gadget ends up in exactly one file

## Usage

```bash
# Generate gadgets per module
rp++ -f kernel32.dll -r 5 --bad-bytes "00|09|0a|0b|0c|0d|20" > k32.txt
rp++ -f ntdll.dll    -r 5 --bad-bytes "00|09|0a|0b|0c|0d|20" > ntdll.txt
rp++ -f msvcrt.dll   -r 5 --bad-bytes "00|09|0a|0b|0c|0d|20" > msvcrt.txt

# Sort them all at once
python3 ropsorter.py k32.txt ntdll.txt msvcrt.txt ./gadgets
```

Default output dir is `./rop_gadgets/` if not specified.

Each gadget in the output is prefixed with its source module so you know where it came from:

```
[  2] k32.txt:0x76a3b1a0: pop eax ; ret
[  2] ntdll.txt:0x77d4c2f0: pop eax ; ret
[  3] msvcrt.txt:0x7c3812a5: pop eax ; pop ebx ; ret
```

## Output Files

| File | Contents |
|------|----------|
| `pivots.txt` | Stack pivots (`xchg reg, esp` / `mov esp, reg` / `add esp`) |
| `writers.txt` | Memory writes (`mov [reg], reg` / `stosd`) |
| `readers.txt` | Memory reads (`mov reg, [reg]` / `lodsd` / `lea`) |
| `transfers.txt` | Reg-to-reg (`mov reg, reg` / `push; pop` / `xchg`) |
| `loaders.txt` | Stack loads (`pop reg` / `popad`) |
| `arithmetic.txt` | Math/bitwise (`add` / `sub` / `xor` / `neg` / `shl` / etc.) |
| `conditionals.txt` | Conditions (`test` / `cmp` / `cmov` / `set`) |
| `nops.txt` | Bare `ret` / `nop` |
| `leave.txt` | Contains `leave` — chain killer |
| `jmp_call.txt` | Contains `jmp` or `call` |
| `uncategorized.txt` | Everything else — check here when stuck |
