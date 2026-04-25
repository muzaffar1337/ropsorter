# ropsorter

Categorize and rank ROP gadgets from rp++, ROPgadget, ropper, or radare2 output.

Supports **x86**, **x64**, **ARM**, and **ARM64** (AArch64).

## What It Does

- Sorts gadgets into category files (pivots, writers, readers, loaders, etc.)
- Ranks by cleanliness — fewest side effects first
- Tracks source file — output shows which module each gadget came from
- Supports multiple input files at once
- Auto-detects architecture and tool format (or specify manually)
- Nothing is lost — every gadget ends up in exactly one file

## Usage

```bash
# Generate gadgets per module
rp++ -f kernel32.dll -r 5 --bad-bytes "00|09|0a|0b|0c|0d|20" > k32.txt
rp++ -f ntdll.dll    -r 5 --bad-bytes "00|09|0a|0b|0c|0d|20" > ntdll.txt
rp++ -f msvcrt.dll   -r 5 --bad-bytes "00|09|0a|0b|0c|0d|20" > msvcrt.txt

# Sort them all at once (auto-detect arch & format)
python3 ropsorter.py k32.txt ntdll.txt msvcrt.txt ./gadgets

# Or specify architecture and format explicitly
python3 ropsorter.py --arch x64 k32.txt ntdll.txt ./gadgets
python3 ropsorter.py --arch arm --format ropgadget libc.txt ./gadgets
python3 ropsorter.py --arch arm64 libc.txt ./gadgets
```

Default output dir is `./rop_gadgets/` if not specified.

Each gadget in the output is prefixed with its source module so you know where it came from:

```
[  2] k32.txt:0x76a3b1a0: pop eax ; ret
[  2] ntdll.txt:0x77d4c2f0: pop eax ; ret
[  3] msvcrt.txt:0x7c3812a5: pop eax ; pop ebx ; ret
```

## Supported Architectures

| Arch | Flag | Registers | Return |
|------|------|-----------|--------|
| x86 | `--arch x86` | eax-edi, esp, ebp | `ret` / `retn` |
| x64 | `--arch x64` | rax-rdi, r8-r15, rsp, rbp | `ret` / `retn` |
| ARM | `--arch arm` | r0-r12, sp, lr, pc | `bx lr` / `pop {pc}` |
| ARM64 | `--arch arm64` | x0-x30, sp, xzr | `ret` (br x30) |

## Supported Formats

| Tool | Flag | Auto-detected |
|------|------|---------------|
| rp++ | `--format rp++` | Yes |
| ROPgadget | `--format ropgadget` | Yes |
| ropper | `--format ropper` | Yes |
| radare2 | `--format radare2` | Yes |

## Output Files

| File | Contents |
|------|----------|
| `pivots.txt` | Stack pivots (redirect stack pointer) |
| `writers.txt` | Memory writes |
| `readers.txt` | Memory reads |
| `transfers.txt` | Register-to-register moves |
| `loaders.txt` | Load values from stack |
| `arithmetic.txt` | Math and bitwise operations |
| `conditionals.txt` | Comparisons and conditional ops |
| `nops.txt` | Bare returns, nops |
| `leave.txt` | Chain killers (x86/x64 only) |
| `jmp_call.txt` | Contains branch/call instructions |
| `uncategorized.txt` | Everything else — check here when stuck |

## Branches

- **`main`** — multi-arch support (x86/x64/ARM/ARM64)
- **`OSED`** — x86-only version, single file, built for OSED (EXP-301) prep
