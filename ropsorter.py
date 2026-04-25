#!/usr/bin/env python3
"""
gadget_sort.py — Categorize ROP gadgets from rp++ output.

Design principles:
  - Every single gadget lands in exactly one file. NOTHING is lost.
  - Within each file, cleanest gadgets (fewest side effects) listed FIRST.
  - Original rp++ file is NEVER modified. Read-only.
  - All duplicates kept (same instructions, different addresses — all preserved).

Usage:
    python3 gadget_sort.py <gadgets.txt> [output_dir]

Output files (priority order — first match wins):
    pivots.txt        — Stack pivots: xchg reg,esp / mov esp,reg / add esp / sub esp
    writers.txt       — Write to memory: mov [reg], reg
    readers.txt       — Read from memory: mov reg, [reg]
    transfers.txt     — Register-to-register: mov reg,reg / push reg;pop reg / xchg reg,reg
    loaders.txt       — Load from stack: pop reg
    arithmetic.txt    — Math: add/sub/inc/dec/neg/not/xor/and/or/shl/shr/rol/ror/mul/div
    conditionals.txt  — Conditions: test/cmp/cmov/set
    nops.txt          — Alignment: bare ret / nop
    leave.txt         — Contains 'leave' (mov esp,ebp; pop ebp) — chain killer
    jmp_call.txt      — Contains jmp or call (separated — harder to chain)
    uncategorized.txt — Everything else. CHECK THIS when you can't find what you need.
"""

import sys
import os
import re


# ════════════════════════════════════════════════════════════════════
#  CATEGORY DEFINITIONS
#  Priority order matters — first match wins.
#  Put specific/dangerous patterns before broad ones.
# ════════════════════════════════════════════════════════════════════

CATEGORIES = [
    # ── PIVOTS: anything that redirects ESP ──
    {
        "name": "pivots",
        "desc": "Stack Pivots — redirect ESP",
        "patterns": [
            # xchg involving esp
            r"xchg\s+esp\s*,\s*(?:eax|ebx|ecx|edx|esi|edi|ebp)",
            r"xchg\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*esp",
            # direct mov/lea into esp
            r"mov\s+esp\s*,",
            r"lea\s+esp\s*,",
            # add/sub esp
            r"add\s+esp\s*,",
            r"sub\s+esp\s*,",
        ],
    },

    # ── WRITERS: store value TO memory ──
    {
        "name": "writers",
        "desc": "Writers — write value to memory: mov [reg], reg / mov [reg+off], imm",
        "patterns": [
            # mov [anything], source
            r"mov\s+(?:dword|word|byte)\s*\[",
            r"mov\s+\[",
            # string store ops
            r"\bstosd\b",
            r"\bstosw\b",
            r"\bstosb\b",
            # add/sub/xor/and/or to memory
            r"\badd\s+(?:dword|word|byte)\s*\[",
            r"\bsub\s+(?:dword|word|byte)\s*\[",
            r"\bxor\s+(?:dword|word|byte)\s*\[",
            r"\band\s+(?:dword|word|byte)\s*\[",
            r"\bor\s+(?:dword|word|byte)\s*\[",
            r"\badd\s+\[",
            r"\bsub\s+\[",
            r"\bxor\s+\[",
        ],
    },

    # ── READERS: load value FROM memory ──
    {
        "name": "readers",
        "desc": "Readers — read from memory: mov reg, [reg] / mov reg, dword [reg+off]",
        "patterns": [
            # mov reg, [anything]
            r"mov\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*(?:dword|word|byte)?\s*\[",
            # string load ops
            r"\blodsd\b",
            r"\blodsw\b",
            r"\blodsb\b",
            # lea reg, [anything] (address calculation, very useful)
            r"\blea\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*\[",
            # sub/add reg, [mem]
            r"\badd\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*(?:dword|word|byte)?\s*\[",
            r"\bsub\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*(?:dword|word|byte)?\s*\[",
            r"\bxor\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*(?:dword|word|byte)?\s*\[",
            r"\band\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*(?:dword|word|byte)?\s*\[",
            r"\bor\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*(?:dword|word|byte)?\s*\[",
        ],
    },

    # ── TRANSFERS: register to register (NO memory involved) ──
    {
        "name": "transfers",
        "desc": "Transfers — register-to-register (cleanest listed first)",
        "patterns": [
            # mov reg, reg (no brackets)
            r"mov\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*(?:eax|ebx|ecx|edx|esi|edi|ebp|esp)\s*;",
            # push reg ... pop reg (transfer through stack)
            r"push\s+(?:eax|ebx|ecx|edx|esi|edi|ebp|esp).*pop\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)",
            # xchg reg, reg (not involving esp — those are pivots above)
            r"xchg\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*(?:eax|ebx|ecx|edx|esi|edi|ebp)",
            # movzx/movsx
            r"movzx\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,",
            r"movsx\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,",
            # cdq (sign-extend eax into edx:eax)
            r"\bcdq\b",
        ],
    },

    # ── LOADERS: pop from stack into register ──
    {
        "name": "loaders",
        "desc": "Loaders — pop controlled values from stack into registers",
        "patterns": [
            r"\bpop\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)",
            r"\bpopad\b",
            r"\bpopa\b",
            r"\bpopfd\b",
        ],
    },

    # ── ARITHMETIC: math and bitwise on registers ──
    {
        "name": "arithmetic",
        "desc": "Arithmetic — add/sub/neg/not/xor/and/or/inc/dec/shl/shr/rol/ror/mul/div/sbb/adc",
        "patterns": [
            r"\badd\s+(?:eax|ebx|ecx|edx|esi|edi|ebp|al|ah|bl|bh|cl|ch|dl|dh)\s*,",
            r"\bsub\s+(?:eax|ebx|ecx|edx|esi|edi|ebp|al|ah|bl|bh|cl|ch|dl|dh)\s*,",
            r"\binc\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)",
            r"\bdec\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)",
            r"\bneg\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)",
            r"\bnot\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)",
            r"\bxor\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*(?:eax|ebx|ecx|edx|esi|edi|ebp|0x)",
            r"\band\s+(?:eax|ebx|ecx|edx|esi|edi|ebp|al|ah)\s*,",
            r"\bor\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)\s*,",
            r"\bshl\s+",
            r"\bshr\s+",
            r"\bsar\s+",
            r"\brol\s+",
            r"\bror\s+",
            r"\bsbb\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)",
            r"\badc\s+(?:eax|ebx|ecx|edx|esi|edi|ebp)",
            r"\bmul\s+",
            r"\bdiv\s+",
            r"\bimul\s+",
            r"\bidiv\s+",
        ],
    },

    # ── CONDITIONALS ──
    {
        "name": "conditionals",
        "desc": "Conditionals — test/cmp/cmov/set",
        "patterns": [
            r"\btest\s+",
            r"\bcmp\s+",
            r"\bcmov\w+\s+",
            r"\bset\w+\s+",
        ],
    },

    # ── NOPS: bare ret, nop ──
    {
        "name": "nops",
        "desc": "NOPs — bare ret, nop, alignment gadgets",
        "patterns": [
            r"^0x[0-9a-fA-F]+:\s*retn?\s*;",
            r"^0x[0-9a-fA-F]+:\s*retn\s+0x",
            r"^0x[0-9a-fA-F]+:\s*nop\b",
        ],
    },
]


# ════════════════════════════════════════════════════════════════════
#  CLEANLINESS SCORING
#  Lower score = cleaner = fewer side effects = listed first in file
# ════════════════════════════════════════════════════════════════════

def cleanliness_score(instr_str):
    """
    Score a gadget's side effects. Lower = cleaner.

    +1   per instruction
    +20  contains 'leave' (redirects ESP via EBP — very dangerous)
    +5   per memory dereference '['
    +4   contains 'retn 0x' (consumes extra stack beyond normal ret)
    +2   per pop beyond the first (extra stack consumption)
    +1   per minor register clobber (add al, add dl, and al, etc.)
    +2   if sbb/adc present (carry flag dependent — unpredictable)
    """
    score = 0
    full = instr_str.lower()

    # Count instructions
    parts = [p.strip() for p in full.split(";") if p.strip()]
    score += len(parts)

    # leave = mov esp, ebp; pop ebp — extremely dangerous side effect
    if re.search(r"\bleave\b", full):
        score += 20

    # Memory dereferences — each is a potential crash
    derefs = len(re.findall(r"\[", full))
    score += derefs * 5

    # retn N — extra stack bytes consumed
    retn_match = re.search(r"\bretn\s+0x([0-9a-f]+)", full)
    if retn_match:
        extra = int(retn_match.group(1), 16)
        score += 4 + (extra // 4)

    # Extra pops (first pop is usually the point; extras are side effects)
    pops = re.findall(r"\bpop\s+", full)
    if len(pops) > 1:
        score += (len(pops) - 1) * 2

    # Minor clobbers: add al, add dl, and al, etc.
    minor = re.findall(r"\b(?:add|sub|and|or|xor)\s+(?:[abcd][lh]|d[lh])\s*,", full)
    score += len(minor)

    # sbb/adc — carry flag dependent
    if re.search(r"\b(?:sbb|adc)\b", full):
        score += 2

    return score


# ════════════════════════════════════════════════════════════════════
#  PARSING
# ════════════════════════════════════════════════════════════════════

def parse_file(filepath):
    """
    Read rp++ output file (READ-ONLY).
    Returns list of (address, instructions, raw_line, filename).
    Skips header lines, blank lines, and non-gadget lines.
    """
    gadgets = []
    filename = os.path.basename(filepath)
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.rstrip("\n\r")
            if not stripped.strip():
                continue

            # Match rp++ gadget format:
            # 0xADDRESS: instr1 ; instr2 ; ret  ;  (N found)
            m = re.match(
                r"^(0x[0-9a-fA-F]+):\s*(.+?)\s*(?:\(\d+\s*found\))?\s*$",
                stripped.strip()
            )
            if m:
                addr = m.group(1)
                instrs = m.group(2).rstrip("; ").strip()
                gadgets.append((addr, instrs, stripped.strip(), filename))

    return gadgets


# ════════════════════════════════════════════════════════════════════
#  CATEGORIZATION
# ════════════════════════════════════════════════════════════════════

def has_jmp_or_call(instrs):
    """Check if gadget contains jmp or call."""
    return bool(re.search(r"\b(?:jmp|call)\b", instrs, re.IGNORECASE))


def has_leave(instrs):
    """Check if gadget contains leave (mov esp,ebp; pop ebp — chain killer)."""
    return bool(re.search(r"\bleave\b", instrs, re.IGNORECASE))


def categorize_gadget(addr, instrs, raw_line):
    """
    Assign ONE category to a gadget. First match wins.
    JMP/CALL → jmp_call (checked first).
    LEAVE → leave (checked second — chain killer).
    Then categories in priority order.
    Unmatched → uncategorized (NOTHING is lost).
    """
    if has_jmp_or_call(instrs):
        return "jmp_call"

    if has_leave(instrs):
        return "leave"

    for cat in CATEGORIES:
        for pattern in cat["patterns"]:
            if re.search(pattern, raw_line if pattern.startswith("^") else instrs, re.IGNORECASE):
                return cat["name"]

    return "uncategorized"


def categorize_all(gadgets):
    """
    Categorize every gadget. Returns dict of category -> [(score, filename, raw_line), ...].
    Asserts total in == total out.
    """
    results = {cat["name"]: [] for cat in CATEGORIES}
    results["jmp_call"] = []
    results["leave"] = []
    results["uncategorized"] = []

    for addr, instrs, raw_line, filename in gadgets:
        cat = categorize_gadget(addr, instrs, raw_line)
        score = cleanliness_score(instrs)
        results[cat].append((score, filename, raw_line))

    # VERIFY: every gadget accounted for
    total_out = sum(len(v) for v in results.values())
    assert total_out == len(gadgets), (
        f"BUG: {len(gadgets)} gadgets parsed, {total_out} categorized. "
        f"Difference: {len(gadgets) - total_out}"
    )

    # Sort each category: cleanest first (lowest score)
    for cat in results:
        results[cat].sort(key=lambda x: x[0])

    return results


# ════════════════════════════════════════════════════════════════════
#  OUTPUT
# ════════════════════════════════════════════════════════════════════

CLEAN_CATEGORIES = [
    "pivots", "writers", "readers", "transfers", "loaders",
    "arithmetic", "conditionals", "nops"
]

NOISY_CATEGORIES = [
    "leave", "jmp_call", "uncategorized"
]

def write_results(results, out_dir, total_parsed):
    """Write all categories into a single output directory."""
    os.makedirs(out_dir, exist_ok=True)

    desc_map = {cat["name"]: cat["desc"] for cat in CATEGORIES}
    desc_map["jmp_call"] = "JMP/CALL gadgets — contain jmp or call, harder to chain"
    desc_map["leave"] = (
        "LEAVE gadgets — contain 'leave' (mov esp,ebp; pop ebp).\n"
        "# Chain killer unless you control EBP. Use only as last resort."
    )
    desc_map["uncategorized"] = (
        "UNCATEGORIZED — didn't match any category.\n"
        "# >>> CHECK THIS FILE when you can't find what you need! <<<"
    )

    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[1m"
    N = "\033[0m"

    print(f"\n{B}{'='*62}")
    print(f"  Gadget Categorization Results")
    print(f"{'='*62}{N}\n")

    print(f"  {B}Output → {out_dir}/{N}\n")

    total_out = 0

    def _write_category(cat_name, color):
        nonlocal total_out
        gadget_list = results.get(cat_name, [])
        count = len(gadget_list)
        total_out += count

        if count == 0:
            return

        filepath = os.path.join(out_dir, f"{cat_name}.txt")
        desc = desc_map.get(cat_name, cat_name)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"# {desc}\n")
            f.write(f"# Count: {count}\n")
            f.write(f"# Sorted: cleanest (fewest side effects) → noisiest\n")
            f.write(f"#\n")
            f.write(f"# [score] = cleanliness score (lower = cleaner)\n")
            f.write(f"#   +1/instr  +20 leave  +5/deref  +4 retn_N\n")
            f.write(f"#   +2/extra_pop  +1/minor_clobber  +2 sbb/adc\n")
            f.write(f"{'#'*62}\n\n")

            for score, filename, line in gadget_list:
                f.write(f"[{score:3d}] {filename}:{line}\n")

        print(f"  {color}{cat_name:<20s}{N} {count:>6d}  →  {filepath}")

    for cat_name in CLEAN_CATEGORIES:
        _write_category(cat_name, G)

    if any(results.get(c) for c in NOISY_CATEGORIES):
        print()

    for cat_name in NOISY_CATEGORIES:
        _write_category(cat_name, Y)

    # Final verification
    if total_out != total_parsed:
        print(f"\n  {R}{B}[!] BUG: {total_parsed} parsed, {total_out} written!{N}")
    else:
        print(f"\n  {G}{B}  {'TOTAL':<20s} {total_out:>6d}  ✓ every gadget accounted for{N}")

    print(f"\n{B}{'='*62}{N}\n")


# ════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════

def main():
    # Parse arguments: separate .txt input files from output dirs
    # Usage: ropsorter.py file1.txt [file2.txt ...] [clean_dir] [noisy_dir]
    # Output dirs are detected as args that don't look like existing files or
    # end with .txt. We support an explicit separator '--' too.

    args = sys.argv[1:]

    if not args:
        print(f"Usage: python3 {sys.argv[0]} <gadgets1.txt> [gadgets2.txt ...] [out_dir]")
        print(f"\n  gadgetsN.txt — rp++ output files (one per module)")
        print(f"  out_dir      — all category files go here (default: ./rop_gadgets/)")
        print(f"\nExample:")
        print(f"  rp++ -f kernel32.dll -r 5 --bad-bytes \"00|09|0a|0b|0c|0d|20\" > k32.txt")
        print(f"  rp++ -f ntdll.dll    -r 5 --bad-bytes \"00|09|0a|0b|0c|0d|20\" > ntdll.txt")
        print(f"  python3 {sys.argv[0]} k32.txt ntdll.txt ./gadgets")
        sys.exit(1)

    # Split args: existing files are inputs, first non-file arg is out_dir
    input_files = []
    remaining = []
    for a in args:
        if os.path.isfile(a):
            input_files.append(a)
        else:
            remaining.append(a)

    if not input_files:
        print(f"[!] No input files found among arguments.")
        sys.exit(1)

    out_dir = remaining[0] if remaining else "./rop_gadgets"

    # Load and merge gadgets from all input files
    all_gadgets = []
    for fpath in input_files:
        print(f"[*] Reading (read-only): {fpath}")
        gadgets = parse_file(fpath)
        print(f"    Parsed: {len(gadgets)} gadgets  ({os.path.basename(fpath)})")
        all_gadgets.extend(gadgets)

    print(f"[*] Total gadgets across all files: {len(all_gadgets)}")

    if not all_gadgets:
        print("[!] No gadgets found. Check file format (expecting rp++ output).")
        sys.exit(1)

    print(f"[*] Categorizing and scoring...")
    results = categorize_all(all_gadgets)

    write_results(results, out_dir, len(all_gadgets))

    print(f"[*] Output: {out_dir}/")
    print(f"[*] Can't find a gadget? → check {out_dir}/uncategorized.txt\n")


if __name__ == "__main__":
    main()
