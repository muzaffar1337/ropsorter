#!/usr/bin/env python3
"""
ropsorter.py — Categorize ROP gadgets from rp++ output.

Supports: x86, x64, ARM, ARM64 (AArch64).

Design principles:
  - Every single gadget lands in exactly one file. NOTHING is lost.
  - Within each file, cleanest gadgets (fewest side effects) listed FIRST.
  - Original rp++ file is NEVER modified. Read-only.
  - All duplicates kept (same instructions, different addresses — all preserved).

Usage:
    python3 ropsorter.py [--arch x86|x64|arm|arm64] <gadgets.txt> [gadgets2.txt ...] [output_dir]
"""

import sys
import os
import re
import argparse

from archs import get_arch, detect_arch, SUPPORTED_ARCHS


# ════════════════════════════════════════════════════════════════════
#  CLEANLINESS SCORING
#  Lower score = cleaner = fewer side effects = listed first in file
# ════════════════════════════════════════════════════════════════════

def cleanliness_score(instr_str, arch):
    """
    Score a gadget's side effects. Lower = cleaner.

    +1   per instruction
    +20  contains chain-killer (leave on x86/x64)
    +5   per memory dereference '['
    +4   contains extra stack consumption (retn 0xN on x86/x64)
    +2   per pop beyond the first (extra stack consumption)
    +1   per minor register clobber (arch-specific)
    +2   if carry-flag dependent instruction present
    """
    score = 0
    full = instr_str.lower()

    # Count instructions
    parts = [p.strip() for p in full.split(";") if p.strip()]
    score += len(parts)

    # Chain killer (leave on x86/x64, None on ARM)
    if arch.LEAVE_PATTERN and re.search(arch.LEAVE_PATTERN, full):
        score += 20

    # Memory dereferences — each is a potential crash
    derefs = len(re.findall(r"\[", full))
    score += derefs * 5

    # Extra stack consumption (retn N on x86/x64)
    if arch.RETN_EXTRA_PATTERN:
        retn_match = re.search(arch.RETN_EXTRA_PATTERN, full)
        if retn_match:
            extra = int(retn_match.group(1), 16)
            score += 4 + (extra // 4)

    # Extra pops (first pop is usually the point; extras are side effects)
    pops = re.findall(r"\bpop\s+", full)
    if len(pops) > 1:
        score += (len(pops) - 1) * 2

    # Minor clobbers (arch-specific: byte registers on x86/x64)
    if arch.MINOR_CLOBBER_PATTERN:
        minor = re.findall(arch.MINOR_CLOBBER_PATTERN, full)
        score += len(minor)

    # Carry-flag dependent instructions
    if arch.CARRY_FLAG_PATTERN and re.search(arch.CARRY_FLAG_PATTERN, full):
        score += 2

    return score


# ════════════════════════════════════════════════════════════════════
#  PARSING — supports rp++, ROPgadget, ropper, radare2
# ════════════════════════════════════════════════════════════════════

# Gadget line patterns for each tool format:
#   rp++:       0x12345678: instr1 ; instr2 ; ret ; (1 found)
#   ROPgadget:  0x12345678 : instr1 ; instr2 ; ret
#   ropper:     0x12345678: instr1; instr2; ret;
#   radare2:    0x12345678   instr1; instr2; ret

_GADGET_PATTERNS = {
    "rp++": re.compile(
        r"^(0x[0-9a-fA-F]+):\s*(.+?)\s*\(\d+\s*found\)\s*$"
    ),
    "ropgadget": re.compile(
        r"^(0x[0-9a-fA-F]+)\s*:\s*(.+?)\s*$"
    ),
    "ropper": re.compile(
        r"^(0x[0-9a-fA-F]+):\s*(.+?)\s*$"
    ),
    "radare2": re.compile(
        r"^(0x[0-9a-fA-F]+)\s{2,}(.+?)\s*$"
    ),
}

# Order matters for auto-detect: most specific first
_FORMAT_DETECT_ORDER = ["rp++", "radare2", "ropgadget", "ropper"]

SUPPORTED_FORMATS = list(_GADGET_PATTERNS.keys())


def detect_format(filepath):
    """
    Auto-detect gadget file format by testing first few gadget-like lines.
    Returns format name string or None.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or not stripped.startswith("0x"):
                    continue
                for fmt in _FORMAT_DETECT_ORDER:
                    if _GADGET_PATTERNS[fmt].match(stripped):
                        return fmt
                break
    except Exception:
        pass
    return None


def parse_file(filepath, fmt=None):
    """
    Read gadget file (READ-ONLY). Supports rp++, ROPgadget, ropper, radare2.
    Returns list of (address, instructions, raw_line, filename).
    Skips header lines, blank lines, comments, and non-gadget lines.
    """
    if fmt is None:
        fmt = detect_format(filepath)
    if fmt is None:
        fmt = "ropper"  # most permissive fallback

    pattern = _GADGET_PATTERNS[fmt]
    gadgets = []
    filename = os.path.basename(filepath)

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            m = pattern.match(stripped)
            if m:
                addr = m.group(1)
                instrs = m.group(2).rstrip("; ").strip()
                gadgets.append((addr, instrs, stripped, filename))

    return gadgets


# ════════════════════════════════════════════════════════════════════
#  CATEGORIZATION
# ════════════════════════════════════════════════════════════════════

def categorize_gadget(addr, instrs, raw_line, arch):
    """
    Assign ONE category to a gadget. First match wins.
    JMP/CALL → jmp_call (checked first).
    Chain killer (leave) → leave (checked second).
    Then categories in priority order.
    Unmatched → uncategorized (NOTHING is lost).
    """
    if re.search(arch.JMP_CALL_PATTERN, instrs, re.IGNORECASE):
        return "jmp_call"

    if arch.LEAVE_PATTERN and re.search(arch.LEAVE_PATTERN, instrs, re.IGNORECASE):
        return "leave"

    for cat in arch.CATEGORIES:
        for pattern in cat["patterns"]:
            target = raw_line if pattern.startswith("^") else instrs
            if re.search(pattern, target, re.IGNORECASE):
                return cat["name"]

    return "uncategorized"


def categorize_all(gadgets, arch):
    """
    Categorize every gadget. Returns dict of category -> [(score, filename, raw_line), ...].
    Asserts total in == total out.
    """
    results = {cat["name"]: [] for cat in arch.CATEGORIES}
    results["jmp_call"] = []
    results["leave"] = []
    results["uncategorized"] = []

    for addr, instrs, raw_line, filename in gadgets:
        cat = categorize_gadget(addr, instrs, raw_line, arch)
        score = cleanliness_score(instrs, arch)
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

def write_results(results, out_dir, total_parsed, arch):
    """Write all categories into a single output directory."""
    os.makedirs(out_dir, exist_ok=True)

    desc_map = {cat["name"]: cat["desc"] for cat in arch.CATEGORIES}
    desc_map["jmp_call"] = f"JMP/CALL gadgets — contain branch/call, harder to chain ({arch.ARCH_NAME})"
    if arch.LEAVE_PATTERN and arch.LEAVE_DESC:
        desc_map["leave"] = arch.LEAVE_DESC
    else:
        desc_map["leave"] = "Chain-killer gadgets (architecture-specific)"
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
    print(f"  Gadget Categorization Results  [{arch.ARCH_NAME}]")
    print(f"{'='*62}{N}\n")

    print(f"  {B}Output -> {out_dir}/{N}\n")

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
            f.write(f"# Architecture: {arch.ARCH_NAME}\n")
            f.write(f"# Count: {count}\n")
            f.write(f"# Sorted: cleanest (fewest side effects) -> noisiest\n")
            f.write(f"#\n")
            f.write(f"# [score] = cleanliness score (lower = cleaner)\n")
            f.write(f"{'#'*62}\n\n")

            for score, filename, line in gadget_list:
                f.write(f"[{score:3d}] {filename}:{line}\n")

        print(f"  {color}{cat_name:<20s}{N} {count:>6d}  ->  {filepath}")

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
        print(f"\n  {G}{B}  {'TOTAL':<20s} {total_out:>6d}  [OK] every gadget accounted for{N}")

    print(f"\n{B}{'='*62}{N}\n")


# ════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Categorize ROP gadgets. Supports rp++, ROPgadget, ropper, radare2.",
        epilog=(
            "Examples:\n"
            "  ropsorter.py --arch x86 k32.txt ntdll.txt ./gadgets\n"
            "  ropsorter.py --arch x64 --format ropgadget gadgets.txt\n"
            "  ropsorter.py libc.txt  (auto-detect arch & format)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--arch",
        choices=["x86", "x64", "arm", "arm64", "aarch64"],
        default=None,
        help="Target architecture (auto-detected if not specified)",
    )
    parser.add_argument(
        "--format",
        choices=SUPPORTED_FORMATS,
        default=None,
        help="Gadget tool format (auto-detected if not specified)",
    )
    parser.add_argument(
        "args",
        nargs="+",
        help="Input gadget files and optional output directory",
    )

    parsed = parser.parse_args()

    # Split positional args: existing files are inputs, first non-file is out_dir
    input_files = []
    remaining = []
    for a in parsed.args:
        if os.path.isfile(a):
            input_files.append(a)
        else:
            remaining.append(a)

    if not input_files:
        print("[!] No input files found among arguments.")
        sys.exit(1)

    out_dir = remaining[0] if remaining else "./rop_gadgets"

    # Resolve architecture
    if parsed.arch:
        arch = get_arch(parsed.arch)
        print(f"[*] Architecture: {arch.ARCH_NAME} (specified)")
    else:
        arch = detect_arch(input_files[0])
        if arch:
            print(f"[*] Architecture: {arch.ARCH_NAME} (auto-detected)")
        else:
            print("[!] Could not auto-detect architecture. Use --arch to specify.")
            print(f"    Supported: {', '.join(SUPPORTED_ARCHS)}")
            sys.exit(1)

    # Resolve format
    fmt = parsed.format
    if fmt:
        print(f"[*] Format: {fmt} (specified)")
    else:
        fmt = detect_format(input_files[0])
        if fmt:
            print(f"[*] Format: {fmt} (auto-detected)")
        else:
            fmt = "ropper"
            print(f"[*] Format: {fmt} (fallback)")

    # Load and merge gadgets from all input files
    all_gadgets = []
    for fpath in input_files:
        print(f"[*] Reading (read-only): {fpath}")
        gadgets = parse_file(fpath, fmt)
        print(f"    Parsed: {len(gadgets)} gadgets  ({os.path.basename(fpath)})")
        all_gadgets.extend(gadgets)

    print(f"[*] Total gadgets across all files: {len(all_gadgets)}")

    if not all_gadgets:
        print("[!] No gadgets found. Check file format (expecting rp++ output).")
        sys.exit(1)

    print(f"[*] Categorizing and scoring...")
    results = categorize_all(all_gadgets, arch)

    write_results(results, out_dir, len(all_gadgets), arch)

    print(f"[*] Output: {out_dir}/")
    print(f"[*] Can't find a gadget? -> check {out_dir}/uncategorized.txt\n")


if __name__ == "__main__":
    main()
