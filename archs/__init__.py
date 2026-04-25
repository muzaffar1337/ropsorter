"""
Architecture loader for ropsorter.
Each arch module exports: ARCH_NAME, REGISTERS, CATEGORIES, RETURN_PATTERN,
LEAVE_PATTERN, NOP_PATTERNS, MINOR_CLOBBER_PATTERN, CHAIN_KILLER_PATTERNS.
"""

import re

from archs import x86, x64, arm, arm64

_ARCH_MAP = {
    "x86": x86,
    "x64": x64,
    "arm": arm,
    "arm64": arm64,
    "aarch64": arm64,
}

SUPPORTED_ARCHS = list(_ARCH_MAP.keys())


def get_arch(name):
    """Return arch module by name."""
    mod = _ARCH_MAP.get(name.lower())
    if mod is None:
        raise ValueError(
            f"Unknown architecture: {name!r}. "
            f"Supported: {', '.join(SUPPORTED_ARCHS)}"
        )
    return mod


def detect_arch(filepath):
    """
    Try to detect architecture from rp++ output header.
    rp++ prints a line like:
        'Trying to open 'target.dll'...'
        'Wait a few seconds, rop is looking for gadgets...'
        'A total of N gadgets found.'
    And sometimes includes arch hints like 'x86', 'x64', 'PE/x86', 'ELF/x64',
    'ARM', 'AArch64', etc.

    Returns arch module or None if detection fails.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            # Check first 20 lines for arch hints
            for i, line in enumerate(f):
                if i >= 20:
                    break
                low = line.lower()

                if "aarch64" in low or "arm64" in low:
                    return arm64
                if "armv" in low or ("arm" in low and "arm64" not in low):
                    return arm
                # x64 checks before x86 (x86_64 contains x86)
                if "x86_64" in low or "x64" in low or "pe/x64" in low or "elf/x64" in low:
                    return x64
                if "x86" in low or "pe/x86" in low or "elf/x86" in low or "i386" in low:
                    return x86

            # Fallback: peek at first gadget and guess from register names
            f.seek(0)
            for line in f:
                m = re.match(r"^0x[0-9a-fA-F]+:\s*(.+)", line.strip())
                if m:
                    instrs = m.group(1).lower()
                    if any(r in instrs for r in ("rax", "rbx", "rcx", "rdx", "r8", "r9", "r10")):
                        return x64
                    if any(r in instrs for r in ("x0", "x1", "x2", "x19", "x29", "x30")):
                        return arm64
                    if any(r in instrs for r in ("eax", "ebx", "ecx", "edx", "esi", "edi")):
                        return x86
                    if re.search(r"\br\d{1,2}\b", instrs):
                        return arm
                    break
    except Exception:
        pass

    return None
