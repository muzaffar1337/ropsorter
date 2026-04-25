"""x86 (32-bit) architecture patterns for ropsorter."""

ARCH_NAME = "x86"

REGISTERS = {
    "gp": ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"],
    "sp": "esp",
    "bp": "ebp",
    "byte": ["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"],
}

_GP = r"(?:eax|ebx|ecx|edx|esi|edi|ebp)"
_GP_SP = r"(?:eax|ebx|ecx|edx|esi|edi|ebp|esp)"
_BYTE = r"(?:al|ah|bl|bh|cl|ch|dl|dh)"
_GP_BYTE = r"(?:eax|ebx|ecx|edx|esi|edi|ebp|al|ah|bl|bh|cl|ch|dl|dh)"
_SIZE = r"(?:dword|word|byte)"

CATEGORIES = [
    # -- PIVOTS: redirect ESP --
    {
        "name": "pivots",
        "desc": "Stack Pivots — redirect ESP",
        "patterns": [
            rf"xchg\s+esp\s*,\s*{_GP}",
            rf"xchg\s+{_GP}\s*,\s*esp",
            r"mov\s+esp\s*,",
            r"lea\s+esp\s*,",
            r"add\s+esp\s*,",
            r"sub\s+esp\s*,",
        ],
    },
    # -- WRITERS: store to memory --
    {
        "name": "writers",
        "desc": "Writers — write value to memory: mov [reg], reg / mov [reg+off], imm",
        "patterns": [
            rf"mov\s+{_SIZE}\s*\[",
            r"mov\s+\[",
            r"\bstosd\b",
            r"\bstosw\b",
            r"\bstosb\b",
            rf"\badd\s+{_SIZE}\s*\[",
            rf"\bsub\s+{_SIZE}\s*\[",
            rf"\bxor\s+{_SIZE}\s*\[",
            rf"\band\s+{_SIZE}\s*\[",
            rf"\bor\s+{_SIZE}\s*\[",
            r"\badd\s+\[",
            r"\bsub\s+\[",
            r"\bxor\s+\[",
        ],
    },
    # -- READERS: load from memory --
    {
        "name": "readers",
        "desc": "Readers — read from memory: mov reg, [reg] / mov reg, dword [reg+off]",
        "patterns": [
            rf"mov\s+{_GP}\s*,\s*{_SIZE}?\s*\[",
            r"\blodsd\b",
            r"\blodsw\b",
            r"\blodsb\b",
            rf"\blea\s+{_GP}\s*,\s*\[",
            rf"\badd\s+{_GP}\s*,\s*{_SIZE}?\s*\[",
            rf"\bsub\s+{_GP}\s*,\s*{_SIZE}?\s*\[",
            rf"\bxor\s+{_GP}\s*,\s*{_SIZE}?\s*\[",
            rf"\band\s+{_GP}\s*,\s*{_SIZE}?\s*\[",
            rf"\bor\s+{_GP}\s*,\s*{_SIZE}?\s*\[",
        ],
    },
    # -- TRANSFERS: reg to reg --
    {
        "name": "transfers",
        "desc": "Transfers — register-to-register (cleanest listed first)",
        "patterns": [
            rf"mov\s+{_GP}\s*,\s*{_GP_SP}\s*;",
            rf"push\s+{_GP_SP}.*pop\s+{_GP}",
            rf"xchg\s+{_GP}\s*,\s*{_GP}",
            rf"movzx\s+{_GP}\s*,",
            rf"movsx\s+{_GP}\s*,",
            r"\bcdq\b",
        ],
    },
    # -- LOADERS: pop from stack --
    {
        "name": "loaders",
        "desc": "Loaders — pop controlled values from stack into registers",
        "patterns": [
            rf"\bpop\s+{_GP}",
            r"\bpopad\b",
            r"\bpopa\b",
            r"\bpopfd\b",
        ],
    },
    # -- ARITHMETIC --
    {
        "name": "arithmetic",
        "desc": "Arithmetic — add/sub/neg/not/xor/and/or/inc/dec/shl/shr/rol/ror/mul/div/sbb/adc",
        "patterns": [
            rf"\badd\s+{_GP_BYTE}\s*,",
            rf"\bsub\s+{_GP_BYTE}\s*,",
            rf"\binc\s+{_GP}",
            rf"\bdec\s+{_GP}",
            rf"\bneg\s+{_GP}",
            rf"\bnot\s+{_GP}",
            rf"\bxor\s+{_GP}\s*,\s*(?:{_GP}|0x)",
            rf"\band\s+(?:{_GP}|al|ah)\s*,",
            rf"\bor\s+{_GP}\s*,",
            r"\bshl\s+",
            r"\bshr\s+",
            r"\bsar\s+",
            r"\brol\s+",
            r"\bror\s+",
            rf"\bsbb\s+{_GP}",
            rf"\badc\s+{_GP}",
            r"\bmul\s+",
            r"\bdiv\s+",
            r"\bimul\s+",
            r"\bidiv\s+",
        ],
    },
    # -- CONDITIONALS --
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
    # -- NOPS --
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

# What constitutes a "return" on this arch
RETURN_PATTERN = r"\bret[n]?\b"

# Chain killer: leave = mov esp, ebp; pop ebp
LEAVE_PATTERN = r"\bleave\b"
LEAVE_DESC = (
    "LEAVE gadgets — contain 'leave' (mov esp,ebp; pop ebp).\n"
    "# Chain killer unless you control EBP. Use only as last resort."
)

# JMP/CALL pattern
JMP_CALL_PATTERN = r"\b(?:jmp|call)\b"

# Minor clobber detection for cleanliness scoring
MINOR_CLOBBER_PATTERN = r"\b(?:add|sub|and|or|xor)\s+(?:[abcd][lh]|d[lh])\s*,"

# retn N pattern (extra stack consumption)
RETN_EXTRA_PATTERN = r"\bretn\s+0x([0-9a-f]+)"

# Carry-flag dependent instructions
CARRY_FLAG_PATTERN = r"\b(?:sbb|adc)\b"
