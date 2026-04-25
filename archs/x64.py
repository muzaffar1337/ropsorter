"""x64 (64-bit) architecture patterns for ropsorter."""

ARCH_NAME = "x64"

REGISTERS = {
    "gp": [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ],
    "sp": "rsp",
    "bp": "rbp",
    "byte": [
        "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
        "sil", "dil", "bpl", "spl",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    ],
    "dword": [
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    ],
}

_GP = r"(?:rax|rbx|rcx|rdx|rsi|rdi|rbp|r8|r9|r1[0-5])"
_GP_SP = r"(?:rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r1[0-5])"
_GP32 = r"(?:eax|ebx|ecx|edx|esi|edi|ebp|r8d|r9d|r1[0-5]d)"
_GP_ALL = r"(?:rax|rbx|rcx|rdx|rsi|rdi|rbp|r8|r9|r1[0-5]|eax|ebx|ecx|edx|esi|edi|ebp|r8d|r9d|r1[0-5]d)"
_BYTE = r"(?:al|ah|bl|bh|cl|ch|dl|dh|sil|dil|bpl|spl|r[89]b|r1[0-5]b)"
_SIZE = r"(?:qword|dword|word|byte)"

CATEGORIES = [
    # -- PIVOTS: redirect RSP --
    {
        "name": "pivots",
        "desc": "Stack Pivots — redirect RSP",
        "patterns": [
            rf"xchg\s+rsp\s*,\s*{_GP}",
            rf"xchg\s+{_GP}\s*,\s*rsp",
            r"mov\s+rsp\s*,",
            r"lea\s+rsp\s*,",
            r"add\s+rsp\s*,",
            r"sub\s+rsp\s*,",
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
            r"\bstosq\b",
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
        "desc": "Readers — read from memory: mov reg, [reg] / mov reg, qword [reg+off]",
        "patterns": [
            rf"mov\s+{_GP_ALL}\s*,\s*{_SIZE}?\s*\[",
            r"\blodsq\b",
            r"\blodsd\b",
            r"\blodsw\b",
            r"\blodsb\b",
            rf"\blea\s+{_GP_ALL}\s*,\s*\[",
            rf"\badd\s+{_GP_ALL}\s*,\s*{_SIZE}?\s*\[",
            rf"\bsub\s+{_GP_ALL}\s*,\s*{_SIZE}?\s*\[",
            rf"\bxor\s+{_GP_ALL}\s*,\s*{_SIZE}?\s*\[",
            rf"\band\s+{_GP_ALL}\s*,\s*{_SIZE}?\s*\[",
            rf"\bor\s+{_GP_ALL}\s*,\s*{_SIZE}?\s*\[",
        ],
    },
    # -- TRANSFERS: reg to reg --
    {
        "name": "transfers",
        "desc": "Transfers — register-to-register (cleanest listed first)",
        "patterns": [
            rf"mov\s+{_GP}\s*,\s*{_GP_SP}\s*;",
            rf"mov\s+{_GP32}\s*,\s*{_GP32}\s*;",
            rf"push\s+{_GP_SP}.*pop\s+{_GP}",
            rf"xchg\s+{_GP}\s*,\s*{_GP}",
            rf"movzx\s+{_GP_ALL}\s*,",
            rf"movsx\s+{_GP_ALL}\s*,",
            rf"movsxd\s+{_GP}\s*,",
            r"\bcqo\b",
            r"\bcdqe\b",
            r"\bcdq\b",
        ],
    },
    # -- LOADERS: pop from stack --
    {
        "name": "loaders",
        "desc": "Loaders — pop controlled values from stack into registers",
        "patterns": [
            rf"\bpop\s+{_GP}",
            r"\bpopfq\b",
        ],
    },
    # -- ARITHMETIC --
    {
        "name": "arithmetic",
        "desc": "Arithmetic — add/sub/neg/not/xor/and/or/inc/dec/shl/shr/rol/ror/mul/div/sbb/adc",
        "patterns": [
            rf"\badd\s+{_GP_ALL}\s*,",
            rf"\bsub\s+{_GP_ALL}\s*,",
            rf"\binc\s+{_GP_ALL}",
            rf"\bdec\s+{_GP_ALL}",
            rf"\bneg\s+{_GP_ALL}",
            rf"\bnot\s+{_GP_ALL}",
            rf"\bxor\s+{_GP_ALL}\s*,\s*(?:{_GP_ALL}|0x)",
            rf"\band\s+{_GP_ALL}\s*,",
            rf"\bor\s+{_GP_ALL}\s*,",
            r"\bshl\s+",
            r"\bshr\s+",
            r"\bsar\s+",
            r"\brol\s+",
            r"\bror\s+",
            rf"\bsbb\s+{_GP_ALL}",
            rf"\badc\s+{_GP_ALL}",
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

RETURN_PATTERN = r"\bret[n]?\b"

LEAVE_PATTERN = r"\bleave\b"
LEAVE_DESC = (
    "LEAVE gadgets — contain 'leave' (mov rsp,rbp; pop rbp).\n"
    "# Chain killer unless you control RBP. Use only as last resort."
)

JMP_CALL_PATTERN = r"\b(?:jmp|call)\b"

MINOR_CLOBBER_PATTERN = (
    r"\b(?:add|sub|and|or|xor)\s+"
    r"(?:[abcd][lh]|sil|dil|bpl|spl|r[89]b|r1[0-5]b)\s*,"
)

RETN_EXTRA_PATTERN = r"\bretn\s+0x([0-9a-f]+)"

CARRY_FLAG_PATTERN = r"\b(?:sbb|adc)\b"
