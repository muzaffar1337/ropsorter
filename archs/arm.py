"""ARM (32-bit) architecture patterns for ropsorter."""

ARCH_NAME = "arm"

REGISTERS = {
    "gp": ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12"],
    "sp": "sp",
    "bp": "r11",      # frame pointer (fp) is r11 by convention
    "lr": "lr",        # link register (r14)
    "pc": "pc",        # program counter (r15)
    "byte": [],        # ARM doesn't have separate byte registers
}

_GP = r"(?:r\d{1,2})"
_GP_ALL = r"(?:r\d{1,2}|sp|lr|pc|fp|ip)"
_REGLIST = r"\{[^}]+\}"  # {r0, r1, ...} register lists

CATEGORIES = [
    # -- PIVOTS: redirect SP --
    {
        "name": "pivots",
        "desc": "Stack Pivots — redirect SP",
        "patterns": [
            r"\bmov\s+sp\s*,\s*" + _GP,
            r"\badd\s+sp\s*,\s*sp\s*,",
            r"\bsub\s+sp\s*,\s*sp\s*,",
            r"\bldr\s+sp\s*,",
        ],
    },
    # -- WRITERS: store to memory --
    {
        "name": "writers",
        "desc": "Writers — store to memory: str rN, [rM] / stm / strd",
        "patterns": [
            rf"\bstr\s+{_GP_ALL}\s*,\s*\[",
            rf"\bstrb\s+{_GP_ALL}\s*,\s*\[",
            rf"\bstrh\s+{_GP_ALL}\s*,\s*\[",
            rf"\bstrd\s+{_GP_ALL}\s*,",
            r"\bstm(?:ia|ib|da|db|fd|fa|ed|ea)?\s+",
            r"\bpush\s+\{",
        ],
    },
    # -- READERS: load from memory --
    {
        "name": "readers",
        "desc": "Readers — load from memory: ldr rN, [rM] / ldm / ldrd",
        "patterns": [
            rf"\bldr\s+{_GP}\s*,\s*\[",
            rf"\bldrb\s+{_GP}\s*,\s*\[",
            rf"\bldrh\s+{_GP}\s*,\s*\[",
            rf"\bldrsb\s+{_GP}\s*,\s*\[",
            rf"\bldrsh\s+{_GP}\s*,\s*\[",
            rf"\bldrd\s+{_GP}\s*,",
            # ldm that doesn't include sp or pc (those are pivots/returns)
            r"\bldm(?:ia|ib|da|db|fd|fa|ed|ea)?\s+(?!sp)",
        ],
    },
    # -- TRANSFERS: reg to reg / immediate --
    {
        "name": "transfers",
        "desc": "Transfers — register moves: mov rN, rM / mov rN, #imm",
        "patterns": [
            rf"\bmov\s+{_GP}\s*,\s*{_GP_ALL}",
            rf"\bmov\s+{_GP}\s*,\s*#",         # mov rN, #imm (immediate load)
            rf"\bmvn\s+{_GP}\s*,\s*{_GP_ALL}",
            # push {rX}; pop {rY} transfer
            r"\bpush\s+\{[^}]+\}.*pop\s+\{[^}]+\}",
            rf"\buxtb\s+{_GP}\s*,",
            rf"\buxth\s+{_GP}\s*,",
            rf"\bsxtb\s+{_GP}\s*,",
            rf"\bsxth\s+{_GP}\s*,",
        ],
    },
    # -- LOADERS: pop from stack --
    {
        "name": "loaders",
        "desc": "Loaders — pop controlled values from stack into registers",
        "patterns": [
            r"\bpop\s+\{[^}]+\}",             # pop {regs} (including pop {r0, pc} — ARM returns this way)
            r"\bldm(?:ia|fd)?\s+sp!\s*,\s*\{", # ldm sp!, {regs}
        ],
    },
    # -- ARITHMETIC --
    {
        "name": "arithmetic",
        "desc": "Arithmetic — add/sub/rsb/mul/and/orr/eor/bic/lsl/lsr/asr/ror",
        "patterns": [
            rf"\badd\s+{_GP}\s*,",
            rf"\bsub\s+{_GP}\s*,",
            rf"\brsb\s+{_GP}\s*,",
            rf"\badc\s+{_GP}\s*,",
            rf"\bsbc\s+{_GP}\s*,",
            rf"\brsc\s+{_GP}\s*,",
            rf"\band\s+{_GP}\s*,",
            rf"\borr\s+{_GP}\s*,",
            rf"\beor\s+{_GP}\s*,",
            rf"\bbic\s+{_GP}\s*,",
            rf"\bmvn\s+{_GP}\s*,\s*#",
            rf"\bmul\s+{_GP}\s*,",
            rf"\bmla\s+{_GP}\s*,",
            rf"\bumull\s+",
            rf"\bsmull\s+",
            r"\blsl\s+",
            r"\blsr\s+",
            r"\basr\s+",
            r"\bror\s+",
            rf"\bclz\s+{_GP}\s*,",
            rf"\brbit\s+{_GP}\s*,",
            rf"\brev\s+{_GP}\s*,",
        ],
    },
    # -- CONDITIONALS --
    {
        "name": "conditionals",
        "desc": "Conditionals — cmp/cmn/tst/teq/it",
        "patterns": [
            r"\bcmp\s+",
            r"\bcmn\s+",
            r"\btst\s+",
            r"\bteq\s+",
            r"\bit[te]{0,3}\s+",  # IT blocks (Thumb-2)
            r"\bmov(?:eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)\s+",
        ],
    },
    # -- NOPS --
    {
        "name": "nops",
        "desc": "NOPs — bare bx lr, nop, alignment gadgets",
        "patterns": [
            r"^0x[0-9a-fA-F]+:\s*bx\s+lr\s*;",
            r"^0x[0-9a-fA-F]+:\s*mov\s+pc\s*,\s*lr\s*;",
            r"^0x[0-9a-fA-F]+:\s*pop\s+\{pc\}\s*;",
            r"^0x[0-9a-fA-F]+:\s*nop\b",
        ],
    },
]

# ARM returns via bx lr or pop {pc}
RETURN_PATTERN = r"\b(?:bx\s+lr|pop\s+\{[^}]*pc[^}]*\})\b"

# No direct 'leave' equivalent on ARM
LEAVE_PATTERN = None
LEAVE_DESC = None

# JMP/CALL: branches and bl (branch-and-link)
JMP_CALL_PATTERN = r"\b(?:b(?!x\s+lr)\s+|bl\s+|blx\s+|bx\s+(?!lr)|mov\s+pc\s*,\s*(?!lr))"

# No byte sub-registers to clobber on ARM
MINOR_CLOBBER_PATTERN = None

# No retn N on ARM
RETN_EXTRA_PATTERN = None

# Carry-flag dependent
CARRY_FLAG_PATTERN = r"\b(?:adc|sbc|rsc)\b"
