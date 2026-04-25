"""ARM64 / AArch64 architecture patterns for ropsorter."""

ARCH_NAME = "arm64"

REGISTERS = {
    "gp": [f"x{i}" for i in range(31)] + [f"w{i}" for i in range(31)],
    "sp": "sp",
    "bp": "x29",       # frame pointer (fp) is x29 by convention
    "lr": "x30",       # link register
    "zero": ["xzr", "wzr"],
    "byte": [],         # no separate byte registers
}

_X = r"(?:x\d{1,2}|x30)"
_W = r"(?:w\d{1,2}|w30)"
_GP = r"(?:x\d{1,2}|x30|w\d{1,2}|w30)"
_GP_SP = r"(?:x\d{1,2}|x30|sp)"
_REGLIST = r"\{[^}]+\}"  # not used as much in aarch64 but some tools show it

CATEGORIES = [
    # -- PIVOTS: redirect SP --
    {
        "name": "pivots",
        "desc": "Stack Pivots — redirect SP",
        "patterns": [
            rf"\bmov\s+sp\s*,\s*{_X}",
            r"\badd\s+sp\s*,\s*sp\s*,",
            r"\bsub\s+sp\s*,\s*sp\s*,",
            r"\bldr\s+sp\s*,",
        ],
    },
    # -- WRITERS: store to memory --
    {
        "name": "writers",
        "desc": "Writers — store to memory: str xN, [xM] / stp / stur",
        "patterns": [
            rf"\bstr\s+{_GP}\s*,\s*\[",
            rf"\bstrb\s+{_W}\s*,\s*\[",
            rf"\bstrh\s+{_W}\s*,\s*\[",
            rf"\bstp\s+{_GP}\s*,\s*{_GP}\s*,\s*\[",
            rf"\bstur\s+{_GP}\s*,\s*\[",
            rf"\bsturb\s+{_W}\s*,\s*\[",
            rf"\bsturh\s+{_W}\s*,\s*\[",
        ],
    },
    # -- READERS: load from memory --
    {
        "name": "readers",
        "desc": "Readers — load from memory: ldr xN, [xM] / ldp / ldur",
        "patterns": [
            rf"\bldr\s+{_GP}\s*,\s*\[",
            rf"\bldrb\s+{_W}\s*,\s*\[",
            rf"\bldrh\s+{_W}\s*,\s*\[",
            rf"\bldrsb\s+{_GP}\s*,\s*\[",
            rf"\bldrsh\s+{_GP}\s*,\s*\[",
            rf"\bldrsw\s+{_X}\s*,\s*\[",
            rf"\bldp\s+{_GP}\s*,\s*{_GP}\s*,\s*\[",
            rf"\bldur\s+{_GP}\s*,\s*\[",
            rf"\bldurb\s+{_W}\s*,\s*\[",
            rf"\bldurh\s+{_W}\s*,\s*\[",
            rf"\badrp?\s+{_X}\s*,",
        ],
    },
    # -- TRANSFERS: reg to reg / immediate --
    {
        "name": "transfers",
        "desc": "Transfers — register moves: mov xN, xM / mov xN, #imm / mov xN, sp",
        "patterns": [
            rf"\bmov\s+{_GP}\s*,\s*{_GP}",
            rf"\bmov\s+{_GP}\s*,\s*sp",         # mov xN, sp
            rf"\bmov\s+{_GP}\s*,\s*(?:xzr|wzr)", # mov xN, xzr/wzr (zero)
            rf"\bmov\s+{_GP}\s*,\s*#",           # mov xN, #imm (immediate)
            rf"\bmvn\s+{_GP}\s*,\s*{_GP}",
            rf"\buxtb\s+{_GP}\s*,",
            rf"\buxth\s+{_GP}\s*,",
            rf"\bsxtb\s+{_GP}\s*,",
            rf"\bsxth\s+{_GP}\s*,",
            rf"\bsxtw\s+{_X}\s*,",
        ],
    },
    # -- LOADERS: pop/load from stack --
    {
        "name": "loaders",
        "desc": "Loaders — load controlled values from stack: ldp from sp, ldr from sp",
        "patterns": [
            # ldp xN, xM, [sp], #imm  (post-index load pair from stack)
            rf"\bldp\s+{_GP}\s*,\s*{_GP}\s*,\s*\[sp\]",
            rf"\bldp\s+{_GP}\s*,\s*{_GP}\s*,\s*\[sp\s*,",
            # ldr xN, [sp, #off]
            rf"\bldr\s+{_GP}\s*,\s*\[sp\s*[,\]]",
        ],
    },
    # -- ARITHMETIC --
    {
        "name": "arithmetic",
        "desc": "Arithmetic — add/sub/neg/mvn/eor/and/orr/bic/lsl/lsr/asr/ror/mul/madd/msub",
        "patterns": [
            rf"\badd\s+{_GP}\s*,\s*(?:{_GP}|sp)\s*,",
            rf"\bsub\s+{_GP}\s*,\s*(?:{_GP}|sp)\s*,",
            rf"\badds\s+{_GP}\s*,",
            rf"\bsubs\s+{_GP}\s*,",
            rf"\bneg\s+{_GP}\s*,",
            rf"\bmvn\s+{_GP}\s*,\s*#",
            rf"\band\s+{_GP}\s*,\s*{_GP}\s*,",
            rf"\bands\s+{_GP}\s*,",
            rf"\borr\s+{_GP}\s*,\s*{_GP}\s*,",
            rf"\beor\s+{_GP}\s*,\s*{_GP}\s*,",
            rf"\bbic\s+{_GP}\s*,",
            rf"\bmul\s+{_GP}\s*,",
            rf"\bmadd\s+{_GP}\s*,",
            rf"\bmsub\s+{_GP}\s*,",
            rf"\bumull\s+{_X}\s*,",
            rf"\bsmull\s+{_X}\s*,",
            rf"\budiv\s+{_GP}\s*,",
            rf"\bsdiv\s+{_GP}\s*,",
            r"\blsl\s+",
            r"\blsr\s+",
            r"\basr\s+",
            r"\bror\s+",
            rf"\bclz\s+{_GP}\s*,",
            rf"\brbit\s+{_GP}\s*,",
            rf"\brev\s+{_GP}\s*,",
            rf"\brev16\s+{_GP}\s*,",
            rf"\brev32\s+{_X}\s*,",
            rf"\badc\s+{_GP}\s*,",
            rf"\bsbc\s+{_GP}\s*,",
        ],
    },
    # -- CONDITIONALS --
    {
        "name": "conditionals",
        "desc": "Conditionals — cmp/cmn/tst/ccmp/csel/cset/csinc/csinv/csneg",
        "patterns": [
            r"\bcmp\s+",
            r"\bcmn\s+",
            r"\btst\s+",
            r"\bccmp\s+",
            r"\bccmn\s+",
            rf"\bcsel\s+{_GP}\s*,",
            rf"\bcset\s+{_GP}\s*,",
            rf"\bcsinc\s+{_GP}\s*,",
            rf"\bcsinv\s+{_GP}\s*,",
            rf"\bcsneg\s+{_GP}\s*,",
        ],
    },
    # -- NOPS --
    {
        "name": "nops",
        "desc": "NOPs — bare ret, nop, alignment gadgets",
        "patterns": [
            r"^0x[0-9a-fA-F]+:\s*ret\s*;",
            r"^0x[0-9a-fA-F]+:\s*nop\b",
        ],
    },
]

# ARM64 ret = br x30 (return to link register)
RETURN_PATTERN = r"\bret\b"

# No direct 'leave' equivalent on ARM64
LEAVE_PATTERN = None
LEAVE_DESC = None

# JMP/CALL: branches
JMP_CALL_PATTERN = r"\b(?:b\s+|bl\s+|blr\s+|br\s+(?!x30))"

# No byte sub-registers to clobber
MINOR_CLOBBER_PATTERN = None

# No retn N on ARM64
RETN_EXTRA_PATTERN = None

# Carry-flag dependent
CARRY_FLAG_PATTERN = r"\b(?:adc|sbc)\b"
