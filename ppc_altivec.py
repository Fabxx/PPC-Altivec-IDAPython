# reference: https://python.docs.hex-rays.com/annotated.html

import idaapi
import ida_funcs
import idautils
import ida_bytes
import ida_loader
import ida_kernwin
import ida_ua
import ida_idp
import ida_lines

from enum import IntEnum
from idaapi import get_dword

# Operand identifiers (they map into g_altivecOperands array)

class AltivecOperandID(IntEnum):
    NO_OPERAND = 0
    VA = 1
    VB = 2
    VC = 3
    VD = 4
    VS = VD  # Alias
    SIMM = 5
    UIMM = 6
    SHB = 7
    RA = 8
    RB = 9
    STRM = 10

    # Takires: Added operand identifiers
    RS = 11
    RT = RS  # Alias
    L15 = 12
    L9_10 = 13
    LS = L9_10  # Alias
    L10 = 14
    L = L10  # Alias
    VD128 = 15
    VS128 = VD128  # Alias
    CRM = 16
    VA128 = 17
    VB128 = 18
    VC128 = 19
    VPERM128 = 20
    VD3D0 = 21
    VD3D1 = 22
    VD3D2 = 23
    RA0 = 24

    # LEV, FL1, FL2, SV, SVC_LEV

    SPR = 25

    # Gekko specific
    FA = 26
    FB = 27
    FC = 28
    FD = 29
    FS = FD  # Alias

    crfD = 30

    WB = 31
    IB = 32
    WC = 33
    IC = 34

    # RA, RB
    DRA = 35
    DRB = 36


# Class used to define an operand


class CbeaSprg:
    def __init__(self, sprg: int, short_name: str, comment: str):
        self.sprg = sprg
        self.short_name = short_name
        self.comment = comment

    def __repr__(self):
        return f"CbeaSprg({self.sprg}, '{self.short_name}', '{self.comment}')"


g_cbeaSprgs = [
    CbeaSprg(1023, "PIR", "Processor Identification Register"),
    CbeaSprg(1022, "BP_VR", "CBEA-Compliant Processor Version Register"),
    CbeaSprg(1017, "HID6", "Hardware Implementation Register 6"),
    CbeaSprg(1015, "DABRX", "Data Address Breakpoint Register Extension"),
    CbeaSprg(1013, "DABR", "Data Address Breakpoint Register"),
    CbeaSprg(1012, "HID4", "Hardware Implementation Register 4"),
    CbeaSprg(1009, "HID1", "Hardware Implementation Register 1"),
    CbeaSprg(1008, "HID0", "Hardware Implementation Register 0"),
    CbeaSprg(981, "ICIDR", "Instruction Class ID Register 1"),
    CbeaSprg(980, "IRMR1", "Instruction Range Mask Register 1"),
    CbeaSprg(979, "IRSR1", "Instruction Range Start Register 1"),
    CbeaSprg(978, "ICIDR0", "Instruction Class ID Register 0"),
    CbeaSprg(977, "IRMR0", "Instruction Range Mask Register 0"),
    CbeaSprg(976, "IRSR0", "Instruction Range Start Register 0"),
    CbeaSprg(957, "DCIDR1", "Data Class ID Register 1"),
    CbeaSprg(956, "DRMR1", "Data Range Mask Register 1"),
    CbeaSprg(955, "DRSR1", "Data Range Start Register 1"),
    CbeaSprg(954, "DCIDR0", "Data Class ID Register 0"),
    CbeaSprg(953, "DRMR0", "Data Range Mask Register 0"),
    CbeaSprg(952, "DRSR0", "Data Range Start Register 0"),
    CbeaSprg(951, "PPE_TLB_RMT", "PPE Translation Lookaside Buffer RMT Register"),
    CbeaSprg(949, "PPE_TLB_RPN", "PPE Translation Lookaside Buffer Real-Page Number"),
    CbeaSprg(948, "PPE_TLB_VPN", "PPE Translation Lookaside Buffer Virtual-Page Number"),
    CbeaSprg(947, "PPE_TLB_Index", "PPE Translation Lookaside Buffer Index Register"),
    CbeaSprg(946, "PPE_TLB_Index_Hint", "PPE Translation Lookaside Buffer Index Hint Register"),
    CbeaSprg(922, "TTR", "Thread Switch Timeout Register"),
    CbeaSprg(921, "TSCR", "Thread Switch Control Register"),
    CbeaSprg(897, "TSRR", "Thread Status Register Remote"),
    CbeaSprg(896, "TSRL", "Thread Status Register Local"),
    CbeaSprg(319, "LPIDR", "Logical Partition Identity Register"),
    CbeaSprg(318, "LPCR", "Logical Partition Control Register"),
    CbeaSprg(315, "HSRR1", "Hypervisor Machine Status Save/Restore Register 1"),
    CbeaSprg(314, "HSRR0", "Hypervisor Machine Status Save/Restore Register 0"),
    CbeaSprg(313, "HRMOR", "Hypervisor Real Mode Offset Register"),
    CbeaSprg(312, "RMOR", "Real Mode Offset Register"),
    CbeaSprg(310, "HDEC", "Hypervisor Decrementer Register"),
    CbeaSprg(305, "HSPRG1", "Hypervisor Software Use Special Purpose Register 1"),
    CbeaSprg(304, "HSPRG0", "Hypervisor Software Use Special Purpose Register 0"),
    CbeaSprg(287, "PVR", "PPE Processor Version Register"),
    CbeaSprg(285, "TBU", "Time Base Upper Register - Write Only"),
    CbeaSprg(284, "TBL", "Time Base Lower Register - Write Only"),
    CbeaSprg(275, "SPRG3", "Software Use Special Purpose Register 3"),
    CbeaSprg(274, "SPRG2", "Software Use Special Purpose Register 2"),
    CbeaSprg(273, "SPRG1", "Software Use Special Purpose Register 1"),
    CbeaSprg(272, "SPRG0", "Software Use Special Purpose Register 0"),
    CbeaSprg(269, "TBU", "Time Base Upper Register - Read Only"),
    CbeaSprg(268, "TB", "Time Base Register - Read Only"),
    CbeaSprg(259, "SPRG3", "Software Use Special Purpose Register 3"),
    CbeaSprg(256, "VRSAVE", "VXU Register Save"),
    CbeaSprg(152, "CTRL", "Control Register Write"),
    CbeaSprg(136, "CTRL", "Control Register Read"),
    CbeaSprg(29, "ACCR", "Address Compare Control Register"),
    CbeaSprg(27, "SRR1", "Machine Status Save/Restore Register 1"),
    CbeaSprg(26, "SRR0", "Machine Status Save/Restore Register 0"),
    CbeaSprg(25, "SDR1", "Storage Description Register 1"),
    CbeaSprg(22, "DEC", "Decrementer Register"),
    CbeaSprg(19, "DAR", "Data Address Register"),
    CbeaSprg(18, "DSISR", "Data Storage Interrupt Status Register"),
    CbeaSprg(9, "CTR", "Count Register"),
    CbeaSprg(8, "LR", "Link Register"),
    CbeaSprg(1, "XER", "Fixed-Point Exception Register"),
]

class AltivecOperand:
    def __init__(self, bits: int, shift: int):
        self.bits = bits
        self.shift = shift

    def __repr__(self):
        return f"AltivecOperand(bits={self.bits}, shift={self.shift})"


altivec_operands = [ # // {Length, Start bit}
    (0, 0),    # No Operand
    (5, 16),   # VA
    (5, 11),   # VB
    (5, 6),    # VC
    (5, 21),   # VD / VS
    (5, 16),   # SIMM
    (5, 16),   # UIMM
    (4, 6),    # SHB
    (5, 16),   # RA
    (5, 11),   # RB
    (2, 21),   # STRM

    # Takires: Added operands
    (5, 21),   # RS / RT
    (1, 16),   # L15
    (2, 21),   # L9_10
    (1, 21),   # L10
    (0, 0),    # VD128 / VS128
    (8, 12),   # CRM
    (0, 0),    # VA128
    (0, 0),    # VB128
    (3, 8),    # VC128
    (0, 0),    # VPERM128
    (3, 18),   # VD3D0
    (2, 16),   # VD3D1
    (2, 6),    # VD3D2
    (5, 16),   # RA0
    (10, 11),  # SPR

    # Gekko specific
    (5, 16),   # FA
    (5, 11),   # FB
    (5, 6),    # FC
    (5, 21),   # FD/FS
    (3, 23),   # crfD
    (1, 16),   # WB
    (3, 12),   # IB
    (1, 10),   # WC
    (3, 7),    # IC
    (5, 16),   # DRA
    (5, 11),   # DRB
]

# Macros used to define opcode table

def OP(x):
    return ((x & 0x3F) << 26)

OP_MASK = OP(0x3F)

def SC(op, sa, lk):
    return OP(op) | ((sa & 1) << 1) | (lk & 1)

SC_MASK = SC(0x3F, 0x3FF, 1)

def VX(op, xop):
    return OP(op) | (xop & 0x7FF)

VX_MASK = VX(0x3F, 0x7FF)

def VXR(op, xop, rc):
    return OP(op) | ((rc & 1) << 10) | (xop & 0x3FF)

VXR_MASK = VXR(0x3F, 0x3FF, 1)

def X(op, xop):
    return OP(op) | ((xop & 0x3FF) << 1)

X_MASK = X(0x3F, 0x3FF)

RA_MASK = (0x1F << 16)
RB_MASK = (0x1F << 11)
RT_MASK = (0x1F << 21)

def VXA(op, xop):
    return OP(op) | (xop & 0x3F)

VXA_MASK = VXA(0x3F, 0x3F)

def XDSS(op, xop, a):
    return X(op, xop) | ((a & 1) << 25)

XDSS_MASK = XDSS(0x3F, 0x3FF, 1)

def VX128(op, xop):
    return OP(op) | (xop & 0x3D0)

VX128_MASK = VX(0x3F, 0x3D0)

def VX128_1(op, xop):
    return OP(op) | (xop & 0x7F3)

VX128_1_MASK = VX(0x3F, 0x7F3)

def VX128_2(op, xop):
    return OP(op) | (xop & 0x210)

VX128_2_MASK = VX(0x3F, 0x210)

def VX128_3(op, xop):
    return OP(op) | (xop & 0x7F0)

VX128_3_MASK = VX(0x3F, 0x7F0)

def VX128_P(op, xop):
    return OP(op) | (xop & 0x630)

VX128_P_MASK = VX(0x3F, 0x630)

def VX128_4(op, xop):
    return OP(op) | (xop & 0x730)

VX128_4_MASK = VX(0x3F, 0x730)

def VX128_5(op, xop):
    return OP(op) | (xop & 0x10)

VX128_5_MASK = VX(0x3F, 0x10)


def XFX(op, xop, a):
    return X(op, xop) | ((a & 1) << 20)

XFX_MASK = XFX(0x3F, 0x3FF, 1)

def XRT(op, xop, rt):
    return X(op, xop) | ((rt & 0x1F) << 21)

XRT_MASK = XRT(0x3F, 0x3FF, 0x1F)

def XRA(op, xop, ra):
    return X(op, xop) | ((ra & 0x1F) << 16)

XRA_MASK = X_MASK | RA_MASK

def XRC(op, xop, rc):
    return X(op, xop) | (rc & 1)

XRARB_MASK = X_MASK | RA_MASK | RB_MASK
XRLARB_MASK = XRARB_MASK & ~(1 << 16)

def XSYNC(op, xop, l):
    return X(op, xop) | ((l & 3) << 21)

XRTRA_MASK = X_MASK | RT_MASK | RA_MASK
XRTLRA_MASK = XRTRA_MASK & ~(1 << 21)

# gekko specific

def OPS(op, xop):
    return OP(op) | ((xop & 0x1F) << 1)

def OPSC(op, xop, rc):
    return OPS(op, xop) | (rc & 1)

OPS_MASK = OPSC(0x3F, 0x1F, 1)
OPS_MASK_DOT = OPSC(0x3F, 0x1F, 1)

def OPM(op, xop):
    return OP(op) | ((xop & 0x3F) << 1)

def OPMC(op, xop, rc):
    return OPM(op, xop) | (rc & 1)

OPM_MASK = OPMC(0x3F, 0x3F, 0)

def OPL(op, xop):
    return OP(op) | ((xop & 0x3FF) << 1)

def OPLC(op, xop, rc):
    return OPL(op, xop) | (rc & 1)

OPL_MASK = OPLC(0x3F, 0x3FF, 1)
OPL_MASK_DOT = OPLC(0x3F, 0x3FF, 1)


# Opcode identifiers (they map into g_altivec_opcodes array)
# NOTE: Enums in python by default don't have a value, we must respect the increasing memory range

CUSTOM_INSN_ITYPE = 0x8000

class altivec_insn_type_t(IntEnum):

    altivec_insn_start = CUSTOM_INSN_ITYPE
    altivec_lvebx = altivec_insn_start
    altivec_lvehx = altivec_insn_start + 1
    altivec_lvewx = altivec_insn_start + 2
    altivec_lvsl = altivec_insn_start + 3
    altivec_lvsr = altivec_insn_start + 4
    altivec_lvx = altivec_insn_start + 5
    altivec_lvxl = altivec_insn_start + 6
    altivec_stvebx = altivec_insn_start + 7
    altivec_stvehx = altivec_insn_start + 8
    altivec_stvewx = altivec_insn_start + 9
    altivec_stvx = altivec_insn_start + 10
    altivec_stvxl = altivec_insn_start + 11
    altivec_dst = altivec_insn_start + 12
    altivec_dstt = altivec_insn_start + 13
    altivec_dstst = altivec_insn_start + 14
    altivec_dststt = altivec_insn_start + 15
    altivec_dss = altivec_insn_start + 16
    altivec_dssall = altivec_insn_start + 17
    altivec_mfvscr = altivec_insn_start + 18
    altivec_mtvscr = altivec_insn_start + 19
    altivec_vaddcuw = altivec_insn_start + 20
    altivec_vaddfp = altivec_insn_start + 21
    altivec_vaddsbs = altivec_insn_start + 22
    altivec_vaddshs = altivec_insn_start + 23
    altivec_vaddsws = altivec_insn_start + 24
    altivec_vaddubm = altivec_insn_start + 25
    altivec_vaddubs = altivec_insn_start + 26
    altivec_vadduhm = altivec_insn_start + 27
    altivec_vadduhs = altivec_insn_start + 28
    altivec_vadduwm = altivec_insn_start + 29
    altivec_vadduws = altivec_insn_start + 30
    altivec_vand = altivec_insn_start + 31
    altivec_vandc = altivec_insn_start + 32
    altivec_vavgsb = altivec_insn_start + 33
    altivec_vavgsh = altivec_insn_start + 34
    altivec_vavgsw = altivec_insn_start + 35
    altivec_vavgub = altivec_insn_start + 36
    altivec_vavguh = altivec_insn_start + 37
    altivec_vavguw = altivec_insn_start + 38
    altivec_vcfsx = altivec_insn_start + 39
    altivec_vcfux = altivec_insn_start + 40
    altivec_vcmpbfp = altivec_insn_start + 41
    altivec_vcmpbfp_c = altivec_insn_start + 42
    altivec_vcmpeqfp = altivec_insn_start + 43
    altivec_vcmpeqfp_c = altivec_insn_start + 44
    altivec_vcmpequb = altivec_insn_start + 45
    altivec_vcmpequb_c = altivec_insn_start + 46
    altivec_vcmpequh = altivec_insn_start + 47
    altivec_vcmpequh_c = altivec_insn_start + 48
    altivec_vcmpequw = altivec_insn_start + 49
    altivec_vcmpequw_c = altivec_insn_start + 50
    altivec_vcmpgefp = altivec_insn_start + 51
    altivec_vcmpgefp_c = altivec_insn_start + 52
    altivec_vcmpgtfp = altivec_insn_start + 53
    altivec_vcmpgtfp_c = altivec_insn_start + 54
    altivec_vcmpgtsb = altivec_insn_start + 55
    altivec_vcmpgtsb_c = altivec_insn_start + 56
    altivec_vcmpgtsh = altivec_insn_start + 57
    altivec_vcmpgtsh_c = altivec_insn_start + 58
    altivec_vcmpgtsw = altivec_insn_start + 59
    altivec_vcmpgtsw_c = altivec_insn_start + 60
    altivec_vcmpgtub = altivec_insn_start + 61
    altivec_vcmpgtub_c = altivec_insn_start + 62
    altivec_vcmpgtuh = altivec_insn_start + 63
    altivec_vcmpgtuh_c = altivec_insn_start + 64
    altivec_vcmpgtuw = altivec_insn_start + 65
    altivec_vcmpgtuw_c = altivec_insn_start + 66
    altivec_vctsxs = altivec_insn_start + 67
    altivec_vctuxs = altivec_insn_start + 68
    altivec_vexptefp = altivec_insn_start + 69
    altivec_vlogefp = altivec_insn_start + 70
    altivec_vmaddfp = altivec_insn_start + 71
    altivec_vmaxfp = altivec_insn_start + 72
    altivec_vmaxsb = altivec_insn_start + 73
    altivec_vmaxsh = altivec_insn_start + 74
    altivec_vmaxsw = altivec_insn_start + 75
    altivec_vmaxub = altivec_insn_start + 76
    altivec_vmaxuh = altivec_insn_start + 77
    altivec_vmaxuw = altivec_insn_start + 78
    altivec_vmhaddshs = altivec_insn_start + 79
    altivec_vmhraddshs = altivec_insn_start + 80
    altivec_vminfp = altivec_insn_start + 81
    altivec_vminsb = altivec_insn_start + 82
    altivec_vminsh = altivec_insn_start + 83
    altivec_vminsw = altivec_insn_start + 84
    altivec_vminub = altivec_insn_start + 85
    altivec_vminuh = altivec_insn_start + 86
    altivec_vminuw = altivec_insn_start + 87
    altivec_vmladduhm = altivec_insn_start + 88
    altivec_vmrghb = altivec_insn_start + 89
    altivec_vmrghh = altivec_insn_start + 90
    altivec_vmrghw = altivec_insn_start + 91
    altivec_vmrglb = altivec_insn_start + 92
    altivec_vmrglh = altivec_insn_start + 93
    altivec_vmrglw = altivec_insn_start + 94
    altivec_vmsummbm = altivec_insn_start + 95
    altivec_vmsumshm = altivec_insn_start + 96
    altivec_vmsumshs = altivec_insn_start + 97
    altivec_vmsumubm = altivec_insn_start + 98
    altivec_vmsumuhm = altivec_insn_start + 99
    altivec_vmsumuhs = altivec_insn_start + 100
    altivec_vmulesb = altivec_insn_start + 101
    altivec_vmulesh = altivec_insn_start + 102
    altivec_vmuleub = altivec_insn_start + 103
    altivec_vmuleuh = altivec_insn_start + 104
    altivec_vmulosb = altivec_insn_start + 105
    altivec_vmulosh = altivec_insn_start + 106
    altivec_vmuloub = altivec_insn_start + 107
    altivec_vmulouh = altivec_insn_start + 108
    altivec_vnmsubfp = altivec_insn_start + 109
    altivec_vnor = altivec_insn_start + 110
    altivec_vor = altivec_insn_start + 111
    altivec_vperm = altivec_insn_start + 112
    altivec_vpkpx = altivec_insn_start + 113
    altivec_vpkshss = altivec_insn_start + 114
    altivec_vpkshus = altivec_insn_start + 115
    altivec_vpkswss = altivec_insn_start + 116
    altivec_vpkswus = altivec_insn_start + 117
    altivec_vpkuhum = altivec_insn_start + 118
    altivec_vpkuhus = altivec_insn_start + 119
    altivec_vpkuwum = altivec_insn_start + 120
    altivec_vpkuwus = altivec_insn_start + 121
    altivec_vrefp = altivec_insn_start + 122
    altivec_vrfim = altivec_insn_start + 123
    altivec_vrfin = altivec_insn_start + 124
    altivec_vrfip = altivec_insn_start + 125
    altivec_vrfiz = altivec_insn_start + 126
    altivec_vrlb = altivec_insn_start + 127
    altivec_vrlh = altivec_insn_start + 128
    altivec_vrlw = altivec_insn_start + 129
    altivec_vrsqrtefp = altivec_insn_start + 130
    altivec_vsel = altivec_insn_start + 131
    altivec_vsl = altivec_insn_start + 132
    altivec_vslb = altivec_insn_start + 133
    altivec_vsldoi = altivec_insn_start + 134
    altivec_vslh = altivec_insn_start + 135
    altivec_vslo = altivec_insn_start + 136
    altivec_vslw = altivec_insn_start + 137
    altivec_vspltb = altivec_insn_start + 138
    altivec_vsplth = altivec_insn_start + 139
    altivec_vspltisb = altivec_insn_start + 140
    altivec_vspltish = altivec_insn_start + 141
    altivec_vspltisw = altivec_insn_start + 142
    altivec_vspltw = altivec_insn_start + 143
    altivec_vsr = altivec_insn_start + 144
    altivec_vsrab = altivec_insn_start + 145
    altivec_vsrah = altivec_insn_start + 146
    altivec_vsraw = altivec_insn_start + 147
    altivec_vsrb = altivec_insn_start + 148
    altivec_vsrh = altivec_insn_start + 149
    altivec_vsro = altivec_insn_start + 150
    altivec_vsrw = altivec_insn_start + 151
    altivec_vsubcuw = altivec_insn_start + 152
    altivec_vsubfp = altivec_insn_start + 153
    altivec_vsubsbs = altivec_insn_start + 154
    altivec_vsubshs = altivec_insn_start + 155
    altivec_vsubsws = altivec_insn_start + 156
    altivec_vsububm = altivec_insn_start + 157
    altivec_vsububs = altivec_insn_start + 158
    altivec_vsubuhm = altivec_insn_start + 159
    altivec_vsubuhs = altivec_insn_start + 160
    altivec_vsubuwm = altivec_insn_start + 161
    altivec_vsubuws = altivec_insn_start + 162
    altivec_vsumsws = altivec_insn_start + 163
    altivec_vsum2sws = altivec_insn_start + 164
    altivec_vsum4sbs = altivec_insn_start + 165
    altivec_vsum4shs = altivec_insn_start + 166
    altivec_vsum4ubs = altivec_insn_start + 167
    altivec_vupkhpx = altivec_insn_start + 168
    altivec_vupkhsb = altivec_insn_start + 169
    altivec_vupkhsh = altivec_insn_start + 170
    altivec_vupklpx = altivec_insn_start + 171
    altivec_vupklsb = altivec_insn_start + 172
    altivec_vupklsh = altivec_insn_start + 173
    altivec_vxor = altivec_insn_start + 174
    vmx128_vsldoi128 = altivec_insn_start + 175
    vmx128_lvsl128 = altivec_insn_start + 176
    vmx128_lvsr128 = altivec_insn_start + 177
    vmx128_lvewx128 = altivec_insn_start + 178
    vmx128_lvx128 = altivec_insn_start + 179
    vmx128_stvewx128 = altivec_insn_start + 180
    vmx128_stvx128 = altivec_insn_start + 181
    vmx128_lvxl128 = altivec_insn_start + 182
    vmx128_stvxl128 = altivec_insn_start + 183
    vmx128_lvlx128 = altivec_insn_start + 184
    vmx128_lvrx128 = altivec_insn_start + 185
    vmx128_stvlx128 = altivec_insn_start + 186
    vmx128_stvrx128 = altivec_insn_start + 187
    vmx128_lvlxl128 = altivec_insn_start + 188
    vmx128_lvrxl128 = altivec_insn_start + 189
    vmx128_stvlxl128 = altivec_insn_start + 190
    vmx128_stvrxl128 = altivec_insn_start + 191
    vmx128_vperm128 = altivec_insn_start + 192
    vmx128_vaddfp128 = altivec_insn_start + 193
    vmx128_vsubfp128 = altivec_insn_start + 194
    vmx128_vmulfp128 = altivec_insn_start + 195
    vmx128_vmaddfp128 = altivec_insn_start + 196
    vmx128_vmaddcfp128 = altivec_insn_start + 197
    vmx128_vnmsubfp128 = altivec_insn_start + 198
    vmx128_vmsum3fp128 = altivec_insn_start + 199
    vmx128_vmsum4fp128 = altivec_insn_start + 200
    vmx128_vpkshss128 = altivec_insn_start + 201
    vmx128_vand128 = altivec_insn_start + 202
    vmx128_vpkshus128 = altivec_insn_start + 203
    vmx128_vandc128 = altivec_insn_start + 204
    vmx128_vpkswss128 = altivec_insn_start + 205
    vmx128_vnor128 = altivec_insn_start + 206
    vmx128_vpkswus128 = altivec_insn_start + 207
    vmx128_vor128 = altivec_insn_start + 208
    vmx128_vpkuhum128 = altivec_insn_start + 209
    vmx128_vxor128 = altivec_insn_start + 210
    vmx128_vpkuhus128 = altivec_insn_start + 211
    vmx128_vsel128 = altivec_insn_start + 212
    vmx128_vpkuwum128 = altivec_insn_start + 213
    vmx128_vslo128 = altivec_insn_start + 214
    vmx128_vpkuwus128 = altivec_insn_start + 215
    vmx128_vsro128 = altivec_insn_start + 216
    vmx128_vpermwi128 = altivec_insn_start + 217
    vmx128_vcfpsxws128 = altivec_insn_start + 218
    vmx128_vcfpuxws128 = altivec_insn_start + 219
    vmx128_vcsxwfp128 = altivec_insn_start + 220
    vmx128_vcuxwfp128 = altivec_insn_start + 221
    vmx128_vrfim128 = altivec_insn_start + 222
    vmx128_vrfin128 = altivec_insn_start + 223
    vmx128_vrfip128 = altivec_insn_start + 224
    vmx128_vrfiz128 = altivec_insn_start + 225
    vmx128_vpkd3d128 = altivec_insn_start + 226
    vmx128_vrefp128 = altivec_insn_start + 227
    vmx128_vrsqrtefp128 = altivec_insn_start + 228
    vmx128_vexptefp128 = altivec_insn_start + 229
    vmx128_vlogefp128 = altivec_insn_start + 230
    vmx128_vrlimi128 = altivec_insn_start + 231
    vmx128_vspltw128 = altivec_insn_start + 232
    vmx128_vspltisw128 = altivec_insn_start + 233
    vmx128_vupkd3d128 = altivec_insn_start + 234
    vmx128_vcmpeqfp128 = altivec_insn_start + 235
    vmx128_vcmpeqfp128c = altivec_insn_start + 236
    vmx128_vrlw128 = altivec_insn_start + 237
    vmx128_vcmpgefp128 = altivec_insn_start + 238
    vmx128_vcmpgefp128c = altivec_insn_start + 239
    vmx128_vslw128 = altivec_insn_start + 240
    vmx128_vcmpgtfp128 = altivec_insn_start + 241
    vmx128_vcmpgtfp128c = altivec_insn_start + 242
    vmx128_vsraw128 = altivec_insn_start + 243
    vmx128_vcmpbfp128 = altivec_insn_start + 244
    vmx128_vcmpbfp128c = altivec_insn_start + 245
    vmx128_vsrw128 = altivec_insn_start + 246
    vmx128_vcmpequw128 = altivec_insn_start + 247
    vmx128_vcmpequw128c = altivec_insn_start + 248
    vmx128_vmaxfp128 = altivec_insn_start + 249
    vmx128_vminfp128 = altivec_insn_start + 250
    vmx128_vmrghw128 = altivec_insn_start + 251
    vmx128_vmrglw128 = altivec_insn_start + 252
    vmx128_vupkhsb128 = altivec_insn_start + 253
    vmx128_vupklsb128 = altivec_insn_start + 254
    vmx128_lvlx = altivec_insn_start + 255
    vmx128_lvlxl = altivec_insn_start + 256
    vmx128_lvrx = altivec_insn_start + 257
    vmx128_lvrxl = altivec_insn_start + 258
    vmx128_stvlx = altivec_insn_start + 259
    vmx128_stvlxl = altivec_insn_start + 260
    vmx128_stvrx = altivec_insn_start + 261
    vmx128_stvrxl = altivec_insn_start + 262
    std_attn = altivec_insn_start + 263
    std_dbcz128 = altivec_insn_start + 264
    std_hvsc = altivec_insn_start + 265
    std_mtspr = altivec_insn_start + 266
    std_mfspr = altivec_insn_start + 267
    std_ldbrx = altivec_insn_start + 268
    std_mfocrf = altivec_insn_start + 269
    std_mtmsr = altivec_insn_start + 270
    std_mtmsrd = altivec_insn_start + 271
    std_mtocrf = altivec_insn_start + 272
    std_slbmte = altivec_insn_start + 273
    std_stdbrx = altivec_insn_start + 274
    std_lwsync = altivec_insn_start + 275
    std_ptesync = altivec_insn_start + 276
    std_sync = altivec_insn_start + 277
    std_tlbiel = altivec_insn_start + 278
    std_tlbie = altivec_insn_start + 279
    std_tlbi = altivec_insn_start + 280
    std_slbie = altivec_insn_start + 281
    spec_callthru = altivec_insn_start + 282
    spec_cctpl = altivec_insn_start + 283
    spec_cctpm = altivec_insn_start + 284
    spec_cctph = altivec_insn_start + 285
    spec_db8cyc = altivec_insn_start + 286
    spec_db10cyc = altivec_insn_start + 287
    spec_db12cyc = altivec_insn_start + 288
    spec_db16cyc = altivec_insn_start + 289
    spec_02002000 = altivec_insn_start + 290
    gekko_psq_lx = altivec_insn_start + 291
    gekko_psq_stx = altivec_insn_start + 292
    gekko_psq_lux = altivec_insn_start + 293
    gekko_psq_stux = altivec_insn_start + 294
    gekko_psq_l = altivec_insn_start + 295
    gekko_psq_lu = altivec_insn_start + 296
    gekko_psq_st = altivec_insn_start + 297
    gekko_psq_stu = altivec_insn_start + 298
    gekko_ps_div = altivec_insn_start + 299
    gekko_ps_div_dot = altivec_insn_start + 300
    gekko_ps_sub = altivec_insn_start + 301
    gekko_ps_sub_dot = altivec_insn_start + 302
    gekko_ps_add = altivec_insn_start + 303
    gekko_ps_add_dot = altivec_insn_start + 304
    gekko_ps_sel = altivec_insn_start + 305
    gekko_ps_sel_dot = altivec_insn_start + 306
    gekko_ps_res = altivec_insn_start + 307
    gekko_ps_res_dot = altivec_insn_start + 308
    gekko_ps_mul = altivec_insn_start + 309
    gekko_ps_mul_dot = altivec_insn_start + 310
    gekko_ps_rsqrte = altivec_insn_start + 311
    gekko_ps_rsqrte_dot = altivec_insn_start + 312
    gekko_ps_msub = altivec_insn_start + 313
    gekko_ps_msub_dot = altivec_insn_start + 314
    gekko_ps_madd = altivec_insn_start + 315
    gekko_ps_madd_dot = altivec_insn_start + 316
    gekko_ps_nmsub = altivec_insn_start + 317
    gekko_ps_nmsub_dot = altivec_insn_start + 318
    gekko_ps_nmadd = altivec_insn_start + 319
    gekko_ps_nmadd_dot = altivec_insn_start + 320
    gekko_ps_neg = altivec_insn_start + 321
    gekko_ps_neg_dot = altivec_insn_start + 322
    gekko_ps_mr = altivec_insn_start + 323
    gekko_ps_mr_dot = altivec_insn_start + 324
    gekko_ps_nabs = altivec_insn_start + 325
    gekko_ps_nabs_dot = altivec_insn_start + 326
    gekko_ps_abs = altivec_insn_start + 327
    gekko_ps_abs_dot = altivec_insn_start + 328
    gekko_ps_sum0 = altivec_insn_start + 329
    gekko_ps_sum0_dot = altivec_insn_start + 330
    gekko_ps_sum1 = altivec_insn_start + 331
    gekko_ps_sum1_dot = altivec_insn_start + 332
    gekko_ps_muls0 = altivec_insn_start + 333
    gekko_ps_muls0_dot = altivec_insn_start + 334
    gekko_ps_muls1 = altivec_insn_start + 335
    gekko_ps_muls1_dot = altivec_insn_start + 336
    gekko_ps_madds0 = altivec_insn_start + 337
    gekko_ps_madds0_dot = altivec_insn_start + 338
    gekko_ps_madds1 = altivec_insn_start + 339
    gekko_ps_madds1_dot = altivec_insn_start + 340
    gekko_ps_cmpu0 = altivec_insn_start + 341
    gekko_ps_cmpo0 = altivec_insn_start + 342
    gekko_ps_cmpu1 = altivec_insn_start + 343
    gekko_ps_cmpo1 = altivec_insn_start + 344
    gekko_ps_merge00 = altivec_insn_start + 345
    gekko_ps_merge00_dot = altivec_insn_start + 346
    gekko_ps_merge01 = altivec_insn_start + 347
    gekko_ps_merge01_dot = altivec_insn_start + 348
    gekko_ps_merge10 = altivec_insn_start + 349
    gekko_ps_merge10_dot = altivec_insn_start + 350
    gekko_ps_merge11 = altivec_insn_start + 351
    gekko_ps_merge11_dot = altivec_insn_start + 352
    gekko_ps_dcbz_l = altivec_insn_start + 353


# Structure used to define an opcode

MAX_OPERANDS = 6

class altivec_opcode:
    def __init__(self, insn: altivec_insn_type_t, name, opcode, mask, operands, description):
        self.insn = insn
        self.name = name
        self.opcode = opcode
        self.mask = mask
        self.operands = operands[:MAX_OPERANDS]
        self.description = description

g_altivec_opcodes = [
 altivec_opcode(altivec_insn_type_t.altivec_lvebx, "lvebx", X(31, 7), X_MASK, [AltivecOperandID.VD, AltivecOperandID.RA, AltivecOperandID.RB], "Load Vector Element Byte Indexed") ,
 altivec_opcode(altivec_insn_type_t.altivec_lvehx, "lvehx", X(31, 39), X_MASK, [AltivecOperandID.VD, AltivecOperandID.RA, AltivecOperandID.RB], "Load Vector Element Half Word Indexed") ,
 altivec_opcode(altivec_insn_type_t.altivec_lvewx, "lvewx", X(31, 71), X_MASK, [AltivecOperandID.VD, AltivecOperandID.RA, AltivecOperandID.RB], "Load Vector Element Word Indexed") ,
 altivec_opcode(altivec_insn_type_t.altivec_lvsl, "lvsl", X(31, 6), X_MASK, [AltivecOperandID.VD, AltivecOperandID.RA, AltivecOperandID.RB], "Load Vector for Shift Left") ,
 altivec_opcode(altivec_insn_type_t.altivec_lvsr, "lvsr", X(31, 38), X_MASK, [AltivecOperandID.VD, AltivecOperandID.RA, AltivecOperandID.RB], "Load Vector for Shift Right") ,
 altivec_opcode(altivec_insn_type_t.altivec_lvx, "lvx", X(31, 103), X_MASK, [AltivecOperandID.VD, AltivecOperandID.RA, AltivecOperandID.RB], "Load Vector Indexed") ,
 altivec_opcode(altivec_insn_type_t.altivec_lvxl, "lvxl", X(31, 359), X_MASK, [AltivecOperandID.VD, AltivecOperandID.RA, AltivecOperandID.RB], "Load Vector Indexed LRU") ,
 altivec_opcode(altivec_insn_type_t.altivec_stvebx, "stvebx", X(31, 135), X_MASK, [AltivecOperandID.VS, AltivecOperandID.RA, AltivecOperandID.RB], "Store Vector Element Byte Indexed") ,
 altivec_opcode(altivec_insn_type_t.altivec_stvehx, "stvehx", X(31, 167), X_MASK, [AltivecOperandID.VS, AltivecOperandID.RA, AltivecOperandID.RB], "Store Vector Element Half Word Indexed") ,
 altivec_opcode(altivec_insn_type_t.altivec_stvewx, "stvewx", X(31, 199), X_MASK, [AltivecOperandID.VS, AltivecOperandID.RA, AltivecOperandID.RB], "Store Vector Element Word Indexed") ,
 altivec_opcode(altivec_insn_type_t.altivec_stvx, "stvx", X(31, 231), X_MASK, [AltivecOperandID.VS, AltivecOperandID.RA, AltivecOperandID.RB], "Store Vector Indexed") ,
 altivec_opcode(altivec_insn_type_t.altivec_stvxl, "stvxl", X(31, 487), X_MASK, [AltivecOperandID.VS, AltivecOperandID.RA, AltivecOperandID.RB], "Store Vector Indexed LRU") ,
 altivec_opcode(altivec_insn_type_t.altivec_dst, "dst", XDSS(31, 342, 0), XDSS_MASK, [AltivecOperandID.RA, AltivecOperandID.RB, AltivecOperandID.STRM], "Data Stream Touch") ,
 altivec_opcode(altivec_insn_type_t.altivec_dstt, "dstt", XDSS(31, 342, 1), XDSS_MASK, [AltivecOperandID.RA, AltivecOperandID.RB, AltivecOperandID.STRM], "Data Stream Touch Transient") ,
 altivec_opcode(altivec_insn_type_t.altivec_dstst, "dstst", XDSS(31, 374, 0), XDSS_MASK, [AltivecOperandID.RA, AltivecOperandID.RB, AltivecOperandID.STRM], "Data Stream Touch for Store") ,
 altivec_opcode(altivec_insn_type_t.altivec_dststt, "dststt", XDSS(31, 374, 1), XDSS_MASK, [AltivecOperandID.RA, AltivecOperandID.RB, AltivecOperandID.STRM], "Data Stream Touch for Store Transient") ,
 altivec_opcode(altivec_insn_type_t.altivec_dss, "dss", XDSS(31, 822, 0), XDSS_MASK, [AltivecOperandID.STRM], "Data Stream Stop") ,
 altivec_opcode(altivec_insn_type_t.altivec_dssall, "dssall", XDSS(31, 822, 1), XDSS_MASK, [0], "Data Stream Stop All") ,
 altivec_opcode(altivec_insn_type_t.altivec_mfvscr, "mfvscr", VX(4, 1540), VX_MASK, [AltivecOperandID.VD], "Move from Vector Status and Control Register") ,
 altivec_opcode(altivec_insn_type_t.altivec_mtvscr, "mtvscr", VX(4, 1604), VX_MASK, [AltivecOperandID.VD], "Move to Vector Status and Control Register") ,
 altivec_opcode(altivec_insn_type_t.altivec_vaddcuw, "vaddcuw", VX(4, 384), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Add Carryout Unsigned Word") ,
 altivec_opcode(altivec_insn_type_t.altivec_vaddfp, "vaddfp", VX(4, 10), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Add Floating Point") ,
 altivec_opcode(altivec_insn_type_t.altivec_vaddsbs, "vaddsbs", VX(4, 768), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Add Signed Byte Saturate"),
 altivec_opcode(altivec_insn_type_t.altivec_vaddshs, "vaddshs", VX(4, 832), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Add Signed Half Word Saturate") ,
 altivec_opcode(altivec_insn_type_t.altivec_vaddsws, "vaddsws", VX(4, 896), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Add Signed Word Saturate") ,
 altivec_opcode(altivec_insn_type_t.altivec_vaddubm, "vaddubm", VX(4, 0), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Add Unsigned Byte Modulo") ,
 altivec_opcode(altivec_insn_type_t.altivec_vaddubs, "vaddubs", VX(4, 512), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Add Unsigned Byte Saturate") ,
 altivec_opcode(altivec_insn_type_t.altivec_vadduhm, "vadduhm", VX(4, 64), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Add Unsigned Half Word Modulo") ,
 altivec_opcode(altivec_insn_type_t.altivec_vadduhs, "vadduhs", VX(4, 576), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Add Unsigned Half Word Saturate") ,
 altivec_opcode(altivec_insn_type_t.altivec_vadduwm, "vadduwm", VX(4, 128), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Add Unsigned Word Modulo") ,
 altivec_opcode(altivec_insn_type_t.altivec_vadduws, "vadduws", VX(4, 640), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Add Unsigned Word Saturate") ,
 altivec_opcode(altivec_insn_type_t.altivec_vand, "vand", VX(4, 1028), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Logical AND") ,
 altivec_opcode(altivec_insn_type_t.altivec_vandc, "vandc", VX(4, 1092), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Logical AND with Complement") ,
 altivec_opcode(altivec_insn_type_t.altivec_vavgsb, "vavgsb", VX(4, 1282), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Average Signed Byte") ,
 altivec_opcode(altivec_insn_type_t.altivec_vavgsh, "vavgsh", VX(4, 1346), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Average Signed Half Word") ,
 altivec_opcode(altivec_insn_type_t.altivec_vavgsw, "vavgsw", VX(4, 1410), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Average Signed Word"),
 altivec_opcode(altivec_insn_type_t.altivec_vavgub, "vavgub", VX(4, 1026), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Average Unsigned Byte") ,
 altivec_opcode(altivec_insn_type_t.altivec_vavguh, "vavguh", VX(4, 1090), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Average Unsigned Half Word") ,
 altivec_opcode(altivec_insn_type_t.altivec_vavguw, "vavguw", VX(4, 1154), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Average Unsigned Word") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcfsx, "vcfsx", VX(4, 842), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB, AltivecOperandID.UIMM], "Vector Convert from Signed Fixed-Point Word") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcfux, "vcfux", VX(4, 778), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB, AltivecOperandID.UIMM], "Vector Convert from Unsigned Fixed-Point Word") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpbfp, "vcmpbfp", VXR(4, 966, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Bounds Floating Point") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpbfp_c, "vcmpbfp.", VXR(4, 966, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Bounds Floating Point (set CR6)") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpeqfp, "vcmpeqfp", VXR(4, 198, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Equal-to Floating Point") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpeqfp_c, "vcmpeqfp.", VXR(4, 198, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Equal-to Floating Point (set CR6)") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpequb, "vcmpequb", VXR(4, 6, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Equal-to Unsigned Byte") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpequb_c, "vcmpequb.", VXR(4, 6, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Equal-to Unsigned Byte (set CR6)") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpequh, "vcmpequh", VXR(4, 70, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Equal-to Unsigned Half Word") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpequh_c, "vcmpequh.", VXR(4, 70, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Equal-to Unsigned Half Word (set CR6)"),
 altivec_opcode(altivec_insn_type_t.altivec_vcmpequw, "vcmpequw", VXR(4, 134, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Equal-to Unsigned Word") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpequw_c, "vcmpequw.", VXR(4, 134, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Equal-to Unsigned Word (set CR6)") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgefp, "vcmpgefp", VXR(4, 454, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than-or-Equal-to Floating Point") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgefp_c, "vcmpgefp.", VXR(4, 454, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than-or-Equal-to Floating Point (set CR6)") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtfp, "vcmpgtfp", VXR(4, 710, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Floating Point") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtfp_c, "vcmpgtfp.", VXR(4, 710, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Floating Point (set CR6)") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtsb, "vcmpgtsb", VXR(4, 774, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Signed Byte") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtsb_c, "vcmpgtsb.", VXR(4, 774, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Signed Byte (set CR6)") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtsh, "vcmpgtsh", VXR(4, 838, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Signed Half Word") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtsh_c, "vcmpgtsh.", VXR(4, 838, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Signed Half Word (set CR6)") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtsw, "vcmpgtsw", VXR(4, 902, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Signed Word") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtsw_c, "vcmpgtsw.", VXR(4, 902, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Signed Word (set CR6)") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtub, "vcmpgtub", VXR(4, 518, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Unsigned Byte") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtub_c, "vcmpgtub.", VXR(4, 518, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Unsigned Byte (set CR6)") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtuh, "vcmpgtuh", VXR(4, 582, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Unsigned Half Word") ,
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtuh_c, "vcmpgtuh.", VXR(4, 582, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Unsigned Half Word (set CR6)" ),
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtuw, "vcmpgtuw", VXR(4, 646, 0), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Unsigned Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vcmpgtuw_c, "vcmpgtuw.", VXR(4, 646, 1), VXR_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Compare Greater-Than Unsigned Word (set CR6)" ),
 altivec_opcode(altivec_insn_type_t.altivec_vctsxs, "vctsxs", VX(4, 970), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB, AltivecOperandID.UIMM], "Vector Convert to Signed Fixed-Point Word Saturate" ),
 altivec_opcode(altivec_insn_type_t.altivec_vctuxs, "vctuxs", VX(4, 906), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB, AltivecOperandID.UIMM], "Vector Convert to Unsigned Fixed-Point Word Saturate" ),
 altivec_opcode(altivec_insn_type_t.altivec_vexptefp, "vexptefp", VX(4, 394), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector 2 Raised to the Exponent Estimate Floating Point" ),
 altivec_opcode(altivec_insn_type_t.altivec_vlogefp, "vlogefp", VX(4, 458), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Log2 Estimate Floating Point" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmaddfp, "vmaddfp", VXA(4, 46), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VC, AltivecOperandID.VB], "Vector Multiply-Add Floating Point" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmaxfp, "vmaxfp", VX(4, 1034), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Maximum Floating Point" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmaxsb, "vmaxsb", VX(4, 258), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Maximum Signed Byte" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmaxsh, "vmaxsh", VX(4, 322), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Maximum Signed Half Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmaxsw, "vmaxsw", VX(4, 386), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Maximum Signed Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmaxub, "vmaxub", VX(4, 2), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Maximum Unsigned Byte" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmaxuh, "vmaxuh", VX(4, 66), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Maximum Unsigned Half Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmaxuw, "vmaxuw", VX(4, 130), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Maximum Unsigned Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmhaddshs, "vmhaddshs", VXA(4, 32), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.VC], "Vector Multiply-High and Add Signed Signed Half Word Saturate" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmhraddshs, "vmhraddshs", VXA(4, 33), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.VC], "Vector Multiply-High Round and Add Signed Signed Half Word Saturate" ),
 altivec_opcode(altivec_insn_type_t.altivec_vminfp, "vminfp", VX(4, 1098), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Minimum Floating Point" ),
 altivec_opcode(altivec_insn_type_t.altivec_vminsb, "vminsb", VX(4, 770), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Minimum Signed Byte" ),
 altivec_opcode(altivec_insn_type_t.altivec_vminsh, "vminsh", VX(4, 834), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Minimum Signed Half Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vminsw, "vminsw", VX(4, 898), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Minimum Signed Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vminub, "vminub", VX(4, 514), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Minimum Unsigned Byte" ),
 altivec_opcode(altivec_insn_type_t.altivec_vminuh, "vminuh", VX(4, 578), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Minimum Unsigned Half Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vminuw, "vminuw", VX(4, 642), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Minimum Unsigned Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmladduhm, "vmladduhm", VXA(4, 34), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.VC], "Vector Multiply-Low and Add Unsigned Half Word Modulo" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmrghb, "vmrghb", VX(4, 12), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Merge High Byte" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmrghh, "vmrghh", VX(4, 76), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Merge High Half Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmrghw, "vmrghw", VX(4, 140), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Merge High Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmrglb, "vmrglb", VX(4, 268), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Merge Low Byte" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmrglh, "vmrglh", VX(4, 332), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Merge Low Half Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmrglw, "vmrglw", VX(4, 396), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Merge Low Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmsummbm, "vmsummbm", VXA(4, 37), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.VC], "Vector Multiply-Sum Mixed-Sign Byte Modulo" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmsumshm, "vmsumshm", VXA(4, 40), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.VC], "Vector Multiply-Sum Signed Half Word Modulo" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmsumshs, "vmsumshs", VXA(4, 41), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.VC], "Vector Multiply-Sum Signed Half Word Saturate" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmsumubm, "vmsumubm", VXA(4, 36), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.VC], "Vector Multiply-Sum Unsigned Byte Modulo" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmsumuhm, "vmsumuhm", VXA(4, 38), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.VC], "Vector Multiply-Sum Unsigned Half Word Modulo" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmsumuhs, "vmsumuhs", VXA(4, 39), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.VC], "Vector Multiply-Sum Unsigned Half Word Saturate" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmulesb, "vmulesb", VX(4, 776), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Multiply Even Signed Byte" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmulesh, "vmulesh", VX(4, 840), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Multiply Even Signed Half Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmuleub, "vmuleub", VX(4, 520), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Multiply Even Unsigned Byte" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmuleuh, "vmuleuh", VX(4, 584), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Multiply Even Unsigned Half Word" ),
 altivec_opcode(altivec_insn_type_t.altivec_vmulosb, "vmulosb", VX(4, 264), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Multiply Odd Signed Byte" ),
altivec_opcode(altivec_insn_type_t.altivec_vmulosh, "vmulosh", VX(4, 328), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Multiply Odd Signed Half Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vmuloub, "vmuloub", VX(4, 8), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Multiply Odd Unsigned Byte" ),
altivec_opcode(altivec_insn_type_t.altivec_vmulouh, "vmulouh", VX(4, 72), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Multiply Odd Unsigned Half Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vnmsubfp, "vnmsubfp", VXA(4, 47), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VC, AltivecOperandID.VB], "Vector Negative Multiply-Subtract Floating Point" ),
altivec_opcode(altivec_insn_type_t.altivec_vnor, "vnor", VX(4, 1284), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Logical NOR" ),
altivec_opcode(altivec_insn_type_t.altivec_vor, "vor", VX(4, 1156), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Logical OR" ),
altivec_opcode(altivec_insn_type_t.altivec_vperm, "vperm", VXA(4, 43), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.VC], "Vector Permute" ),
altivec_opcode(altivec_insn_type_t.altivec_vpkpx, "vpkpx", VX(4, 782), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Pack Pixel" ),
altivec_opcode(altivec_insn_type_t.altivec_vpkshss, "vpkshss", VX(4, 398), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Pack Signed Half Word Signed Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vpkshus, "vpkshus", VX(4, 270), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Pack Signed Half Word Unsigned Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vpkswss, "vpkswss", VX(4, 462), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Pack Signed Word Signed Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vpkswus, "vpkswus", VX(4, 334), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Pack Signed Word Unsigned Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vpkuhum, "vpkuhum", VX(4, 14), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Pack Unsigned Half Word Unsigned Modulo" ),
altivec_opcode(altivec_insn_type_t.altivec_vpkuhus, "vpkuhus", VX(4, 142), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Pack Unsigned Half Word Unsigned Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vpkuwum, "vpkuwum", VX(4, 78), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Pack Unsigned Word Unsigned Modulo" ),
altivec_opcode(altivec_insn_type_t.altivec_vpkuwus, "vpkuwus", VX(4, 206), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Pack Unsigned Word Unsigned Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vrefp, "vrefp", VX(4, 266), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Reciprocal Estimate Floating Point" ),
altivec_opcode(altivec_insn_type_t.altivec_vrfim, "vrfim", VX(4, 714), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Round to Floating-Point Integer toward Minus Infinity" ),
altivec_opcode(altivec_insn_type_t.altivec_vrfin, "vrfin", VX(4, 522), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Round to Floating-Point Integer Nearest" ),
altivec_opcode(altivec_insn_type_t.altivec_vrfip, "vrfip", VX(4, 650), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Round to Floating-Point Integer toward Plus Infinity" ),
altivec_opcode(altivec_insn_type_t.altivec_vrfiz, "vrfiz", VX(4, 586), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Round to Floating-Point Integer toward Zero" ),
altivec_opcode(altivec_insn_type_t.altivec_vrlb, "vrlb", VX(4, 4), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Rotate Left Integer Byte" ),
altivec_opcode(altivec_insn_type_t.altivec_vrlh, "vrlh", VX(4, 68), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Rotate Left Integer Half Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vrlw, "vrlw", VX(4, 132), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Rotate Left Integer Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vrsqrtefp, "vrsqrtefp", VX(4, 330), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Reciprocal Square Root Estimate Floating Point" ),
altivec_opcode(altivec_insn_type_t.altivec_vsel, "vsel", VXA(4, 42), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.VC], "Vector Conditional Select" ),
altivec_opcode(altivec_insn_type_t.altivec_vsl, "vsl", VX(4, 452), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Left" ),
altivec_opcode(altivec_insn_type_t.altivec_vslb, "vslb", VX(4, 260), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Left Integer Byte" ),
altivec_opcode(altivec_insn_type_t.altivec_vsldoi, "vsldoi", VXA(4, 44), VXA_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB, AltivecOperandID.SHB], "Vector Shift Left Double by Octet Immediate" ),
altivec_opcode(altivec_insn_type_t.altivec_vslh, "vslh", VX(4, 324), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Left Integer Half Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vslo, "vslo", VX(4, 1036), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Left by Octet" ),
altivec_opcode(altivec_insn_type_t.altivec_vslw, "vslw", VX(4, 388), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Left Integer Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vspltb, "vspltb", VX(4, 524), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB, AltivecOperandID.UIMM], "Vector Splat Byte" ),
altivec_opcode(altivec_insn_type_t.altivec_vsplth, "vsplth", VX(4, 588), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB, AltivecOperandID.UIMM], "Vector Splat Half Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vspltisb, "vspltisb", VX(4, 780), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.SIMM], "Vector Splat Immediate Signed Byte" ),
altivec_opcode(altivec_insn_type_t.altivec_vspltish, "vspltish", VX(4, 844), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.SIMM], "Vector Splat Immediate Signed Half Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vspltisw, "vspltisw", VX(4, 908), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.SIMM], "Vector Splat Immediate Signed Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vspltw, "vspltw", VX(4, 652), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB, AltivecOperandID.UIMM], "Vector Splat Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vsr, "vsr", VX(4, 708), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Right" ),
altivec_opcode(altivec_insn_type_t.altivec_vsrab, "vsrab", VX(4, 772), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Right Algebraic Byte" ),
altivec_opcode(altivec_insn_type_t.altivec_vsrah, "vsrah", VX(4, 836), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Right Algebraic Half Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vsraw, "vsraw", VX(4, 900), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Right Algebraic Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vsrb, "vsrb", VX(4, 516), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Right Byte" ),
altivec_opcode(altivec_insn_type_t.altivec_vsrh, "vsrh", VX(4, 580), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Right Half Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vsro, "vsro", VX(4, 1100), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Right Octet" ),
altivec_opcode(altivec_insn_type_t.altivec_vsrw, "vsrw", VX(4, 644), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Shift Right Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vsubcuw, "vsubcuw", VX(4, 1408), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Subtract Carryout Unsigned Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vsubfp, "vsubfp", VX(4, 74), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Subtract Floating Point" ),
altivec_opcode(altivec_insn_type_t.altivec_vsubsbs, "vsubsbs", VX(4, 1792), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Subtract Signed Byte Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vsubshs, "vsubshs", VX(4, 1856), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Subtract Signed Half Word Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vsubsws, "vsubsws", VX(4, 1920), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Subtract Signed Word Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vsububm, "vsububm", VX(4, 1024), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Subtract Unsigned Byte Modulo" ),
altivec_opcode(altivec_insn_type_t.altivec_vsububs, "vsububs", VX(4, 1536), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Subtract Unsigned Byte Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vsubuhm, "vsubuhm", VX(4, 1088), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Subtract Unsigned Half Word Modulo" ),
altivec_opcode(altivec_insn_type_t.altivec_vsubuhs, "vsubuhs", VX(4, 1600), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Subtract Unsigned Half Word Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vsubuwm, "vsubuwm", VX(4, 1152), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Subtract Unsigned Word Modulo" ),
altivec_opcode(altivec_insn_type_t.altivec_vsubuws, "vsubuws", VX(4, 1664), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Subtract Unsigned Word Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vsumsws, "vsumsws", VX(4, 1928), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Sum Across Signed Word Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vsum2sws, "vsum2sws", VX(4, 1672), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Sum Across Partial (1/2) Signed Word Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vsum4sbs, "vsum4sbs", VX(4, 1800), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Sum Across Partial (1/4) Signed Byte Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vsum4shs, "vsum4shs", VX(4, 1608), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Sum Across Partial (1/4) Signed Half Word Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vsum4ubs, "vsum4ubs", VX(4, 1544), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Sum Across Partial (1/4) Unsigned Byte Saturate" ),
altivec_opcode(altivec_insn_type_t.altivec_vupkhpx, "vupkhpx", VX(4, 846), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Unpack High Pixel" ),
altivec_opcode(altivec_insn_type_t.altivec_vupkhsb, "vupkhsb", VX(4, 526), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Unpack High Signed Byte" ),
altivec_opcode(altivec_insn_type_t.altivec_vupkhsh, "vupkhsh", VX(4, 590), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Unpack High Signed Half Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vupklpx, "vupklpx", VX(4, 974), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Unpack Low Pixel" ),
altivec_opcode(altivec_insn_type_t.altivec_vupklsb, "vupklsb", VX(4, 654), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Unpack Low Signed Byte" ),
altivec_opcode(altivec_insn_type_t.altivec_vupklsh, "vupklsh", VX(4, 718), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VB], "Vector Unpack Low Signed Half Word" ),
altivec_opcode(altivec_insn_type_t.altivec_vxor, "vxor", VX(4, 1220), VX_MASK, [AltivecOperandID.VD, AltivecOperandID.VA, AltivecOperandID.VB], "Vector Logical XOR" ),

# Takires: Added opcodes
altivec_opcode(altivec_insn_type_t.vmx128_vsldoi128, "vsldoi128", VX128_5(4, 16), VX128_5_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128, AltivecOperandID.SHB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvsl128, "lvsl128", VX128_1(4, 3), VX128_1_MASK, [AltivecOperandID.VD128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvsr128, "lvsr128", VX128_1(4, 67), VX128_1_MASK, [AltivecOperandID.VD128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvewx128, "lvewx128", VX128_1(4, 131), VX128_1_MASK, [AltivecOperandID.VD128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvx128, "lvx128", VX128_1(4, 195), VX128_1_MASK, [AltivecOperandID.VD128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_stvewx128, "stvewx128", VX128_1(4, 387), VX128_1_MASK, [AltivecOperandID.VS128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_stvx128, "stvx128", VX128_1(4, 451), VX128_1_MASK, [AltivecOperandID.VS128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvxl128, "lvxl128", VX128_1(4, 707), VX128_1_MASK, [AltivecOperandID.VD128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_stvxl128, "stvxl128", VX128_1(4, 963), VX128_1_MASK, [AltivecOperandID.VS128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvlx128, "lvlx128", VX128_1(4, 1027), VX128_1_MASK, [AltivecOperandID.VD128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvrx128, "lvrx128", VX128_1(4, 1091), VX128_1_MASK, [AltivecOperandID.VD128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_stvlx128, "stvlx128", VX128_1(4, 1283), VX128_1_MASK, [AltivecOperandID.VS128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_stvrx128, "stvrx128", VX128_1(4, 1347), VX128_1_MASK, [AltivecOperandID.VS128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvlxl128, "lvlxl128", VX128_1(4, 1539), VX128_1_MASK, [AltivecOperandID.VD128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvrxl128, "lvrxl128", VX128_1(4, 1603), VX128_1_MASK, [AltivecOperandID.VD128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_stvlxl128, "stvlxl128", VX128_1(4, 1795), VX128_1_MASK, [AltivecOperandID.VS128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_stvrxl128, "stvrxl128", VX128_1(4, 1859), VX128_1_MASK, [AltivecOperandID.VS128, AltivecOperandID.RA, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vperm128, "vperm128", VX128_2(5, 0), VX128_2_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128, AltivecOperandID.VC128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vaddfp128, "vaddfp128", VX128(5, 16), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vsubfp128, "vsubfp128", VX128(5, 80), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vmulfp128, "vmulfp128", VX128(5, 144), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vmaddfp128, "vmaddfp128", VX128(5, 208), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128, AltivecOperandID.VS128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vmaddcfp128, "vmaddcfp128", VX128(5, 272), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VS128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vnmsubfp128, "vnmsubfp128", VX128(5, 336), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128, AltivecOperandID.VS128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vmsum3fp128, "vmsum3fp128", VX128(5, 400), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vmsum4fp128, "vmsum4fp128", VX128(5, 464), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vpkshss128, "vpkshss128", VX128(5, 512), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vand128, "vand128", VX128(5, 528), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vpkshus128, "vpkshus128", VX128(5, 576), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vandc128, "vandc128", VX128(5, 592), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vpkswss128, "vpkswss128", VX128(5, 640), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vnor128, "vnor128", VX128(5, 656), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vpkswus128, "vpkswus128", VX128(5, 704), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vor128, "vor128", VX128(5, 720), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vpkuhum128, "vpkuhum128", VX128(5, 768), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vxor128, "vxor128", VX128(5, 784), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vpkuhus128, "vpkuhus128", VX128(5, 832), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vsel128, "vsel128", VX128(5, 848), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128, AltivecOperandID.VS128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vpkuwum128, "vpkuwum128", VX128(5, 896), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vslo128, "vslo128", VX128(5, 912), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vpkuwus128, "vpkuwus128", VX128(5, 960), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vsro128, "vsro128", VX128(5, 976), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),

altivec_opcode(altivec_insn_type_t.vmx128_vpermwi128, "vpermwi128", VX128_P(6, 528), VX128_P_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128, AltivecOperandID.VPERM128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcfpsxws128, "vcfpsxws128", VX128_3(6, 560), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128, AltivecOperandID.SIMM], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcfpuxws128, "vcfpuxws128", VX128_3(6, 624), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128, AltivecOperandID.UIMM], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcsxwfp128, "vcsxwfp128", VX128_3(6, 688), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128, AltivecOperandID.SIMM], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcuxwfp128, "vcuxwfp128", VX128_3(6, 752), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128, AltivecOperandID.UIMM], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vrfim128, "vrfim128", VX128_3(6, 816), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vrfin128, "vrfin128", VX128_3(6, 880), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vrfip128, "vrfip128", VX128_3(6, 944), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vrfiz128, "vrfiz128", VX128_3(6, 1008), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vpkd3d128, "vpkd3d128", VX128_4(6, 1552), VX128_4_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128, AltivecOperandID.VD3D0, AltivecOperandID.VD3D1, AltivecOperandID.VD3D2], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vrefp128, "vrefp128", VX128_3(6, 1584), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vrsqrtefp128, "vrsqrtefp128", VX128_3(6, 1648), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vexptefp128, "vexptefp128", VX128_3(6, 1712), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vlogefp128, "vlogefp128", VX128_3(6, 1776), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vrlimi128, "vrlimi128", VX128_4(6, 1808), VX128_4_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128, AltivecOperandID.UIMM, AltivecOperandID.VD3D2], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vspltw128, "vspltw128", VX128_3(6, 1840), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128, AltivecOperandID.UIMM], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vspltisw128, "vspltisw128", VX128_3(6, 1904), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128, AltivecOperandID.SIMM], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vupkd3d128, "vupkd3d128", VX128_3(6, 2032), VX128_3_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128, AltivecOperandID.UIMM], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcmpeqfp128, "vcmpeqfp128", VX128(6, 0), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcmpeqfp128c, "vcmpeqfp128.", VX128(6, 64), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vrlw128, "vrlw128", VX128(6, 80), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcmpgefp128, "vcmpgefp128", VX128(6, 128), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcmpgefp128c, "vcmpgefp128.", VX128(6, 192), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vslw128, "vslw128", VX128(6, 208), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcmpgtfp128, "vcmpgtfp128", VX128(6, 256), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcmpgtfp128c, "vcmpgtfp128.", VX128(6, 320), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vsraw128, "vsraw128", VX128(6, 336), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcmpbfp128, "vcmpbfp128", VX128(6, 384), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcmpbfp128c, "vcmpbfp128.", VX128(6, 448), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vsrw128, "vsrw128", VX128(6, 464), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcmpequw128, "vcmpequw128", VX128(6, 512), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vcmpequw128c, "vcmpequw128.", VX128(6, 576), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vmaxfp128, "vmaxfp128", VX128(6, 640), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vminfp128, "vminfp128", VX128(6, 704), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vmrghw128, "vmrghw128", VX128(6, 768), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vmrglw128, "vmrglw128", VX128(6, 832), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VA128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vupkhsb128, "vupkhsb128", VX128(6, 896), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_vupklsb128, "vupklsb128", VX128(6, 960), VX128_MASK, [AltivecOperandID.VD128, AltivecOperandID.VB128], "" ),

altivec_opcode(altivec_insn_type_t.vmx128_lvlx, "lvlx", X(31, 519), X_MASK, [AltivecOperandID.VD, AltivecOperandID.RA0, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvlxl, "lvlxl", X(31, 775), X_MASK, [AltivecOperandID.VD, AltivecOperandID.RA0, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvrx, "lvrx", X(31, 551), X_MASK, [AltivecOperandID.VD, AltivecOperandID.RA0, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_lvrxl, "lvrxl", X(31, 807), X_MASK, [AltivecOperandID.VD, AltivecOperandID.RA0, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_stvlx, "stvlx", X(31, 647), X_MASK, [AltivecOperandID.VS, AltivecOperandID.RA0, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_stvlxl, "stvlxl", X(31, 903), X_MASK, [AltivecOperandID.VS, AltivecOperandID.RA0, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_stvrx, "stvrx", X(31, 679), X_MASK, [AltivecOperandID.VS, AltivecOperandID.RA0, AltivecOperandID.RB], "" ),
altivec_opcode(altivec_insn_type_t.vmx128_stvrxl, "stvrxl", X(31, 935), X_MASK, [AltivecOperandID.VS, AltivecOperandID.RA0, AltivecOperandID.RB], "" ),

altivec_opcode(altivec_insn_type_t.std_attn, "attn", X(0, 256), X_MASK, [0], "" ),
altivec_opcode(altivec_insn_type_t.std_dbcz128, "dbcz128", XRT(31, 1014, 1), XRT_MASK, [AltivecOperandID.RA, AltivecOperandID.RB], "Data Cache Block set to Zero (1)" ),

# the normal PPC processor module handles normal syscalls,
# so this just need to handle level 1 syscalls (hypercalls)
altivec_opcode(altivec_insn_type_t.std_hvsc, "hvsc", 0x44000022, 0xFFFFFFFF, [0], "Level1 Syscall (Hypercall)" ),

# added entries for mfspr and mtspr to cover all spr's described in CEBA documentation
altivec_opcode(altivec_insn_type_t.std_mtspr, "mtspr", 0x7C0003A6, 0xFC0007FE, [AltivecOperandID.SPR, AltivecOperandID.RS], "Move to sprg, " ), # XFX macro didnt work just put opcode + mask manually
altivec_opcode(altivec_insn_type_t.std_mfspr, "mfspr", 0x7C0002A6, 0xFC0007FE, [AltivecOperandID.RS, AltivecOperandID.SPR], "Move from sprg, " ),

altivec_opcode(altivec_insn_type_t.std_ldbrx, "ldbrx", X(31, 532), X_MASK, [AltivecOperandID.RT, AltivecOperandID.RA0, AltivecOperandID.RB], "Load Doubleword Byte Reverse Indexed" ),
altivec_opcode(altivec_insn_type_t.std_mfocrf, "mfocrf", XFX(31, 19, 1), XFX_MASK, [AltivecOperandID.RT, AltivecOperandID.CRM], "Move from One Condition Register Field" ),
altivec_opcode(altivec_insn_type_t.std_mtmsr, "mtmsr", X(31, 146), XRLARB_MASK, [AltivecOperandID.RS], "Move to Machine State Register" ),
altivec_opcode(altivec_insn_type_t.std_mtmsrd, "mtmsrd", X(31, 178), XRLARB_MASK, [AltivecOperandID.RS, AltivecOperandID.L15], "Move to Machine State Register Doubleword" ),
altivec_opcode(altivec_insn_type_t.std_mtocrf, "mtocrf", XFX(31, 144, 1), XFX_MASK, [AltivecOperandID.CRM, AltivecOperandID.RS], "Move to One Condition Register Field" ),
altivec_opcode(altivec_insn_type_t.std_slbmte, "slbmte", X(31, 402), XRA_MASK, [AltivecOperandID.RS, AltivecOperandID.RB, 0], "SLB Move to Entry" ),
altivec_opcode(altivec_insn_type_t.std_stdbrx, "stdbrx", X(31, 660), X_MASK, [AltivecOperandID.RS, AltivecOperandID.RA0, AltivecOperandID.RB], "Store Doubleword Byte Reverse Indexed" ),
#altivec_opcode(altivec_insn_type_t.std_svc, "svc", SC(17, 0, 0), SC_MASK, [AltivecOperandID.SVC_LEV, AltivecOperandID.FL1, AltivecOperandID.FL2], "Synchronize"	),
#altivec_opcode(altivec_insn_type_t.std_svcl, "svcl", SC(17, 0, 1), SC_MASK, [AltivecOperandID.SVC_LEV, AltivecOperandID.FL1, AltivecOperandID.FL2], "Synchronize"	),
#altivec_opcode(altivec_insn_type_t.std_svca, "svca", SC(17, 1, 0), SC_MASK, [AltivecOperandID.SV], "Synchronize"	),
#altivec_opcode(altivec_insn_type_t.std_svcla, "svcla", SC(17, 1, 1), SC_MASK, [AltivecOperandID.SV], "Synchronize"	),
altivec_opcode(altivec_insn_type_t.std_lwsync, "lwsync", XSYNC(31, 598, 1), 0xffffffff, [0], "Lightweight Synchronize" ),
altivec_opcode(altivec_insn_type_t.std_ptesync, "ptesync", XSYNC(31, 598, 2), 0xffffffff, [0], "Synchronize" ),
altivec_opcode(altivec_insn_type_t.std_sync, "sync", X(31, 598), X_MASK, [0], "Synchronize" ),
altivec_opcode(altivec_insn_type_t.std_tlbiel, "tlbiel", X(31, 274), X_MASK, [AltivecOperandID.RB, AltivecOperandID.L10], "TLB Invalidate Entry Local" ),
altivec_opcode(altivec_insn_type_t.std_tlbie, "tlbie", X(31, 306), XRTLRA_MASK, [AltivecOperandID.RB, AltivecOperandID.L], "TLB Invalidate Entry" ),
altivec_opcode(altivec_insn_type_t.std_tlbi, "tlbi", X(31, 306), XRT_MASK, [AltivecOperandID.RA, AltivecOperandID.RB], "TLB Invalidate" ),
altivec_opcode(altivec_insn_type_t.std_slbie, "slbie", X(31, 434), XRTRA_MASK, [AltivecOperandID.RB], "SLB Invalidate Entry" ),

# special instructions that don't seem to have full setup info
altivec_opcode(altivec_insn_type_t.spec_callthru, "callthru", 0x000eaeb0, 0xffffffff, [0], "SystemSim Callthru" ),
altivec_opcode(altivec_insn_type_t.spec_cctpl, "cctpl", 0x7c210b78, 0xffffffff, [0], "" ),
altivec_opcode(altivec_insn_type_t.spec_cctpm, "cctpm", 0x7c421378, 0xffffffff, [0], "" ),
altivec_opcode(altivec_insn_type_t.spec_cctph, "cctph", 0x7c631b78, 0xffffffff, [0], "" ),
altivec_opcode(altivec_insn_type_t.spec_db8cyc, "db8cyc", 0x7f9ce378, 0xffffffff, [0], "" ),
altivec_opcode(altivec_insn_type_t.spec_db10cyc, "db10cyc", 0x7fbdeb78, 0xffffffff, [0], "" ),
altivec_opcode(altivec_insn_type_t.spec_db12cyc, "db12cyc", 0x7fdef378, 0xffffffff, [0], "" ),
altivec_opcode(altivec_insn_type_t.spec_db16cyc, "db16cyc", 0x7ffffb78, 0xffffffff, [0], "" ),
altivec_opcode(altivec_insn_type_t.spec_02002000, "opcode_02002000", 0x02002000, 0xffffffff, [0], "Unknown instruction - included to allow conversion to code" ),

# gekko specific
altivec_opcode(altivec_insn_type_t.gekko_psq_lx, "psq_lx", OPM(4, 6), OPM_MASK, [AltivecOperandID.FD, AltivecOperandID.RA, AltivecOperandID.RB, AltivecOperandID.WC, AltivecOperandID.IC], "Paired Single Quantized Load Indexed" ),
altivec_opcode(altivec_insn_type_t.gekko_psq_stx, "psq_stx", OPM(4, 7), OPM_MASK, [AltivecOperandID.FS, AltivecOperandID.RA, AltivecOperandID.RB, AltivecOperandID.WC, AltivecOperandID.IC], "Paired Single Quantized Store Indexed" ),
altivec_opcode(altivec_insn_type_t.gekko_psq_lux, "psq_lux", OPM(4, 38), OPM_MASK, [AltivecOperandID.FD, AltivecOperandID.RA, AltivecOperandID.RB, AltivecOperandID.WC, AltivecOperandID.IC], "Paired Single Quantized Load with update Indexed" ),
altivec_opcode(altivec_insn_type_t.gekko_psq_stux, "psq_stux", OPM(4, 39), OPM_MASK, [AltivecOperandID.FS, AltivecOperandID.RA, AltivecOperandID.RB, AltivecOperandID.WC, AltivecOperandID.IC], "Paired Single Quantized Store with update Indexed" ),

altivec_opcode(altivec_insn_type_t.gekko_psq_l, "psq_l", OP(56), OP_MASK, [AltivecOperandID.FD, AltivecOperandID.DRA, AltivecOperandID.WB, AltivecOperandID.IB], "Paired Single Quantized Load" ),
altivec_opcode(altivec_insn_type_t.gekko_psq_lu, "psq_lu", OP(57), OP_MASK, [AltivecOperandID.FD, AltivecOperandID.DRA, AltivecOperandID.WB, AltivecOperandID.IB], "Paired Single Quantized Load with Update" ),
altivec_opcode(altivec_insn_type_t.gekko_psq_st, "psq_st", OP(60), OP_MASK, [AltivecOperandID.FS, AltivecOperandID.DRA, AltivecOperandID.WB, AltivecOperandID.IB], "Paired Single Quantized Store" ),
altivec_opcode(altivec_insn_type_t.gekko_psq_stu, "psq_stu", OP(61), OP_MASK, [AltivecOperandID.FS, AltivecOperandID.DRA, AltivecOperandID.WB, AltivecOperandID.IB], "Paired Single Quantized Store with update" ),

altivec_opcode(altivec_insn_type_t.gekko_ps_div, "ps_div", OPSC(4, 18, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single Divide" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_div_dot, "ps_div.", OPSC(4, 18, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single Divide" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_sub, "ps_sub", OPSC(4, 20, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single Subtract" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_sub_dot, "ps_sub.", OPSC(4, 20, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single Subtract" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_add, "ps_add", OPSC(4, 21, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single Add" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_add_dot, "ps_add.", OPSC(4, 21, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single Add" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_sel, "ps_sel", OPSC(4, 23, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Select" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_sel_dot, "ps_sel.", OPSC(4, 23, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Select" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_res, "ps_res", OPSC(4, 24, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Reciprocal Estimate" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_res_dot, "ps_res.", OPSC(4, 24, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Reciprocal Estimate" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_mul, "ps_mul", OPSC(4, 25, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC], "Paired Single Multiply" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_mul_dot, "ps_mul.", OPSC(4, 25, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC], "Paired Single Multiply" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_rsqrte, "ps_rsqrte", OPSC(4, 26, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Reciprocal Square Root Estimate" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_rsqrte_dot, "ps_rsqrte.", OPSC(4, 26, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Reciprocal Square Root Estimate" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_msub, "ps_msub", OPSC(4, 28, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Multiply-Subtract" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_msub_dot, "ps_msub.", OPSC(4, 28, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Multiply-Subtract" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_madd, "ps_madd", OPSC(4, 29, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Multiply-Add" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_madd_dot, "ps_madd.", OPSC(4, 29, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Multiply-Add" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_nmsub, "ps_nmsub", OPSC(4, 30, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Negative Multiply-Subtract" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_nmsub_dot, "ps_nmsub.", OPSC(4, 30, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Negative Multiply-Subtract" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_nmadd, "ps_nmadd", OPSC(4, 31, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Negative Multiply-Add" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_nmadd_dot, "ps_nmadd.", OPSC(4, 31, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Negative Multiply-Add" ),

altivec_opcode(altivec_insn_type_t.gekko_ps_neg, "ps_neg", OPLC(4, 40, 0), OPL_MASK, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Negate" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_neg_dot, "ps_neg.", OPLC(4, 40, 1), OPL_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Negate" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_mr, "ps_mr", OPLC(4, 72, 0), OPL_MASK, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Move Register" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_mr_dot, "ps_mr.", OPLC(4, 72, 1), OPL_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Move Register" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_nabs, "ps_nabs", OPLC(4, 136, 0), OPL_MASK, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Negative Absolute Value" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_nabs_dot, "ps_nabs.", OPLC(4, 136, 1), OPL_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Negative Absolute Value" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_abs, "ps_abs", OPLC(4, 264, 0), OPL_MASK, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Absolute Value" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_abs_dot, "ps_abs.", OPLC(4, 264, 1), OPL_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FB], "Paired Single Absolute Value" ),

altivec_opcode(altivec_insn_type_t.gekko_ps_sum0, "ps_sum0", OPSC(4, 10, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single vector SUM high" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_sum0_dot, "ps_sum0.", OPSC(4, 10, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single vector SUM high" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_sum1, "ps_sum1", OPSC(4, 11, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single vector SUM low" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_sum1_dot, "ps_sum1.", OPSC(4, 11, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single vector SUM low" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_muls0, "ps_muls0", OPSC(4, 12, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC], "Paired Single Multiply Scalar high" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_muls0_dot, "ps_muls0.", OPSC(4, 12, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC], "Paired Single Multiply Scalar high" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_muls1, "ps_muls1", OPSC(4, 13, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC], "Paired Single Multiply Scalar low" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_muls1_dot, "ps_muls1.", OPSC(4, 13, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC], "Paired Single Multiply Scalar low" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_madds0, "ps_madds0", OPSC(4, 14, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Multiply-Add Scalar high" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_madds0_dot, "ps_madds0.", OPSC(4, 14, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Multiply-Add Scalar high" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_madds1, "ps_madds1", OPSC(4, 15, 0), OPS_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Multiply-Add Scalar low" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_madds1_dot, "ps_madds1.", OPSC(4, 15, 1), OPS_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FC, AltivecOperandID.FB], "Paired Single Multiply-Add Scalar low" ),

altivec_opcode(altivec_insn_type_t.gekko_ps_cmpu0, "ps_cmpu0", OPL(4, 0), OPL_MASK, [AltivecOperandID.crfD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Singles Compare Unordered High" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_cmpo0, "ps_cmpo0", OPL(4, 32), OPL_MASK, [AltivecOperandID.crfD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Singles Compare Ordered High" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_cmpu1, "ps_cmpu1", OPL(4, 64), OPL_MASK, [AltivecOperandID.crfD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Singles Compare Unordered Low" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_cmpo1, "ps_cmpo1", OPL(4, 96), OPL_MASK, [AltivecOperandID.crfD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Singles Compare Ordered Low" ),

altivec_opcode(altivec_insn_type_t.gekko_ps_merge00, "ps_merge00", OPLC(4, 528, 0), OPL_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single MERGE high" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_merge00_dot, "ps_merge00.", OPLC(4, 528, 1), OPL_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single MERGE high" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_merge01, "ps_merge01", OPLC(4, 560, 0), OPL_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single MERGE direct" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_merge01_dot, "ps_merge01.", OPLC(4, 560, 1), OPL_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single MERGE direct" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_merge10, "ps_merge10", OPLC(4, 592, 0), OPL_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single MERGE swapped" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_merge10_dot, "ps_merge10.", OPLC(4, 592, 1), OPL_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single MERGE swapped" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_merge11, "ps_merge11", OPLC(4, 624, 0), OPL_MASK, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single MERGE low" ),
altivec_opcode(altivec_insn_type_t.gekko_ps_merge11_dot, "ps_merge11.", OPLC(4, 624, 1), OPL_MASK_DOT, [AltivecOperandID.FD, AltivecOperandID.FA, AltivecOperandID.FB], "Paired Single MERGE low" ),

altivec_opcode(altivec_insn_type_t.gekko_ps_dcbz_l, "dcbz_l", OPL(4, 1014), OPL_MASK, [AltivecOperandID.RA, AltivecOperandID.RB], "Data Cache Block Set to Zero Locked" ),


]

#	FUNCTION		PluginAnalyse

#	DESCRIPTION		This is the main analysis function..

def plugin_analyse(insn: ida_ua.insn_t):

    code_bytes = get_dword(insn.ea)

    # Estrai i byte di operazione con la maschera OP_MASK
    op_bytes = code_bytes & OP_MASK

    # Opcode supportati
    supported_opcodes = {0, 4, 5, 6, 17, 31, 56, 57, 60, 61}

    # Controlla se l'opcode è supportato
    if op_bytes in supported_opcodes:
        opcode_array_size = len(g_altivec_opcodes)
        p_current_opcode : altivec_opcode = g_altivec_opcodes
        
        for opcodeLoop in range(opcode_array_size):
            operandLoop = 0;
            while pCurrentOpcode.operands[operandLoop] != 0 and operandLoop < MAX_OPERANDS:
            
                pOperandData : op_t = insn.ops[operandLoop] # cmd.Operands[operandLoop];
                pCurrentOperand : altivec_operand = g_altivecOperands[pCurrentOpcode.operands[operandLoop]]

                raw_bits = (code_bytes >> pCurrent_operand.shift) & ((1 << pCurrent_operand.bits) - 1)
                extended_bits = (raw_bits << (32 - pCurrent_operand.bits)) >> (32 - pCurrent_operand.bits)

                match pCurrentOpcode.operands[operandLoop]:

                    # Main Altivec Registers
                    case AltivecOperandID.VA | AltivecOperandID.VB | AltivecOperandID.VC | AltivecOperandID.VD:  # VS
                        pOperandData.type = o_reg
                        pOperandData.reg = raw_bits
                        pOperandData.specflag1 = 0x01  # marks the register as Altivec
                        break

                    # Signed immediate (extended_bits is sign extended into 32 bits)
                    case AltivecOperandID.SIMM:
                        pOperandData.type = o_imm
                        pOperandData.dtype = dt_byte
                        pOperandData.value = extended_bits
                        break

                    # Unsigned immediate
                    case AltivecOperandID.UIMM:
                        pOperandData.type = o_imm
                        pOperandData.dtype = dt_byte
                        pOperandData.value = raw_bits
                        break

                    # Shift values are the same as unsigned immediates, but we separate for clarity
                    case AltivecOperandID.SHB:
                        pOperandData.type = o_imm
                        pOperandData.dtype = dt_byte
                        pOperandData.value = raw_bits
                        break

                    # Altivec memory loads are always via a CPU register
                    case AltivecOperandID.RA | AltivecOperandID.RB:
                        pOperandData.type = o_reg
                        pOperandData.reg = raw_bits
                        pOperandData.specflag1 = 0x00
                        break
                    
                    # Altivec data stream ID
                    case AltivecOperandID.STRM:
                        pOperandData.type = o_imm
                        pOperandData.dtype = dt_byte
                        pOperandData.value = raw_bits
                        break
                    
                    # Takires: Added operands
                    case AltivecOperandID.L9_10 | AltivecOperandID.L10 | AltivecOperandID.L15:
                        pOperandData.type = o_imm
                        pOperandData.dtype = dt_byte
                        pOperandData.value = raw_bits
                        break

                    case AltivecOperandID.RS: # Also RT

                        pOperandData.type = o_reg
                        pOperandData.reg = raw_bits
                        pOperandData.specflag1 = 0x00
                        break

                    case AltivecOperandID.VD128: # Also VS128

                        pOperandData.type = o_reg
                        pOperandData.reg = ((code_bytes >> 21) & 0x1F | ((code_bytes & 0x0C) << 3))
                        pOperandData.specflag1 = 0x01
                        break

                    case AltivecOperandID.VA128:

                        pOperandData.type = o_reg
                        pOperandData.reg = ((code_bytes >> 16) & 0x1F) | (code_bytes & 0x20) | ((code_bytes >> 4) & 0x40)
                        pOperandData.specflag1 = 0x01
                        break

                    case AltivecOperandID.VB128:
                        pOperandData.type = o_reg
                        pOperandData.reg = ((code_bytes << 5) & 0x60 | ((code_bytes >> 11) & 0x1F))
                        pOperandData.specflag1 = 0x01
                        break

                    case AltivecOperandID.VC128:
                        pOperandData.type = o_reg
                        pOperandData.reg = raw_bits
                        pOperandData.specflag1 = 0x01
                        break

                    case AltivecOperandID.CRM:
                        pOperandData.type = o_reg
                        pOperandData.reg = raw_bits
                        pOperandData.specflag1 = 0x02 # Mark the register as being a CRF.
                        break

                    case AltivecOperandID.VPERM128:
                        pOperandData.type = o_imm
                        pOperandData.dtype = dt_byte
                        pOperandData.value = ((code_bytes >> 1) & 0xE0) | ((code_bytes >> 16) & 0x1F)
                        break
                    
                    case AltivecOperandID.VD3D0 | AltivecOperandID.VD3D1 | AltivecOperandID.VD3D2:
                        pOperandData.type = o_imm
                        pOperandData.dtype = dt_byte
                        pOperandData.value = raw_bits
                        break

                    case AltivecOperandID.RA0:
                        if raw_bits == 0:
                            pOperandData.type = o_imm
                            pOperandData.dtype = dt_byte
                            pOperandData.value = raw_bits
                        else:
                            pOperandData.type = o_reg
                            pOperandData.reg = raw_bits
                            pOperandData.specflag1 = 0
                        break

                    case AltivecOperandID.SPR:
                        pOperandData.type = o_reg
                        pOperandData.dtype = (((raw_bits & 0x3E0) >> 5) + ((raw_bits & 0x1F) << 5));
                        pOperandData.value = 0x04 # Mark the register as being a SPR.
                        break
                    
                    # gekko specific

                    # These are main Gekko registers

                    case AltivecOperandID.FA | AltivecOperandID.FB | AltivecOperandID.FC | AltivecOperandID.FD:
                        pOperandData.type = o_reg
                        pOperandData.reg = raw_bits
                        pOperandData.specflag1 = 0x08 # Mark the register as being a Gekko one
                        break
                    
                    case AltivecOperandID.crfD | AltivecOperandID.WB | AltivecOperandID.IB | AltivecOperandID.WC | AltivecOperandID.IC:
                        pOperandData.type = o_imm
                        pOperandData.dtype = dt_byte
                        pOperandData.value = raw_bits
                        break

                    case AltivecOperandID.DRA:
                        imm = code_bytes & 0x7FF
                        sign = code_bytes & 0x800
                        displacement = 0

                        if sign == 0:
                            displacement = imm
                        else:
                            displacement = -1 * imm

                        pOperandData.type = o_displ
                        pOperandData.phrase = raw_bits
                        pOperandData.addr = displacement
                        break

                    case _:
                        pass
                    
                    # Next operand please..
                operandLoop+=1
            
            # Make a not of which opcode we are, we need it to print our stuff out.
            insn.itype = pCurrentOpcode.insn

            # The command is 4 bytes long..
            return 4

    # We obviously didn't find our opcode this time round.. go test the next one.
    pCurrentOpcode+=1;


# FUNCTION 		PluginExtentionCallback

# DESCRIPTION	This callback is responsible for distributing work associated with each
#					intercepted event that we deal with. In our case we deal with the following
#					event identifiers.
#
#					custom_ana		:	Analyses a command (in 'cmd') to see if it is an Altivec
#										instruction. If so, then it extracts information from the
#										opcode in order to determine which opcode it is, along with
#										data relating to any used operands.
#
#					custom_mnem		:	Generates the mnemonic for our Altivec instructions, by looking
#										into our array of opcode information structures.
#
#					custom_outop	:	Outputs operands for Altivec instructions. In our case, we
#										have an alternate register set (vr0 to vr31), so our operands
#										may be marked as being Altivec registers.
#
#					may_be_func		:	It's perfectly OK for an Altivec instruction to be the start
#										of a function, so I figured I should return 100 here. The
#										return value is a percentage probability..
#
#					is_sane_insn	:	All our Altivec instructions (well, the ones we've identified
#										inside custom_ana processing), are ok.


def PluginExtensionCallback(user_data, event_id, *args):
    match event_id:

        # Analyze a command to see if it's an Altivec instruction
        case ida_idp.processor_t.ev_ana_insn:
            inst : insn_t = args[0]

            if lenght:
                inst.size = lenght
                return lenght # event processed

        # Display operands that differ from PPC ones.. like our altivec registers
        case ida_idp.processor_t.ev_out_operand:
            ctx : outctx_t = args[0]

            if ctx.insn.itype > altivec_insn_start:
                operand : op_t = args[0]
                if operand.type == o_reg and operand.specflag1 & 0x01:
                    buf = f"%vr{operand.reg}"
                    ctx.out_register(buf)
                    return 1
                elif operand.type == o_reg and operand.specflag1 & 0x02:
                    for i in range(8):
                        if operand.reg & (1 << i):
                            buf = f"cr{7 - i}"
                            ctx.out_register(buf)
                            break
                    
                    return 1
                elif operand.type == o_reg and operand-specflag1 & 0x04:
                    sprg_array_size = len(g_cbeaSprgs)
                    p_current_sprg : CbeaSprg = g_cbeaSprgs

                    for sprg in g_cbeaSprgs:
                        if operand.reg == sprg.sprg:
                            ctx.out_register(sprg.shortName)
                            return 1

                    buf = f"{operand.reg:x}"
                    ctx.out_register(buf)
                    return 1
                
                elif operand.type == o_reg and operand-specflag1 & 0x08:
                        buf = f"%fr{operand.reg}"
                        ctx.out_register(buf)
                        return 1

        
        case ida_idp.processor_t.ev_out_insn:
            ctx : outctx_t = args[0]

            if ctx-insn.itype > altivec_insn_start:
                # Output mnemonic
                ctx.out_custom_mnem(g_altivec_opcodes[ctx.insn.itype - altivec_lvebx].name, 10)
                
                # Output operands
            if ctx.insn.ops[0].shown() and ctx.insn.ops[0].type != o_void:
                ctx.out_one_operand(0)

            if ctx.insn.ops[1].shown() and ctx.insn.ops[1].type != o_void:
                if ctx.insn.ops[0].shown():
                    ctx.out_symbol(',')
                    ctx.out_char(' ')
                
                ctx.out_one_operand(1)
            
            if ctx.insn.ops[2].shown() and ctx.insn.ops[2].type != o_void:
                if ctx.insn.ops[0].shown() or ctx.insn.ops[1].shown():
                    ctx.out_symbol(',')
                    ctx.out_char(' ')
                
                ctx.out_one_operand(2)
            
            if ctx.insn.ops[3].shown() and ctx.insn.ops[3].type != o_void:
                if ctx.insn.ops[0].shown() or ctx.insn.ops[1].shown() or ctx.insn.ops[2].shown():
                    ctx.out_symbol(',')
                    ctx.out_char(' ')
                
                ctx.out_one_operand(3)

            if ctx.insn.ops[4].shown() and ctx.insn.ops[4].type != o_void:
                if ctx.insn.ops[0].shown() or ctx.insn.ops[1].shown() or ctx.insn.ops[2].shown() or ctx.insn.ops[3].shown():
                    ctx.out_symbol(',')
                    ctx.out_char(' ')
                
                ctx.out_one_operand(4)

            if show_all_comments() and get_cmt(ctx.insn.ea, true) == -1:
                indent_loop = len(ctx.outbuf)
                while indent_loop < (inf.comment - inf.indent):
                    ctx.out_char(' ')
                    ctx.out_line("# ", COLOR_AUTOCMT)
                    ctx.out_line(g_altivec_opcodes[ctx.insn.itype - altivec_lvebx].description, COLOR_AUTOCMT)
                    
                    # Print out description of SPRG
                    for i in range(len(ctx.insn.ops)):  
                        sprg_array_size = len(g_cbeaSprgs)
                        pCurrentSprg : CbeaSprg = g_cbeaSprgs

                        # go through the entire special register array for looking for a match
                        for sprg in g_cbeaSprgs:
                            if op.reg == sprg.sprg:
                                ctx.out_line(sprg.comment, COLOR_AUTOCMT)

                    indent_loop += 1
                
            ctx.flush_outbuf()
            return 2

        # Can this be the start of a function?
        case ida_idp.processor_t.ev_may_be_func:
            insn : insn_t = args[0]
            if insn.itype > altivec_insn_start:
                return 100

        # If we've identified the command as an Altivec instruction, it's good to go.
        case ida_idp.processor_t.ev_is_sane_insn:
            insn : insn_t = args[0]
            if insn.itype > altivec_insn_start:
                return 1
            
    # We didn't process the event, let IDA Handle it
    return 0

# Plugin information
PLUGIN_NAME = "PowerPC Altivec"
PLUGIN_HELP = "support for VMX128, Xbox360(Xenon), PS3(CellBE) and GC/WII(Gekko) "
PLUGIN_COMMENT = "Altivec Plugin for IDA Pro"
PLUGIN_HOTKEY = "Ctrl+H"


kDefault, kEnabled, kDisabled = 0, 1, 2
g_HookState = kEnabled
g_AltivecNodeName = "$ AltivecPlugin"
g_AltivecNode = idaapi.netnode()


# Callback class
class PluginExtensionCallback(ida_idp.IDP_Hooks):
    def __init__(self):
        ida_idp.IDP_Hooks.__init__(self)

    def processor_run(self, ea):
        if g_HookState == kDisabled:
            return 0
        print(f"Processing address: {ea}")
        return 0

hook = PluginExtensionCallback()

def PluginStartup():
    global g_HookState
    
    # Check if platform is PowerPC
    if idaapi.ph.id != idaapi.PLFM_PPC:
        return idaapi.PLUGIN_SKIP

    g_AltivecNode.create(g_AltivecNodeName)
    databaseHookState = g_AltivecNode.altval(0)

    if databaseHookState != kDefault:
        g_HookState = databaseHookState

    if g_HookState == kEnabled:
        ida_kernwin.msg(f"{PLUGIN_NAME} is enabled\n")
        return idaapi.PLUGIN_KEEP

    return idaapi.PLUGIN_OK


def PluginShutdown():
    # Non eliminare il callback, solo fermarlo se necessario
    print("Plugin shutdown complete.")


def PluginMain(param):
    global g_HookState

    if g_HookState == kEnabled:
        g_HookState = kDisabled
    elif g_HookState == kDisabled:
        g_HookState = kEnabled

    g_AltivecNode.create(g_AltivecNodeName)
    g_AltivecNode.altset(0, g_HookState)

    hook_state_description = ["default", "enabled", "disabled"]
    ida_kernwin.info(f"AUTOHIDE NONE\n{PLUGIN_NAME} is now {hook_state_description[g_HookState]}")

    return True

class AltivecPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        return PluginStartup()

    def term(self):
        PluginShutdown()

    def run(self, arg):
        PluginMain(arg)

def PLUGIN_ENTRY():
    return AltivecPlugin()
