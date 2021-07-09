from __future__ import annotations

# import pydevd_pycharm
import os

import ida_idp
import idaapi
import idc
from sig_applier import ONLY_FIRST, MIN_ENTROPY, DetectPsyQ, PsxExe


def accept_file(li, filename):
    psx_exe = PsxExe(os.path.basename(filename), ONLY_FIRST, MIN_ENTROPY)
    good = psx_exe.parse(li, False)

    if good:
        return {'format': 'Playstation executable', 'processor': 'mipsl'}

    return 0


def load_file(li, neflags, format):
    # pydevd_pycharm.settrace('localhost', port=1234, stdoutToServer=True, stderrToServer=True)

    fname = idaapi.get_input_file_path()
    psx = PsxExe(os.path.basename(fname), ONLY_FIRST, MIN_ENTROPY)
    psx.parse(li, True)

    idaapi.set_processor_type('mipsl', ida_idp.SETPROC_LOADER)

    idaapi.cvar.inf.af = \
        idaapi.AF_CODE | idaapi.AF_JUMPTBL | idaapi.AF_USED | idaapi.AF_UNK | idaapi.AF_PROC | idaapi.AF_STKARG | \
        idaapi.AF_REGARG | idaapi.AF_TRACE | idaapi.AF_VERSP | idaapi.AF_ANORET | idaapi.AF_MEMFUNC | \
        idaapi.AF_TRFUNC | idaapi.AF_FIXUP | idaapi.AF_JFUNC | idaapi.AF_IMMOFF | idaapi.AF_STRLIT | \
        idaapi.AF_MARKCODE | idaapi.AF_LVAR | idaapi.AF_PROCPTR | idaapi.AF_FLIRT

    psx.create_segments(li)

    im = idaapi.compiler_info_t()
    idaapi.inf_get_cc(im)
    im.id = idaapi.COMP_GNU
    im.cm = idaapi.CM_N32_F48 | idaapi.CM_M_NN | idaapi.CM_CC_CDECL
    im.defalign = 4
    im.size_i = 4
    im.size_b = 1
    im.size_e = 4
    im.size_s = 2
    im.size_l = 4
    im.size_ll = 8
    im.size_ldbl = 8
    idaapi.inf_set_cc(im)
    # Replace predefined macros and included directories by id
    # from IDA.CFG (see 'CC_PARMS' in Built-in C parser parameters)
    idaapi.set_c_macros(ida_idp.cfg_get_cc_predefined_macros(im.id))
    idaapi.set_c_header_path(ida_idp.cfg_get_cc_header_path(im.id))
    # Resetting new settings :)
    idc.set_inf_attr(idc.INF_COMPILER, im.id)

    idc.process_config_line("MIPS_DEFAULT_ABI=o32")

    detect = DetectPsyQ(psx.get_exe_name(), ONLY_FIRST, MIN_ENTROPY)
    version = detect.get_psyq_version(psx.rom_addr, psx.rom_addr + psx.rom_size)

    if len(version) > 0:
        psx.apply_psyq_signatures_by_version(version)

    idaapi.add_entry(psx.init_pc, psx.init_pc, 'start', 1)

    PsxExe.apply_til(version)

    psx.update_gp()

    return 1
