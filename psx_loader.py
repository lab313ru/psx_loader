from __future__ import annotations

# import pydevd_pycharm
import os

import ida_idp
import idaapi
import idc
from sig_applier import ONLY_FIRST, MIN_ENTROPY, DetectPsyQ, PsxExe


def accept_file(li, filename):
    psx_exe = PsxExe(os.path.basename(filename), ONLY_FIRST, MIN_ENTROPY)
    params = psx_exe.parse(li)

    if params is not None:
        return {'format': 'Playstation executable', 'processor': 'mipsl'}

    return 0


def load_file(li, neflags, format):
    # pydevd_pycharm.settrace('localhost', port=1234, stdoutToServer=True, stderrToServer=True)

    fname = idaapi.get_input_file_path()
    psx_exe = PsxExe(os.path.basename(fname), ONLY_FIRST, MIN_ENTROPY)
    psx = psx_exe.parse(li)

    idaapi.set_processor_type('mipsl', ida_idp.SETPROC_LOADER)

    idaapi.cvar.inf.af = idaapi.AF_CODE | idaapi.AF_JUMPTBL | idaapi.AF_USED | idaapi.AF_UNK | idaapi.AF_PROC | \
                         idaapi.AF_STKARG | idaapi.AF_REGARG | idaapi.AF_TRACE | idaapi.AF_VERSP | idaapi.AF_ANORET | \
                         idaapi.AF_MEMFUNC | idaapi.AF_TRFUNC | idaapi.AF_FIXUP | idaapi.AF_JFUNC | idaapi.AF_IMMOFF | \
                         idaapi.AF_STRLIT | idaapi.AF_MARKCODE | idaapi.AF_LVAR | idaapi.AF_PROCPTR | idaapi.AF_FLIRT

    psx_exe.create_segments(li, psx)

    detect = DetectPsyQ(psx_exe.get_exe_name(), ONLY_FIRST, MIN_ENTROPY)
    version = detect.get_psyq_version(psx['rom_addr'], psx['rom_addr'] + psx['rom_size'])

    if len(version) > 0:
        psx_exe.apply_psyq_signatures_by_version(version, psx['rom_addr'], psx['rom_addr'] + psx['rom_size'])

    idaapi.add_entry(psx['pc'], psx['pc'], 'start', 1)

    idc.process_config_line("MIPS_DEFAULT_ABI=o32")
    idaapi.set_compiler_id(idaapi.COMP_GNU, "o32")

    PsxExe.apply_til(version)
    
    if psx['gp'] != 0:
        idc.process_config_line("MIPS_GP=0x%08X" % psx['gp'])
    else:
        idaapi.warning('$GP from header is zero! Check \'start\' function for a $gp loading instruction.\n')

    return 1
