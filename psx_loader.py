import struct

import ida_idp
import ida_search
import idaapi
import idc


class PsxExe:
    def __init__(self):
        pass

    @classmethod
    def parse(cls, li):
        li.seek(0)

        header = li.read(0x800)

        if len(header) < 0x800:
            return None

        pos = 0
        ascii_id = struct.unpack_from('8s', header, pos)[0]

        if ascii_id != 'PS-X EXE':
            return None

        init_pc = struct.unpack_from('I', header, 0x10)[0]
        idaapi.msg('PC = 0x%08X\n' % init_pc)
        init_gp = struct.unpack_from('I', header, 0x14)[0]
        idaapi.msg('GP = 0x%08X\n' % init_gp)
        rom_addr = struct.unpack_from('I', header, 0x18)[0]
        rom_size = struct.unpack_from('I', header, 0x1C)[0]
        idaapi.msg('ROM[0x%08X:0x%08X]\n' % (rom_addr, rom_addr + rom_size))
        data_addr = struct.unpack_from('I', header, 0x20)[0]
        data_size = struct.unpack_from('I', header, 0x24)[0]
        idaapi.msg('DATA[0x%08X:0x%08X]\n' % (data_addr, data_addr + data_size))
        bss_addr = struct.unpack_from('I', header, 0x28)[0]
        bss_size = struct.unpack_from('I', header, 0x2C)[0]
        idaapi.msg('BSS[0x%08X:0x%08X]\n' % (bss_addr, bss_addr + bss_size))
        sp_base = struct.unpack_from('I', header, 0x30)[0]
        sp_offset = struct.unpack_from('I', header, 0x34)[0]
        idaapi.msg('SP = 0x%08X\n' % (sp_base + sp_offset))

        return\
            {
                'pc': init_pc,
                'gp': init_gp,
                'rom_addr': rom_addr,
                'rom_size': rom_size,
                'data_addr': data_addr,
                'data_size': data_size,
                'bss_addr': bss_addr,
                'bss_size': bss_size,
                'sp_base': sp_base,
                'sp_offset': sp_offset
            }

    @classmethod
    def find_main(cls, rom_addr, rom_end):
        addr = ida_search.find_binary(rom_addr, rom_end, '00 00 00 00 ? ? ? ? 00 00 00 00 4D 00 00 00', 16,
                                      idaapi.SEARCH_DOWN)

        if addr != idaapi.BADADDR:
            addr += 4
            addr = idc.get_operand_value(addr, 0)

        return addr

    @staticmethod
    def add_port_4(ea, name):
        idaapi.set_name(ea, name)
        idaapi.create_dword(ea, 4)

    @staticmethod
    def add_port_2(ea, name):
        idaapi.set_name(ea, name)
        idaapi.create_word(ea, 2)

    @staticmethod
    def add_port_1(ea, name):
        idaapi.set_name(ea, name)
        idaapi.create_byte(ea, 1)

    @classmethod
    def add_mem_ctrl1(cls):
        idaapi.add_segm(0, 0x1F801000, 0x1F801024, 'MCTRL1', 'XTRN')

        cls.add_port_4(0x1F801000, 'EXP1_BASE_ADDR')
        cls.add_port_4(0x1F801004, 'EXP2_BASE_ADDR')
        cls.add_port_4(0x1F801008, 'EXP1_DELAY_SIZE')
        cls.add_port_4(0x1F80100C, 'EXP3_DELAY_SIZE')
        cls.add_port_4(0x1F801010, 'BIOS_ROM')
        cls.add_port_4(0x1F801014, 'SPU_DELAY')
        cls.add_port_4(0x1F801018, 'CDROM_DELAY')
        cls.add_port_4(0x1F80101C, 'EXP2_DELAY_SIZE')
        cls.add_port_4(0x1F801020, 'COMMON_DELAY')

    @classmethod
    def add_mem_ctrl2(cls):
        idaapi.add_segm(0, 0x1F801060, 0x1F801064, 'MCTRL2', 'XTRN')

        cls.add_port_4(0x1F801060, 'RAM_SIZE')

    @classmethod
    def add_periph_io(cls):
        idaapi.add_segm(0, 0x1F801040, 0x1F801060, 'IO_PORTS', 'XTRN')

        cls.add_port_4(0x1F801040, 'JOY_MCD_DATA')
        cls.add_port_4(0x1F801044, 'JOY_MCD_STAT')
        cls.add_port_2(0x1F801048, 'JOY_MCD_MODE')
        cls.add_port_2(0x1F80104A, 'JOY_MCD_CTRL')
        cls.add_port_2(0x1F80104E, 'JOY_MCD_BAUD')

        cls.add_port_4(0x1F801050, 'SIO_DATA')
        cls.add_port_4(0x1F801054, 'SIO_STAT')
        cls.add_port_2(0x1F801058, 'SIO_MODE')
        cls.add_port_2(0x1F80105A, 'SIO_CTRL')
        cls.add_port_2(0x1F80105C, 'SIO_MISC')
        cls.add_port_2(0x1F80105E, 'SIO_BAUD')

    @classmethod
    def add_int_ctrl(cls):
        idaapi.add_segm(0, 0x1F801070, 0x1F801076, 'INT_CTRL', 'XTRN')

        cls.add_port_2(0x1F801070, 'I_STAT')
        cls.add_port_2(0x1F801074, 'I_MASK')

    @classmethod
    def add_dma(cls):
        idaapi.add_segm(0, 0x1F801080, 0x1F801090, 'DMA_MDEC_IN', 'XTRN')
        idaapi.add_segm(0, 0x1F801090, 0x1F8010A0, 'DMA_MDEC_OUT', 'XTRN')
        idaapi.add_segm(0, 0x1F8010A0, 0x1F8010B0, 'DMA_GPU', 'XTRN')
        idaapi.add_segm(0, 0x1F8010B0, 0x1F8010C0, 'DMA_CDROM', 'XTRN')
        idaapi.add_segm(0, 0x1F8010C0, 0x1F8010D0, 'DMA_SPU', 'XTRN')
        idaapi.add_segm(0, 0x1F8010D0, 0x1F8010E0, 'DMA_PIO', 'XTRN')
        idaapi.add_segm(0, 0x1F8010E0, 0x1F8010F0, 'DMA_OTC', 'XTRN')
        idaapi.add_segm(0, 0x1F8010F0, 0x1F8010F4, 'DMA_CTRL_INT', 'XTRN')

        cls.add_port_4(0x1F801080, 'DMA_MDEC_IN_MADR')
        cls.add_port_4(0x1F801084, 'DMA_MDEC_IN_BCR')
        cls.add_port_4(0x1F801088, 'DMA_MDEC_IN_CHCR')

        cls.add_port_4(0x1F801090, 'DMA_MDEC_OUT_MADR')
        cls.add_port_4(0x1F801094, 'DMA_MDEC_OUT_BCR')
        cls.add_port_4(0x1F801098, 'DMA_MDEC_OUT_CHCR')

        cls.add_port_4(0x1F8010A0, 'DMA_GPU_MADR')
        cls.add_port_4(0x1F8010A4, 'DMA_GPU_BCR')
        cls.add_port_4(0x1F8010A8, 'DMA_GPU_CHCR')

        cls.add_port_4(0x1F8010B0, 'DMA_CDROM_MADR')
        cls.add_port_4(0x1F8010B4, 'DMA_CDROM_BCR')
        cls.add_port_4(0x1F8010B8, 'DMA_CDROM_CHCR')

        cls.add_port_4(0x1F8010C0, 'DMA_SPU_MADR')
        cls.add_port_4(0x1F8010C4, 'DMA_SPU_BCR')
        cls.add_port_4(0x1F8010C8, 'DMA_SPU_CHCR')

        cls.add_port_4(0x1F8010D0, 'DMA_PIO_MADR')
        cls.add_port_4(0x1F8010D4, 'DMA_PIO_BCR')
        cls.add_port_4(0x1F8010D8, 'DMA_PIO_CHCR')

        cls.add_port_4(0x1F8010E0, 'DMA_OTC_MADR')
        cls.add_port_4(0x1F8010E4, 'DMA_OTC_BCR')
        cls.add_port_4(0x1F8010E8, 'DMA_OTC_CHCR')

        cls.add_port_4(0x1F8010F0, 'DMA_DPCR')
        cls.add_port_4(0x1F8010F4, 'DMA_DICR')

    @classmethod
    def add_timers(cls):
        idaapi.add_segm(0, 0x1F801100, 0x1F801110, 'TMR_DOTCLOCK', 'XTRN')
        idaapi.add_segm(0, 0x1F801110, 0x1F801120, 'TMR_HRETRACE', 'XTRN')
        idaapi.add_segm(0, 0x1F801120, 0x1F801130, 'TMR_SYSCLOCK', 'XTRN')

        cls.add_port_4(0x1F801100, 'TMR_DOTCLOCK_VAL')
        cls.add_port_4(0x1F801104, 'TMR_DOTCLOCK_MODE')
        cls.add_port_4(0x1F801108, 'TMR_DOTCLOCK_MAX')

        cls.add_port_4(0x1F801110, 'TMR_HRETRACE_VAL')
        cls.add_port_4(0x1F801114, 'TMR_HRETRACE_MODE')
        cls.add_port_4(0x1F801118, 'TMR_HRETRACE_MAX')

        cls.add_port_4(0x1F801120, 'TMR_SYSCLOCK_VAL')
        cls.add_port_4(0x1F801124, 'TMR_SYSCLOCK_MODE')
        cls.add_port_4(0x1F801128, 'TMR_SYSCLOCK_MAX')

    @classmethod
    def add_cdrom_regs(cls):
        idaapi.add_segm(0, 0x1F801800, 0x1F801804, 'CDROM_REGS', 'XTRN')

        cls.add_port_1(0x1F801800, 'CDROM_REG0')
        cls.add_port_1(0x1F801801, 'CDROM_REG1')
        cls.add_port_1(0x1F801802, 'CDROM_REG2')
        cls.add_port_1(0x1F801803, 'CDROM_REG3')

    @classmethod
    def add_gpu_regs(cls):
        idaapi.add_segm(0, 0x1F801810, 0x1F801818, 'GPU_REGS', 'XTRN')

        cls.add_port_4(0x1F801810, 'GPU_REG0')
        cls.add_port_4(0x1F801814, 'GPU_REG1')

    @classmethod
    def add_mdec_regs(cls):
        idaapi.add_segm(0, 0x1F801820, 0x1F801828, 'MDEC_REGS', 'XTRN')

        cls.add_port_4(0x1F801820, 'MDEC_REG0')
        cls.add_port_4(0x1F801824, 'MDEC_REG1')

    @classmethod
    def add_spu_voices(cls):
        idaapi.add_segm(0, 0x1F801C00, 0x1F801C00 + 0x10 * 24, 'SPU_VOICES', 'XTRN')

        for i in xrange(24):
            cls.add_port_4(0x1F801C00 + i * 0x10 + 0x00, 'VOICE_%02x_LEFT_RIGHT' % i)
            cls.add_port_2(0x1F801C00 + i * 0x10 + 0x04, 'VOICE_%02x_ADPCM_SAMPLE_RATE' % i)
            cls.add_port_2(0x1F801C00 + i * 0x10 + 0x06, 'VOICE_%02x_ADPCM_START_ADDR' % i)
            cls.add_port_2(0x1F801C00 + i * 0x10 + 0x08, 'VOICE_%02x_ADSR_ATT_DEC_SUS_REL' % i)
            cls.add_port_2(0x1F801C00 + i * 0x10 + 0x0C, 'VOICE_%02x_ADSR_CURR_VOLUME' % i)
            cls.add_port_2(0x1F801C00 + i * 0x10 + 0x0E, 'VOICE_%02x_ADPCM_REPEAT_ADDR' % i)


    @classmethod
    def add_spu_ctrl_regs(cls):
        idaapi.add_segm(0, 0x1F801D80, 0x1F801DC0, 'SPU_CTRL_REGS', 'XTRN')

        cls.add_port_2(0x1F801D80, 'SPU_MAIN_VOL_L')
        cls.add_port_2(0x1F801D82, 'SPU_MAIN_VOL_R')
        cls.add_port_2(0x1F801D84, 'SPU_REVERB_OUT_L')
        cls.add_port_2(0x1F801D86, 'SPU_REVERB_OUT_R')
        cls.add_port_4(0x1F801D88, 'SPU_VOICE_KEY_ON')
        cls.add_port_4(0x1F801D8C, 'SPU_VOICE_KEY_OFF')
        cls.add_port_4(0x1F801D90, 'SPU_VOICE_CHN_FM_MODE')
        cls.add_port_4(0x1F801D94, 'SPU_VOICE_CHN_NOISE_MODE')
        cls.add_port_4(0x1F801D98, 'SPU_VOICE_CHN_REVERB_MODE')
        cls.add_port_4(0x1F801D9C, 'SPU_VOICE_CHN_ON_OFF_STATUS')
        cls.add_port_2(0x1F801DA0, 'SPU_UNKN_1DA0')
        cls.add_port_2(0x1F801DA2, 'SOUND_RAM_REVERB_WORK_ADDR')
        cls.add_port_2(0x1F801DA4, 'SOUND_RAM_IRQ_ADDR')
        cls.add_port_2(0x1F801DA6, 'SOUND_RAM_DATA_TRANSFER_ADDR')
        cls.add_port_2(0x1F801DA8, 'SOUND_RAM_DATA_TRANSFER_FIFO')
        cls.add_port_2(0x1F801DAA, 'SPU_CTRL_REG_CPUCNT')
        cls.add_port_2(0x1F801DAC, 'SOUND_RAM_DATA_TRANSTER_CTRL')
        cls.add_port_2(0x1F801DAE, 'SPU_STATUS_REG_SPUSTAT')
        cls.add_port_2(0x1F801DB0, 'CD_VOL_L')
        cls.add_port_2(0x1F801DB2, 'CD_VOL_R')
        cls.add_port_2(0x1F801DB4, 'EXT_VOL_L')
        cls.add_port_2(0x1F801DB6, 'EXT_VOL_R')
        cls.add_port_2(0x1F801DB8, 'CURR_MAIN_VOL_L')
        cls.add_port_2(0x1F801DBA, 'CURR_MAIN_VOL_R')
        cls.add_port_4(0x1F801DBC, 'SPU_UNKN_1DBC')

    @classmethod
    def create_segments(cls, li, psx):
        li.seek(0x800)

        code = li.read(psx['rom_size'])

        idaapi.add_segm(0, 0x80000000, psx['rom_addr'], 'RAM', 'DATA')
        idc.set_default_sreg_value(0x80000000, 'ds', 0)

        idaapi.mem2base(code, psx['rom_addr'], 0x800)
        idaapi.add_segm(0, psx['rom_addr'], psx['rom_addr'] + psx['rom_size'], 'CODE', 'CODE')
        idc.set_default_sreg_value(psx['rom_addr'], 'ds', 0)

        if psx['data_addr'] != 0:
            idaapi.add_segm(0, psx['data_addr'], psx['data_addr'] + psx['data_size'], '.data', 'DATA')
            idc.set_default_sreg_value(psx['data_addr'], 'ds', 0)

        if psx['bss_addr'] != 0:
            idaapi.add_segm(0, psx['bss_addr'], psx['bss_addr'] + psx['bss_size'], '.bss', 'BSS')
            idc.set_default_sreg_value(psx['bss_addr'], 'ds', 0)

        idaapi.add_segm(0, psx['rom_addr'] + psx['rom_size'], 0x80200000, 'RAM', 'DATA')
        idc.set_default_sreg_value(psx['rom_addr'] + psx['rom_size'], 'ds', 0)

        idaapi.add_segm(0, 0x1F800000, 0x1F800400, 'CACHE', 'DATA')
        idaapi.add_segm(0, 0x1F800400, 0x1F801000, 'UNK1', 'XTRN')

        cls.add_mem_ctrl1()
        cls.add_mem_ctrl2()
        cls.add_periph_io()
        cls.add_int_ctrl()
        cls.add_dma()
        cls.add_timers()
        cls.add_cdrom_regs()
        cls.add_gpu_regs()
        cls.add_mdec_regs()
        cls.add_spu_voices()
        cls.add_spu_ctrl_regs()

        idaapi.cvar.inf.start_ss = idaapi.cvar.inf.start_cs = 0
        idaapi.cvar.inf.start_ip = idaapi.cvar.inf.start_ea = psx['pc']
        idaapi.cvar.inf.start_sp = psx['sp_base'] + psx['sp_offset']
        # idaapi.cvar.inf.main = cls.find_main(psx['rom_addr'], psx['rom_addr'] + psx['rom_size'])
        #
        # if idaapi.cvar.inf.main != idaapi.BADADDR:
        #     idaapi.msg('main() addr = 0x%08X\n' % idaapi.cvar.inf.main)
        #     idaapi.set_name(idaapi.cvar.inf.main, 'main')




def accept_file(li, filename):
    psx_exe = PsxExe()
    params = psx_exe.parse(li)

    if params is not None:
        return {'format': 'Playstation executable', 'processor': 'mipsl'}
    else:
        return 0


def load_file(li, neflags, format):
    psx_exe = PsxExe()
    psx = psx_exe.parse(li)

    idaapi.set_processor_type('mipsl', ida_idp.SETPROC_LOADER)

    idaapi.cvar.inf.af = idaapi.AF_CODE | idaapi.AF_JUMPTBL | idaapi.AF_USED | idaapi.AF_UNK | idaapi.AF_PROC | \
        idaapi.AF_STKARG | idaapi.AF_REGARG | idaapi.AF_TRACE | idaapi.AF_VERSP | idaapi.AF_ANORET | \
        idaapi.AF_MEMFUNC | idaapi.AF_TRFUNC | idaapi.AF_FIXUP | idaapi.AF_JFUNC | idaapi.AF_IMMOFF | \
        idaapi.AF_STRLIT | idaapi.AF_MARKCODE | idaapi.AF_LVAR | idaapi.AF_PROCPTR

    psx_exe.create_segments(li, psx)

    idaapi.add_entry(psx['pc'], psx['pc'], 'start', 1)

    idc.process_config_line("MIPS_DEFAULT_ABI=o32")

    return 1
