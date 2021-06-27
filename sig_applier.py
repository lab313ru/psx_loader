from __future__ import annotations

# import pydevd_pycharm
import binascii
import json
import math
import os
import struct
from typing import List, Optional, Tuple

import ida_auto
import ida_bytes
import ida_entry
import ida_idp
import idaapi
import idc


ONLY_FIRST = True
MIN_ENTROPY = 3.0


def masked_search(start_addr: int, end_addr: int, bytes_data: bytes, masks_data: bytes) -> Tuple[int, Optional[bytes]]:
    def prepare_first_search(bd: bytes, md: bytes) -> bytes:
        bd_str = binascii.hexlify(bd, ' ').split(b' ')
        md_str = binascii.hexlify(md, ' ').split(b' ')

        for ii, md_token in enumerate(md_str):
            if md_token != b'ff':
                bd_str[ii] = b'?'

        bd_str = b' '.join(bd_str)

        return bd_str

    len_bytes = len(bytes_data)

    bytes_data_prep = prepare_first_search(bytes_data, masks_data)

    patterns = ida_bytes.compiled_binpat_vec_t()
    idaapi.parse_binpat_str(patterns, start_addr, bytes_data_prep.decode(), 16)
    ea = ida_bytes.bin_search(start_addr, end_addr, patterns,
                              ida_bytes.BIN_SEARCH_FORWARD |
                              ida_bytes.BIN_SEARCH_NOBREAK |
                              ida_bytes.BIN_SEARCH_NOSHOW)

    if ea == idaapi.BADADDR:
        return idaapi.BADADDR, None

    found_bytes = idaapi.get_bytes(ea, len_bytes)

    equal = True
    for i in range(len_bytes):
        m = masks_data[i]
        if found_bytes[i] & m != bytes_data[i] & m:
            equal = False
            break

    if equal:
        return ea, found_bytes

    return idaapi.BADADDR, None


class DetectPsyQ:
    VERSION_BYTES = [0x50, 0x73, 0x07, 0x00, 0x00, 0x00, 0x47, 0x00]  # , 0x07 - is a lib number, 0x47 - a version
    VERSION_MASK = [0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0xEE]
    VERSION_OFFSET = 0x06

    OLD_VERSIONS = ['260', '300', '330', '340', '350']
    OLD_UNIQUE_LIB = 'LIBGPU.LIB'
    OLD_UNIQUE_OBJ = 'SYS.OBJ'

    def __init__(self, game_id, only_first: bool, min_entropy: float) -> None:
        self._game_id = game_id
        self._only_first = only_first
        self._min_entropy = min_entropy

    def get_psyq_version(self, start_addr: int, end_addr: int) -> str:
        offset, data = masked_search(start_addr, end_addr, bytes(DetectPsyQ.VERSION_BYTES), bytes(DetectPsyQ.VERSION_MASK))

        if offset == idaapi.BADADDR:
            return self.__get_old_psy_version(start_addr, end_addr)

        version = idaapi.get_word(offset + DetectPsyQ.VERSION_OFFSET)  # not swapped

        if version & 0xFF00 == 0:
            return '%03X' % ((version & 0xFF) << 4)

        return '%X' % (((version >> 0) & 0xFF) | ((version >> 8) & 0xFF))

    def __get_old_psy_version(self, start_addr: int, end_addr: int) -> str:
        psyq_dir = idaapi.idadir(os.path.join('loaders', 'psyq'))

        dirs = list()
        for ver, _, _ in os.walk(psyq_dir):
            vv = os.path.basename(ver)
            if vv in DetectPsyQ.OLD_VERSIONS:
                dirs.append(ver)

        for ver_dir in dirs:
            lib_json_file = os.path.join(ver_dir, '%s.json' % DetectPsyQ.OLD_UNIQUE_LIB)
            sig = SigApplier(self._game_id, lib_json_file, None, self._only_first, self._min_entropy)

            signatures = sig.get_signatures()

            for item in signatures:
                if item.get_name() != DetectPsyQ.OLD_UNIQUE_OBJ:
                    continue

                bytes_data = item.get_sig()

                offset, _ = masked_search(start_addr, end_addr, bytes_data.get_bytes(), bytes_data.get_masks())

                if offset != idaapi.BADADDR:
                    return os.path.basename(ver_dir)

        return ''


class MaskedBytes:
    def __init__(self, bytes_data: bytes, masks_data: bytes):
        self._bytes_data = bytearray(bytes_data)
        self._masks_data = bytearray(masks_data)

    def __len__(self) -> int:
        return len(self._bytes_data)

    def get_bytes(self) -> bytes:
        return bytes(self._bytes_data)

    def get_masks(self) -> bytes:
        return bytes(self._masks_data)

    @staticmethod
    def from_masked_string(sig: str) -> Optional[MaskedBytes]:
        if sig is None:
            return None

        ll = len(sig)

        if (ll % 3) != 0:
            return None

        bytes_data = bytearray(b'\x00' * (ll // 3))
        masks_data = bytearray(b'\x00' * (ll // 3))

        for i in range(0, ll, 3):
            c1 = sig[i]
            c2 = sig[i + 1]

            masks_data[i // 3] = ((0x00 if (c1 == '?') else 0x0F) << 4) |\
                                 ((0x00 if (c2 == '?') else 0x0F) << 0)

            bytes_data[i // 3] = ((0x00 if (c1 == '?') else int(c1, 16)) << 4) |\
                                 ((0x00 if (c2 == '?') else int(c2, 16)) << 0)

        return MaskedBytes(bytes(bytes_data), bytes(masks_data))

    def calc_entropy(self) -> float:
        counts = [0] * 256
        entropy = 0.0
        total = len(self) * 1.0

        f = bytearray(self.get_bytes())
        m = bytearray(self.get_masks())

        for i in range(len(m)):
            f[i] &= m[i]

        for b in f:
            counts[((b ^ 0x80) - 0x80) + 128] += 1

        for c in counts:
            if c == 0:
                continue

            p = c / total

            entropy -= p * math.log(p) / math.log(2)

        return entropy

    def apply_patches(self, patches: List[Tuple[int, Tuple[str, str]]], labels: List[Tuple[str, int]]) ->\
            List[Tuple[str, int]]:
        if patches is None or len(patches) == 0:
            return labels

        new_labels = []
        new_labels.extend(labels)

        offset_delta = 0

        for patch in patches:
            patch_off = offset_delta + patch[0]
            patch_data = patch[1]
            patch_bytes = MaskedBytes.from_masked_string(patch_data[0][1:])
            patch_check_bytes = MaskedBytes.from_masked_string(patch_data[1])
            check_bytes = patch_check_bytes._bytes_data if patch_check_bytes else None
            patch_bytes_len = len(patch_bytes) if patch_bytes else 0
            shift = 0

            if patch_data[0][0] == '~':  # replace bytes
                for i in range(patch_bytes_len):
                    if self._bytes_data[patch_off + i] != check_bytes[i]:
                        raise Exception('Wrong replace-patch data, OFF: %d, data: %s' % (patch[0], patch_data[1]))

                    self._bytes_data[patch_off + i] = patch_bytes._bytes_data[i]
                    self._masks_data[patch_off + i] = patch_bytes._masks_data[i]

            elif patch_data[0][0] == '+':  # insert bytes
                self.expand(patch_bytes, patch_off)

                shift = patch_bytes_len
                offset_delta += patch_bytes_len
            elif patch_data[0][0] == '-':  # remove bytes
                count = int(patch_data[0][1:])
                self.shrink(count, patch_off)

                shift = -count
                offset_delta -= count

            if shift == 0:
                continue

            for i in range(len(labels)):
                lb_name = new_labels[i][0]
                lb_offs = new_labels[i][1]
                old_off = labels[i][1]

                # remove labels within removed range
                if shift < 0 and (old_off >= patch[0]) and (old_off < patch[0] + (-1 * shift)):
                    lb_name = ''

                if patch_off < lb_offs:
                    lb_offs += shift

                new_labels[i] = (lb_name, lb_offs)

        return new_labels

    def expand(self, add: MaskedBytes, offset: int) -> None:
        self._bytes_data = self._bytes_data[:offset]
        self._masks_data = self._masks_data[:offset]

        self._bytes_data.extend(add.get_bytes())
        self._masks_data.extend(add.get_masks())

        self._bytes_data.extend(self._bytes_data[offset:])
        self._masks_data.extend(self._masks_data[offset:])

    def shrink(self, length: int, offset: int) -> None:
        self._bytes_data = self._bytes_data[:offset]
        self._masks_data = self._masks_data[:offset]

        self._bytes_data.extend(self._bytes_data[:offset])
        self._masks_data.extend(self._masks_data[:offset])

        self._bytes_data.extend(self._bytes_data[offset+length:])
        self._masks_data.extend(self._masks_data[offset+length:])


class PsyqSig:
    def __init__(self, name: str, sig: MaskedBytes, labels: List[Tuple[str, int]]):
        self._name = name
        self._sig = sig
        self._labels = labels
        self._entropy = sig.calc_entropy()
        self._applied = False

    @classmethod
    def from_json_token(cls, token: dict, patches: List[dict]) -> PsyqSig:
        name = token['name']
        sig = token['sig']

        signature = MaskedBytes.from_masked_string(sig)

        labels = list()
        arr = token['labels']

        for item in arr:
            item_name = item['name']
            item_offs = item['offset']
            labels.append((item_name, item_offs))

        if patches is None:
            return PsyqSig(name, signature, labels)

        patches_list = list()

        for patch in patches:
            patch_name = patch['name']

            if name.lower() != patch_name.lower():
                continue

            pos_patches = patch['patches']

            for pos_patch in pos_patches:
                pos = pos_patch['pos']
                item_data = pos_patch['data']
                item_check_data = pos_patch['check'] if pos_patch['check'] else None
                patches_list.append((pos, (item_data, item_check_data)))

        new_labels = signature.apply_patches(patches_list, labels)
        return PsyqSig(name, signature, new_labels)

    def get_entropy(self) -> float:
        return self._entropy

    def set_applied(self, applied: bool) -> None:
        self._applied = applied

    def get_name(self) -> str:
        return self._name

    def get_sig(self) -> MaskedBytes:
        return self._sig

    def get_labels(self) -> List[Tuple[str, int]]:
        return self._labels

    def is_applied(self) -> bool:
        return self._applied


class SigApplier:
    def __init__(self, game_id: str, lib_json_path: str, patches_file: Optional[str], only_first: bool, min_entropy: float) \
            -> None:
        self.game_id = game_id
        self.only_first = only_first
        self.min_entropy = min_entropy

        f, e = os.path.splitext(lib_json_path)
        self.short_lib_name = os.path.basename(f)

        root = None

        if lib_json_path and os.path.exists(lib_json_path):
            with open(lib_json_path) as f:
                root = json.load(f)

        patches = None

        if patches_file and os.path.exists(patches_file):
            with open(patches_file) as f:
                patches = json.load(f)

        d, f = os.path.split(lib_json_path)
        d, psyq_lib_version = os.path.split(d)

        patches_obj = self.__find_game_patches(patches, psyq_lib_version)

        self._signatures = list()

        for item in root:
            sig = PsyqSig.from_json_token(item, patches_obj)

            self._signatures.append(sig)

    def __find_game_patches(self, patches: dict, version: str) -> Optional[list]:
        if patches is None:
            return None

        for patch in patches:
            for game in patch['names']:
                patch_game_name = game.replace('_', '').replace('.', '')

                if patch_game_name.lower() != self.game_id.lower():
                    continue

                libs = patch['libs']

                for lib in libs:
                    patch_lib_name = lib['name']

                    if patch_lib_name.lower() != self.short_lib_name.lower():
                        continue

                    patch_lib_vers = lib['versions']

                    for lib_ver in patch_lib_vers:
                        patch_lib_ver = lib_ver.replace('.', '')

                        if patch_lib_ver.lower() != version.lower():
                            continue

                        return lib['objs']

        return None

    def apply_signatures(self, start_addr: int, end_addr: int) -> None:
        total_objs = len(self._signatures)

        idaapi.msg('Applying obj symbols...\n')

        objs_list = dict()

        for sig in self._signatures:
            low_entropy = sig.get_entropy() < self.min_entropy

            bytes_data = sig.get_sig()
            labels = sig.get_labels()

            search_addr = start_addr

            while search_addr < end_addr:
                addr, _ = masked_search(search_addr, end_addr, bytes_data.get_bytes(), bytes_data.get_masks())

                if addr == idaapi.BADADDR:
                    break

                if not sig.is_applied():
                    objs_list[sig.get_name()] = (addr, sig.get_entropy())

                for lb in labels:
                    lb_name = lb[0]
                    lb_offs = lb[1]

                    if lb_name == '':  # removed label
                        continue

                    lb_addr = addr + lb_offs

                    if ida_bytes.is_unknown(ida_bytes.get_flags(lb_addr) and not low_entropy and not (sig.is_applied() and self.only_first)):
                        ida_auto.auto_make_code(lb_addr)

                    is_func = not lb_name.startswith('loc_')
                    new_name = '%s_' % sig.get_name().replace('.', '_')
                    new_lb_name = lb_name.replace('text_', new_name).replace('loc_', new_name)
                    new_lb_name = ('_%s' % new_lb_name) if ('0' <= new_lb_name[0] <= '9') else new_lb_name

                    if not low_entropy and not (sig.is_applied() and self.only_first) and not self.has_non_default_name(lb_addr, new_lb_name):
                        SigApplier.set_function(lb_addr, new_lb_name, is_func, False)
                        idaapi.msg('Symbol %s at 0x%08X\n' % (new_lb_name, lb_addr))
                    else:
                        prev_comment = ida_bytes.get_cmt(lb_addr, False)

                        prev_comment = ('%s\n' % prev_comment) if prev_comment else ''

                        new_comment = 'Possible %s/%s' % (sig.get_name(), new_lb_name)

                        if prev_comment.find(new_comment) == -1:
                            ida_bytes.set_cmt(lb_addr, '%s%s' % (prev_comment, new_comment), False)
                            idaapi.msg('Possible symbol %s at 0x%08X\n' % (new_lb_name, lb_addr))

                sig.set_applied(True)

                search_addr = addr + 4

        idaapi.msg('Applied OBJs for %s: %d/%d:\n' % (self.short_lib_name, len(objs_list), total_objs))

        for k, v in objs_list.items():
            idaapi.msg('\t0x%08X: %s, %.02f entropy\n' % (v[0], k, v[1]))

    @staticmethod
    def set_function(address: int, name: str, is_func: bool, is_entry: bool) -> None:
        ida_auto.auto_make_code(address)

        if is_func:
            ida_auto.auto_make_proc(address)
            idaapi.set_name(address, name, idaapi.SN_NOCHECK | idaapi.SN_NOWARN)

        idaapi.auto_wait()

        if is_func:
            fn = idaapi.get_func(address)

            if fn:
                fn.flags |= idaapi.FUNC_LIB

        if is_entry:
            ida_entry.add_entry(address, address, name, True)

        if is_func and SigApplier.has_non_default_name(address, None):
            return

        idaapi.set_name(address, name, idaapi.SN_NOCHECK | idaapi.SN_NOWARN | idaapi.SN_LOCAL)

    @staticmethod
    def has_non_default_name(address: int, name: Optional[str]) -> bool:
        sym_name = idc.get_name(address, idaapi.GN_NOT_DUMMY)

        return False if sym_name == '' else (sym_name != name)

    def get_signatures(self) -> List[PsyqSig]:
        return self._signatures


class PsxExe:
    def __init__(self, exe_name: str, only_first: bool, min_entropy: float) -> None:
        self._exe_name = exe_name
        self._only_first = only_first
        self._min_entropy = min_entropy
        self._appliers = dict()

    def get_exe_name(self):
        return self._exe_name

    @classmethod
    def parse(cls, li):
        li.seek(0)

        header = li.read(0x800)

        if len(header) < 0x800:
            return None

        pos = 0
        ascii_id = struct.unpack_from('8s', header, pos)[0]

        if ascii_id != b'PS-X EXE':
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

        return \
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
        # '00 00 00 00 ? ? ? ? 00 00 00 00 4D 00 00 00'
        addr, _ = masked_search(rom_addr, rom_end,
                                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4D\x00\x00\x00',
                                b'\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF')

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
        idaapi.add_segm(0, 0x1F801080, 0x1F80108C, 'DMA_MDEC_IN', 'XTRN')
        idaapi.add_segm(0, 0x1F801090, 0x1F80109C, 'DMA_MDEC_OUT', 'XTRN')
        idaapi.add_segm(0, 0x1F8010A0, 0x1F8010AC, 'DMA_GPU', 'XTRN')
        idaapi.add_segm(0, 0x1F8010B0, 0x1F8010BC, 'DMA_CDROM', 'XTRN')
        idaapi.add_segm(0, 0x1F8010C0, 0x1F8010CC, 'DMA_SPU', 'XTRN')
        idaapi.add_segm(0, 0x1F8010D0, 0x1F8010DC, 'DMA_PIO', 'XTRN')
        idaapi.add_segm(0, 0x1F8010E0, 0x1F8010EC, 'DMA_OTC', 'XTRN')
        idaapi.add_segm(0, 0x1F8010F0, 0x1F8010F8, 'DMA_CTRL_INT', 'XTRN')

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

        for i in range(24):
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

    def apply_psyq_signatures_by_version(self, version: str, start_addr: int, end_addr: int) -> None:
        ida_psyq = idaapi.idadir(os.path.join('loaders', 'psyq'))
        patches_file = os.path.join(ida_psyq, 'patches.json')
        ver_dir = os.path.join(ida_psyq, version)

        files = list()
        for file in os.listdir(ver_dir):
            if file.endswith('.json'):
                files.append(file)

        for file in files:
            fname = os.path.basename(file)

            if fname in self._appliers:
                sig = self._appliers[fname]
            else:
                sig = SigApplier(self._exe_name, os.path.join(ver_dir, file), patches_file,
                                 self._only_first, self._min_entropy)
                self._appliers[fname] = sig

            sig.apply_signatures(start_addr, end_addr)


fname = idaapi.get_input_file_path()
psx_exe = PsxExe(os.path.basename(fname), ONLY_FIRST, MIN_ENTROPY)

li = open(fname, 'rb')
psx = psx_exe.parse(li)
li.close()

detect = DetectPsyQ(psx_exe.get_exe_name(), ONLY_FIRST, MIN_ENTROPY)
version = detect.get_psyq_version(psx['rom_addr'], psx['rom_addr'] + psx['rom_size'])
psx_exe.apply_psyq_signatures_by_version(version, psx['rom_addr'], psx['rom_addr'] + psx['rom_size'])

if psx['gp'] != 0:
    idc.process_config_line("MIPS_GP=0x%08X" % psx['gp'])
else:
    idaapi.warning('$GP from header is zero! Check \'start \' function for a $gp loading instruction.\n')
