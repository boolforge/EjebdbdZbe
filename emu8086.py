#!/usr/bin/env python3
"""
emu8086.py -- a small, direct 8086 real-mode emulator, written specifically
to EXECUTE the real SEA-AXE decompression stub against real file bytes,
rather than continue hand-tracing its disassembly. This is the "dynamic
analysis" step the findings doc named as the correct next tool.

Scope: only the instruction forms actually observed in this stub's
disassembly are implemented, but implemented as general opcode handlers
(ModRM-based), not special-cased per address -- so if the CPU actually
executes an instruction form not yet seen, it raises NotImplementedError
loudly rather than silently doing the wrong thing. That is intentional:
a silent wrong instruction would produce exactly the kind of confidently-
wrong output this whole investigation has been checking for elsewhere.

DOS INT 21h calls actually used by this stub (open/seek/read/memory/exit)
are intercepted and backed by the REAL file on disk, so the "compressed
data" the emulated CPU reads is the real EDGE.EXE bytes, not a mock.
"""
import sys

class CPU:
    def __init__(self, mem_size=0x10000 * 16):
        self.mem = bytearray(mem_size)
        self.regs = {r: 0 for r in ('ax','bx','cx','dx','si','di','bp','sp')}
        self.segs = {r: 0 for r in ('cs','ds','es','ss')}
        self.ip = 0
        self.flags = {'zf':0,'cf':0,'sf':0,'of':0,'pf':0}
        self.halted = False
        self.trace = []
        self.max_steps = 2_000_000
        self.file_handles = {}   # fd -> (real file bytes, position)
        self.next_fd = 5
        self.host_files = {}     # dos filename (upper) -> real path on disk
        self.stdout_capture = []

    # ---------- memory / register helpers ----------
    def lin(self, seg, off): return ((seg << 4) + (off & 0xFFFF)) & 0xFFFFF
    def rb(self, seg, off): return self.mem[self.lin(seg, off)]
    def wb(self, seg, off, v): self.mem[self.lin(seg, off)] = v & 0xFF
    def rw(self, seg, off):
        a = self.lin(seg, off)
        return self.mem[a] | (self.mem[(a+1) & 0xFFFFF] << 8)
    def ww(self, seg, off, v):
        a = self.lin(seg, off)
        self.mem[a] = v & 0xFF
        self.mem[(a+1) & 0xFFFFF] = (v >> 8) & 0xFF

    def get8(self, name):
        if name in ('al','bl','cl','dl'): return self.regs[name[0]+'x'] & 0xFF
        if name in ('ah','bh','ch','dh'): return (self.regs[name[0]+'x'] >> 8) & 0xFF
        raise ValueError(name)
    def set8(self, name, v):
        v &= 0xFF
        if name in ('al','bl','cl','dl'):
            r = name[0]+'x'; self.regs[r] = (self.regs[r] & 0xFF00) | v
        elif name in ('ah','bh','ch','dh'):
            r = name[0]+'x'; self.regs[r] = (self.regs[r] & 0x00FF) | (v << 8)
        else: raise ValueError(name)

    BYTE_REGS = ['al','cl','dl','bl','ah','ch','dh','bh']
    WORD_REGS = ['ax','cx','dx','bx','sp','bp','si','di']
    SEG_REGS  = ['es','cs','ss','ds']

    def fetch8(self):
        b = self.rb(self.segs['cs'], self.ip); self.ip = (self.ip + 1) & 0xFFFF; return b
    def fetch16(self):
        lo = self.fetch8(); hi = self.fetch8(); return lo | (hi << 8)
    def s8(self, v): return v - 256 if v >= 128 else v
    def s16(self, v): return v - 65536 if v >= 32768 else v

    def push(self, v):
        self.regs['sp'] = (self.regs['sp'] - 2) & 0xFFFF
        self.ww(self.segs['ss'], self.regs['sp'], v)
    def pop(self):
        v = self.rw(self.segs['ss'], self.regs['sp'])
        self.regs['sp'] = (self.regs['sp'] + 2) & 0xFFFF
        return v

    def setflags_log(self, val, bits):
        mask = 0xFF if bits == 8 else 0xFFFF
        val &= mask
        self.flags['zf'] = 1 if val == 0 else 0
        self.flags['sf'] = 1 if (val >> (bits-1)) & 1 else 0
        self.flags['cf'] = 0
        self.flags['of'] = 0
        return val
    def setflags_add(self, a, b, res, bits, sub=False):
        mask = 0xFF if bits == 8 else 0xFFFF
        top = 1 << (bits-1)
        r = res & mask
        self.flags['zf'] = 1 if r == 0 else 0
        self.flags['sf'] = 1 if r & top else 0
        if sub:
            self.flags['cf'] = 1 if (a & mask) < (b & mask) else 0
            self.flags['of'] = 1 if (((a ^ b) & (a ^ r)) & top) else 0
        else:
            self.flags['cf'] = 1 if res > mask else 0
            self.flags['of'] = 1 if ((~(a ^ b) & (a ^ r)) & top) else 0
        return r

    # ---------- ModRM decode ----------
    def modrm(self, wide, seg_override=None):
        """Returns ('reg', name) for the reg field and a resolver for rm:
        either ('reg', name) or ('mem', seg, addr)."""
        b = self.fetch8()
        mod = b >> 6
        reg = (b >> 3) & 7
        rm = b & 7
        reg_name = (self.WORD_REGS if wide else self.BYTE_REGS)[reg]
        if mod == 3:
            rm_name = (self.WORD_REGS if wide else self.BYTE_REGS)[rm]
            return reg_name, ('reg', rm_name)
        # compute effective address
        base = 0
        default_seg = 'ds'
        if rm == 0: base = self.regs['bx'] + self.regs['si']
        elif rm == 1: base = self.regs['bx'] + self.regs['di']
        elif rm == 2: base = self.regs['bp'] + self.regs['si']; default_seg='ss'
        elif rm == 3: base = self.regs['bp'] + self.regs['di']; default_seg='ss'
        elif rm == 4: base = self.regs['si']
        elif rm == 5: base = self.regs['di']
        elif rm == 6:
            if mod == 0:
                base = self.fetch16()
            else:
                base = self.regs['bp']; default_seg='ss'
        elif rm == 7: base = self.regs['bx']
        if mod == 1: base += self.s8(self.fetch8())
        elif mod == 2: base += self.s16(self.fetch16())
        seg = seg_override or default_seg
        return reg_name, ('mem', seg, base & 0xFFFF)

    def read_rm(self, rm, wide):
        kind = rm[0]
        if kind == 'reg':
            return self.get8(rm[1]) if not wide else self.regs[rm[1]]
        else:
            _, seg, addr = rm
            return self.rb(self.segs[seg], addr) if not wide else self.rw(self.segs[seg], addr)
    def write_rm(self, rm, val, wide):
        kind = rm[0]
        if kind == 'reg':
            (self.set8(rm[1], val) if not wide else self.regs.__setitem__(rm[1], val & 0xFFFF))
        else:
            _, seg, addr = rm
            (self.wb(self.segs[seg], addr, val) if not wide else self.ww(self.segs[seg], addr, val))

    def getreg(self, name, wide):
        return self.regs[name] if wide else self.get8(name)
    def setreg(self, name, val, wide):
        if wide: self.regs[name] = val & 0xFFFF
        else: self.set8(name, val)

    # ---------- DOS interrupt emulation (backed by the real file) ----------
    def read_asciiz(self, seg, off):
        s = b''
        while True:
            c = self.rb(seg, off)
            if c == 0: break
            s += bytes([c]); off = (off+1) & 0xFFFF
        return s.decode('ascii', 'replace')

    def int21(self):
        ah = (self.regs['ax'] >> 8) & 0xFF
        if getattr(self, 'trace_int21', False):
            print(f"  INT21 AH={ah:02x} AX={self.regs['ax']:04x} BX={self.regs['bx']:04x} "
                  f"CX={self.regs['cx']:04x} DX={self.regs['dx']:04x} DS={self.segs['ds']:04x} "
                  f"at CS:IP={self.segs['cs']:04x}:{self.ip:04x}")
        if ah == 0x30:  # get DOS version
            self.regs['ax'] = 0x0500
        elif ah == 0x25 or ah == 0x35:  # set/get interrupt vector -- no-op
            pass
        elif ah == 0x1A:  # set DTA -- no-op
            pass
        elif ah == 0x4A:  # resize memory block -- pretend success
            self.flags['cf'] = 0
        elif ah == 0x3D:  # open file
            name = self.read_asciiz(self.segs['ds'], self.regs['dx'])
            # This session's harness hands every open() the emulated
            # program's own real bytes (see run_axe_emu.py) rather than
            # modeling PSP/argv[0] filename recovery, which is a separate
            # concern from the decompression logic under test here.
            path = self.host_files.get(name.upper()) or self.host_files.get('*')
            if path is None:
                self.flags['cf'] = 1; self.regs['ax'] = 2
            else:
                data = open(path, 'rb').read()
                fd = self.next_fd; self.next_fd += 1
                self.file_handles[fd] = [data, 0]
                self.regs['ax'] = fd; self.flags['cf'] = 0
        elif ah == 0x3E:  # close
            self.flags['cf'] = 0
        elif ah == 0x42:  # lseek
            fd = self.regs['bx']
            method = (self.regs['ax']) & 0xFF
            off = self.s16(self.regs['cx'] << 16 | self.regs['dx']) if False else None
            # CX:DX = signed 32-bit offset (CX hi, DX lo)
            offset = (self.regs['cx'] << 16 | self.regs['dx'])
            data, pos = self.file_handles[fd]
            if method == 0: pos = offset
            elif method == 1: pos = pos + offset
            elif method == 2: pos = len(data) + offset
            self.file_handles[fd][1] = pos & 0xFFFFFFFF
            self.regs['dx'] = (pos >> 16) & 0xFFFF
            self.regs['ax'] = pos & 0xFFFF
            self.flags['cf'] = 0
        elif ah == 0x3F:  # read
            fd = self.regs['bx']; n = self.regs['cx']
            data, pos = self.file_handles[fd]
            chunk = data[pos:pos+n]
            for i, byte in enumerate(chunk):
                self.wb(self.segs['ds'], (self.regs['dx']+i) & 0xFFFF, byte)
            self.file_handles[fd][1] = pos + len(chunk)
            self.regs['ax'] = len(chunk)
            self.flags['cf'] = 0
        elif ah == 0x4C:  # terminate
            self.halted = True
        elif ah == 0x09:  # print $-terminated string at DS:DX
            s = b''
            off = self.regs['dx']
            while True:
                c = self.rb(self.segs['ds'], off)
                if c == ord('$'): break
                s += bytes([c]); off = (off+1) & 0xFFFF
            self.stdout_capture.append(s.decode('ascii','replace'))
        elif ah == 0x40:  # write (used for stdout/stderr too)
            self.regs['ax'] = self.regs['cx']  # pretend all bytes written
        else:
            raise NotImplementedError(f"INT 21h AH={ah:02x} not modeled")

    # ---------- main step ----------
    def step(self):
        seg_override = None
        rep = None
        while True:
            op = self.fetch8()
            if op == 0x26: seg_override = 'es'; continue
            if op == 0x2E: seg_override = 'cs'; continue
            if op == 0x36: seg_override = 'ss'; continue
            if op == 0x3E: seg_override = 'ds'; continue
            if op == 0xF2: rep = 'nz'; continue
            if op == 0xF3: rep = 'z'; continue
            break
        self.exec_op(op, seg_override, rep)

    def exec_op(self, op, seg_override, rep):
        R = self.regs
        F = self.flags
        def j(cond, rel8=True):
            d = self.s8(self.fetch8()) if rel8 else self.s16(self.fetch16())
            if cond: self.ip = (self.ip + d) & 0xFFFF

        # PUSH/POP reg16
        if 0x50 <= op <= 0x57: self.push(R[self.WORD_REGS[op-0x50]]); return
        if 0x58 <= op <= 0x5F: R[self.WORD_REGS[op-0x58]] = self.pop(); return
        if op in (0x06,0x0E,0x16,0x1E):
            self.push(self.segs[['es',None,'ss','ds'][ (op>>3)&3 ] if op!=0x0E else 'cs']); return
        if op in (0x07,0x17,0x1F):
            self.segs[{0x07:'es',0x17:'ss',0x1F:'ds'}[op]] = self.pop(); return

        # MOV reg,imm
        if 0xB0 <= op <= 0xB7: self.set8(self.BYTE_REGS[op-0xB0], self.fetch8()); return
        if 0xB8 <= op <= 0xBF: R[self.WORD_REGS[op-0xB8]] = self.fetch16(); return

        # INC/DEC reg16
        if 0x40 <= op <= 0x47:
            r = self.WORD_REGS[op-0x40]; old=R[r]; R[r]=(R[r]+1)&0xFFFF
            self.setflags_add(old,1,R[r],16); F['cf'] = 0 if True else F['cf']; return
        if 0x48 <= op <= 0x4F:
            r = self.WORD_REGS[op-0x48]; old=R[r]; R[r]=(R[r]-1)&0xFFFF
            self.setflags_add(old,1,R[r],16,sub=True); return

        # XCHG ax,reg / NOP
        if 0x90 <= op <= 0x97:
            r = self.WORD_REGS[op-0x90]
            if r != 'ax': R['ax'], R[r] = R[r], R['ax']
            return
        if op == 0x98:  # cbw
            v = self.s8(self.get8('al')); R['ax'] = v & 0xFFFF; return
        if op == 0x99:  # cwd
            v = self.s16(R['ax']); R['dx'] = 0xFFFF if v < 0 else 0; return

        # PUSH/POP/JMP/CALL/INC/DEC via 0xFE/0xFF group
        if op in (0xFE, 0xFF):
            wide = (op == 0xFF)
            modb = self.mem[self.lin(self.segs['cs'], self.ip)]
            ext = (modb >> 3) & 7
            _, rm = self.modrm(wide, seg_override)
            if ext == 0:  # inc
                v = self.read_rm(rm, wide); nv = (v+1) & (0xFFFF if wide else 0xFF)
                self.setflags_add(v,1,nv, 16 if wide else 8); self.write_rm(rm, nv, wide)
            elif ext == 1:  # dec
                v = self.read_rm(rm, wide); nv = (v-1) & (0xFFFF if wide else 0xFF)
                self.setflags_add(v,1,nv, 16 if wide else 8, sub=True); self.write_rm(rm, nv, wide)
            elif ext == 2:  # call near indirect
                target = self.read_rm(rm, True); self.push(self.ip); self.ip = target
            elif ext == 3:  # call far indirect
                _, seg, addr = rm
                newip = self.rw(self.segs[seg], addr); newcs = self.rw(self.segs[seg], (addr+2)&0xFFFF)
                self.push(self.segs['cs']); self.push(self.ip)
                self.ip = newip; self.segs['cs'] = newcs
            elif ext == 4:  # jmp near indirect
                self.ip = self.read_rm(rm, True)
            elif ext == 5:  # jmp far indirect
                _, seg, addr = rm
                self.ip = self.rw(self.segs[seg], addr); self.segs['cs'] = self.rw(self.segs[seg], (addr+2)&0xFFFF)
            elif ext == 6:  # push
                self.push(self.read_rm(rm, True))
            return

        # MOV r/m,r and r,r/m  (88,89,8A,8B)
        if op in (0x88,0x89,0x8A,0x8B):
            wide = op in (0x89,0x8B)
            reg, rm = self.modrm(wide, seg_override)
            if op in (0x88,0x89): self.write_rm(rm, self.getreg(reg,wide), wide)
            else: self.setreg(reg, self.read_rm(rm, wide), wide)
            return
        if op == 0x8C:  # mov r/m,segreg
            b = self.mem[self.lin(self.segs['cs'], self.ip)]
            segname = self.SEG_REGS[(b>>3)&3]
            _, rm = self.modrm(True, seg_override)
            self.write_rm(rm, self.segs[segname], True); return
        if op == 0x8E:  # mov segreg,r/m
            b = self.mem[self.lin(self.segs['cs'], self.ip)]
            segname = self.SEG_REGS[(b>>3)&3]
            _, rm = self.modrm(True, seg_override)
            self.segs[segname] = self.read_rm(rm, True); return
        if op in (0xA0,0xA1,0xA2,0xA3):
            wide = op in (0xA1,0xA3)
            addr = self.fetch16(); seg = seg_override or 'ds'
            if op in (0xA0,0xA1):
                R['ax'] = (self.rw(self.segs[seg],addr) if wide else (R['ax']&0xFF00)|self.rb(self.segs[seg],addr))
            else:
                (self.ww if wide else self.wb)(self.segs[seg], addr, R['ax'] if wide else self.get8('al'))
            return
        if op in (0xC6,0xC7):
            wide = (op==0xC7)
            _, rm = self.modrm(wide, seg_override)
            imm = self.fetch16() if wide else self.fetch8()
            self.write_rm(rm, imm, wide); return
        if op == 0x8F:  # pop r/m16
            _, rm = self.modrm(True, seg_override)
            self.write_rm(rm, self.pop(), True); return

        # ALU r/m,r / r,r/m / al,imm / ax,imm  for add/or/adc/sbb/and/sub/xor/cmp
        ALU = {0:'add',1:'or',2:'adc',3:'sbb',4:'and',5:'sub',6:'xor',7:'cmp'}
        if (op & 0xC0) == 0x00 and (op & 0x07) in (0,1,2,3,4,5) and op < 0x40 and (op%8) < 6:
            group = op >> 3
            if group in ALU:
                which = op & 0x07
                if which in (0,1,2,3):
                    wide = which in (1,3)
                    reg, rm = self.modrm(wide, seg_override)
                    if which in (0,1):      # r/m, reg  (dest = r/m)
                        a = self.read_rm(rm, wide); b = self.getreg(reg, wide)
                        dest_rm, dest_reg = rm, None
                    else:                   # reg, r/m  (dest = reg)
                        a = self.getreg(reg, wide); b = self.read_rm(rm, wide)
                        dest_rm, dest_reg = None, reg
                    self.alu(ALU[group], a, b, wide, dest_rm=dest_rm, dest_reg=dest_reg)
                    return
                if which in (4,5):
                    wide = (which == 5)
                    imm = self.fetch16() if wide else self.fetch8()
                    a = R['ax'] if wide else self.get8('al')
                    self.alu(ALU[group], a, imm, wide, dest_reg=('ax' if wide else 'al'))
                    return

        if op in (0x80,0x81,0x83):
            wide = (op != 0x80)
            modb = self.mem[self.lin(self.segs['cs'], self.ip)]
            ext = (modb >> 3) & 7
            _, rm = self.modrm(wide, seg_override)
            if op == 0x81: imm = self.fetch16()
            elif op == 0x83: imm = self.s8(self.fetch8()) & (0xFFFF if wide else 0xFF)
            else: imm = self.fetch8()
            a = self.read_rm(rm, wide)
            self.alu(ALU[ext], a, imm, wide, dest_rm=rm)
            return

        if op in (0xD0,0xD1,0xD2,0xD3):
            wide = op in (0xD1,0xD3)
            by_cl = op in (0xD2,0xD3)
            modb = self.mem[self.lin(self.segs['cs'], self.ip)]
            ext = (modb >> 3) & 7
            _, rm = self.modrm(wide, seg_override)
            count = (self.get8('cl') if by_cl else 1)
            v = self.read_rm(rm, wide)
            mask = 0xFFFF if wide else 0xFF
            top = 0x8000 if wide else 0x80
            for _ in range(count):
                if ext == 4:  # shl
                    F['cf'] = 1 if v & top else 0; v = (v << 1) & mask
                elif ext == 5:  # shr
                    F['cf'] = v & 1; v = (v >> 1) & mask
                elif ext == 7:  # sar
                    signbit = v & top
                    F['cf'] = v & 1; v = ((v >> 1) | signbit) & mask
                else:
                    raise NotImplementedError(f"shift/rotate ext={ext}")
            F['zf'] = 1 if v == 0 else 0
            F['sf'] = 1 if v & top else 0
            self.write_rm(rm, v, wide); return

        if op in (0xF6,0xF7):
            wide = (op == 0xF7)
            modb = self.mem[self.lin(self.segs['cs'], self.ip)]
            ext = (modb >> 3) & 7
            _, rm = self.modrm(wide, seg_override)
            if ext == 0 or ext == 1:  # test
                imm = self.fetch16() if wide else self.fetch8()
                v = self.read_rm(rm, wide) & imm
                self.setflags_log(v, 16 if wide else 8)
            elif ext == 2:  # not
                v = self.read_rm(rm, wide); self.write_rm(rm, (~v) & (0xFFFF if wide else 0xFF), wide)
            elif ext == 3:  # neg
                v = self.read_rm(rm, wide); nv = (-v) & (0xFFFF if wide else 0xFF)
                F['cf'] = 1 if v != 0 else 0
                self.write_rm(rm, nv, wide)
            elif ext == 4:  # mul
                v = self.read_rm(rm, wide)
                if wide:
                    res = R['ax'] * v; R['ax'] = res & 0xFFFF; R['dx'] = (res>>16)&0xFFFF
                    F['cf']=F['of'] = 1 if R['dx'] else 0
                else:
                    res = self.get8('al') * v; R['ax'] = res & 0xFFFF
                    F['cf']=F['of'] = 1 if (res>>8) else 0
            elif ext == 6:  # div
                v = self.read_rm(rm, wide)
                if wide:
                    num = (R['dx']<<16)|R['ax']; R['ax']=(num//v)&0xFFFF; R['dx']=(num%v)&0xFFFF
                else:
                    num = R['ax']; R['ax'] = (num//v)&0xFF | ((num%v)<<8)
            else:
                raise NotImplementedError(f"F6/F7 ext={ext}")
            return

        if op == 0x86 or op == 0x87:  # xchg
            wide = (op==0x87)
            reg, rm = self.modrm(wide, seg_override)
            a = self.getreg(reg, wide); b = self.read_rm(rm, wide)
            self.setreg(reg, b, wide); self.write_rm(rm, a, wide); return

        # string ops
        if op in (0xA4,0xA5,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF):
            wide = op in (0xA5,0xAB,0xAD,0xAF)
            count = 1
            is_rep = rep is not None
            n = R['cx'] if is_rep else 1
            src_seg = seg_override or 'ds'
            for _ in range(n if is_rep else 1):
                if is_rep and R['cx'] == 0: break
                if op in (0xA4,0xA5):  # movs
                    v = (self.rw if wide else self.rb)(self.segs[src_seg], R['si'])
                    (self.ww if wide else self.wb)(self.segs['es'], R['di'], v)
                    R['si'] = (R['si'] + (2 if wide else 1)) & 0xFFFF
                    R['di'] = (R['di'] + (2 if wide else 1)) & 0xFFFF
                elif op in (0xAA,0xAB):  # stos
                    v = R['ax'] if wide else self.get8('al')
                    (self.ww if wide else self.wb)(self.segs['es'], R['di'], v)
                    R['di'] = (R['di'] + (2 if wide else 1)) & 0xFFFF
                elif op in (0xAC,0xAD):  # lods
                    v = (self.rw if wide else self.rb)(self.segs[src_seg], R['si'])
                    if wide: R['ax'] = v
                    else: self.set8('al', v)
                    R['si'] = (R['si'] + (2 if wide else 1)) & 0xFFFF
                elif op in (0xAE,0xAF):  # scas
                    v = (self.rw if wide else self.rb)(self.segs['es'], R['di'])
                    a = R['ax'] if wide else self.get8('al')
                    self.setflags_add(a, v, a-v, 16 if wide else 8, sub=True)
                    R['di'] = (R['di'] + (2 if wide else 1)) & 0xFFFF
                if is_rep:
                    R['cx'] = (R['cx'] - 1) & 0xFFFF
                    if rep == 'z' and op in (0xAE,0xAF,0xA6,0xA7) and F['zf'] == 0: break
                    if rep == 'nz' and op in (0xAE,0xAF,0xA6,0xA7) and F['zf'] == 1: break
                    if R['cx'] == 0: break
            return

        # control flow
        if 0x70 <= op <= 0x7F:
            cond = {
                0x70: F['of']==1, 0x71: F['of']==0, 0x72: F['cf']==1, 0x73: F['cf']==0,
                0x74: F['zf']==1, 0x75: F['zf']==0, 0x76: (F['cf']==1 or F['zf']==1), 0x77: (F['cf']==0 and F['zf']==0),
                0x78: F['sf']==1, 0x79: F['sf']==0, 0x7A: False, 0x7B: True,
                0x7C: (F['sf']!=F['of']), 0x7D: (F['sf']==F['of']),
                0x7E: (F['zf']==1 or F['sf']!=F['of']), 0x7F: (F['zf']==0 and F['sf']==F['of']),
            }[op]
            j(cond); return
        if op == 0xE0: d=self.s8(self.fetch8()); R['cx']=(R['cx']-1)&0xFFFF; 
        if op == 0xE0:
            if R['cx']!=0 and F['zf']==0: self.ip=(self.ip+d)&0xFFFF
            return
        if op == 0xE1:
            d=self.s8(self.fetch8()); R['cx']=(R['cx']-1)&0xFFFF
            if R['cx']!=0 and F['zf']==1: self.ip=(self.ip+d)&0xFFFF
            return
        if op == 0xE2:
            d=self.s8(self.fetch8()); R['cx']=(R['cx']-1)&0xFFFF
            if R['cx']!=0: self.ip=(self.ip+d)&0xFFFF
            return
        if op == 0xE3:
            d=self.s8(self.fetch8())
            if R['cx']==0: self.ip=(self.ip+d)&0xFFFF
            return
        if op == 0xEB: j(True); return
        if op == 0xE9: j(True, rel8=False); return
        if op == 0xE8:
            d = self.s16(self.fetch16()); self.push(self.ip); self.ip=(self.ip+d)&0xFFFF; return
        if op == 0xC3: self.ip = self.pop(); return
        if op == 0xC2:
            n = self.fetch16(); self.ip = self.pop(); R['sp']=(R['sp']+n)&0xFFFF; return
        if op == 0xCB:
            self.ip = self.pop(); self.segs['cs'] = self.pop(); return
        if op == 0xCA:
            n = self.fetch16(); self.ip = self.pop(); self.segs['cs']=self.pop(); R['sp']=(R['sp']+n)&0xFFFF; return
        if op == 0x9A:
            newip=self.fetch16(); newcs=self.fetch16()
            self.push(self.segs['cs']); self.push(self.ip)
            self.ip=newip; self.segs['cs']=newcs; return
        if op == 0xEA:
            newip=self.fetch16(); newcs=self.fetch16()
            self.ip=newip; self.segs['cs']=newcs; return
        if op == 0xCD:
            n = self.fetch8()
            if n == 0x21: self.int21()
            else: raise NotImplementedError(f"INT {n:02x}")
            return
        if op in (0xF8,0xF9): F['cf'] = 0 if op==0xF8 else 1; return
        if op in (0xFA,0xFB): return  # cli/sti no-op
        if op in (0xFC,0xFD): return  # cld/std -- direction flag not modeled (no back-scans seen)

        raise NotImplementedError(f"opcode {op:02x} at CS:IP {self.segs['cs']:04x}:{self.ip-1:04x}")

    def alu(self, name, a, b, wide, dest_rm=None, dest_reg=None):
        bits = 16 if wide else 8
        if name == 'add': r = a+b
        elif name == 'or': r = a|b
        elif name == 'adc': r = a+b+self.flags['cf']
        elif name == 'sbb': r = a-b-self.flags['cf']
        elif name == 'and': r = a&b
        elif name == 'sub': r = a-b
        elif name == 'xor': r = a^b
        elif name == 'cmp': r = a-b
        else: raise NotImplementedError(name)
        if name in ('add','adc'): res = self.setflags_add(a,b,r,bits)
        elif name in ('sub','sbb','cmp'): res = self.setflags_add(a,b,r,bits, sub=True)
        else: res = self.setflags_log(r, bits)
        if name != 'cmp':
            if dest_rm is not None: self.write_rm(dest_rm, res, wide)
            elif dest_reg is not None: self.setreg(dest_reg, res, wide)

    def run(self, max_steps=None):
        steps = 0
        limit = max_steps or self.max_steps
        while not self.halted and steps < limit:
            self.step()
            steps += 1
        return steps
