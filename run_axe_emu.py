#!/usr/bin/env python3
import sys, struct
sys.path.insert(0, '/home/claude/work/tools')
from emu8086_fixed import CPU  # FIX: was `from emu8086 import CPU` -- the
                                # UNFIXED module (no DF-flag support). Every
                                # prior run through this harness executed
                                # without the direction-flag fix regardless
                                # of emu8086_fixed.py's existence.

def load_and_run(exe_path, max_steps=2_000_000, trace=False, trace_limit=200):
    data = open(exe_path, 'rb').read()
    assert data[0:2] == b'MZ'
    e_cblp   = data[2]  | (data[3]<<8)
    e_cp     = data[4]  | (data[5]<<8)
    e_cparhdr= data[8]  | (data[9]<<8)
    e_ss     = data[0x0E] | (data[0x0F]<<8)
    e_sp     = data[0x10] | (data[0x11]<<8)
    e_ip     = data[0x14] | (data[0x15]<<8)
    e_cs     = data[0x16] | (data[0x17]<<8)
    header_bytes = e_cparhdr * 16
    image_size = (e_cp-1)*512 + e_cblp if e_cp else len(data)-header_bytes
    load_module = data[header_bytes:header_bytes+image_size]

    cpu = CPU()
    cpu.host_files['*'] = exe_path
    LOAD_SEG = 0x1000
    for i, b in enumerate(load_module):
        cpu.mem[cpu.lin(LOAD_SEG, i)] = b

    cpu.segs['cs'] = LOAD_SEG + e_cs
    cpu.segs['ds'] = LOAD_SEG          # PSP-ish; program overwrites with push cs/pop ds anyway
    cpu.segs['es'] = LOAD_SEG - 0x10   # pretend PSP segment
    cpu.segs['ss'] = LOAD_SEG + e_ss
    cpu.regs['sp'] = e_sp
    cpu.ip = e_ip

    # Minimal but real PSP fields the stub actually reads (found by tracing
    # the emulator into a genuine bug: without this, PSP:0002 reads as 0,
    # the stub's own free-memory check underflows, and it takes an
    # "insufficient memory" branch that shouldn't trigger). PSP:0002 is the
    # real, standard DOS field: "first segment beyond the memory allocated
    # to this program". 0x9FFF simulates a generous ~640KB-class DOS
    # session, comfortably enough for a program this size.
    psp_seg = cpu.segs['es']
    cpu.ww(psp_seg, 0x02, 0x9FFF)
    cpu.wb(psp_seg, 0x00, 0xCD); cpu.wb(psp_seg, 0x01, 0x20)  # INT 20h, old-style exit vector

    # Any file this stub tries to open, hand it the real exe bytes -- the
    # exact PSP/argv[0] filename-recovery mechanism is a separate, already
    # well-understood concern; what's under test here is the decompression
    # logic once the file is open, not DOS filename plumbing.
    # (removed: dead AnyFile class + no-op int21 wrapper that reassigned
    # cpu.int21 to a function that only ever called the original unchanged --
    # pure no-op, no behavior lost by deleting it. Reintroduce a real patched_int21
    # here if/when filename interception actually needs to do something.)

    steps = 0
    errors = []
    from collections import Counter
    hot = Counter()
    progress_log = []
    while not cpu.halted and steps < max_steps:
        pc = (cpu.segs['cs'], cpu.ip)
        hot[pc] += 1
        try:
            if trace and steps < trace_limit:
                print(f"[{steps:6d}] CS:IP={cpu.segs['cs']:04x}:{cpu.ip:04x} "
                      f"AX={cpu.regs['ax']:04x} BX={cpu.regs['bx']:04x} CX={cpu.regs['cx']:04x} "
                      f"DX={cpu.regs['dx']:04x} SI={cpu.regs['si']:04x} DI={cpu.regs['di']:04x} "
                      f"DS={cpu.segs['ds']:04x} ES={cpu.segs['es']:04x}")
            cpu.step()
        except NotImplementedError as e:
            errors.append((steps, pc, str(e)))
            break
        except IndexError as e:
            errors.append((steps, pc, f"memory OOB: {e}"))
            break
        except ZeroDivisionError as e:
            errors.append((steps, pc, f"div by zero: {e}"))
            break
        steps += 1
        if steps % 200000 == 0:
            progress_log.append((steps, cpu.segs['cs'], cpu.ip, cpu.segs['es'], cpu.regs['di'], cpu.regs['si']))
    return cpu, steps, errors, LOAD_SEG, hot, progress_log

if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else "Circuit-s-Edge_DOS_EN_Floppy/circuits-edge/EDGE.EXE"
    steps_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 2_000_000
    cpu, steps, errors, load_seg, hot, progress = load_and_run(path, max_steps=steps_arg, trace=('-t' in sys.argv))
    print(f"ran {steps} steps, halted={cpu.halted}")
    if errors:
        print("STOPPED:", errors[-1])
    print("progress log (every 200k steps): CS:IP, ES:DI, SI")
    for p in progress:
        print(f"  step {p[0]:8d}: CS:IP={p[1]:04x}:{p[2]:04x}  ES:DI={p[3]:04x}:{p[4]:04x}  SI={p[5]:04x}")
    print("top 15 hottest instruction addresses:")
    for addr, cnt in hot.most_common(15):
        print(f"  {addr[0]:04x}:{addr[1]:04x} x{cnt}")
    # dump the output region (decompression writes starting at LOAD_SEG:0)
    out_start = cpu.lin(load_seg, 0)
    dump_len = 400000
    with open('/tmp/edge_decompressed.bin', 'wb') as f:
        f.write(cpu.mem[out_start:out_start+dump_len])
    print(f"wrote /tmp/edge_decompressed.bin ({dump_len} bytes from LOAD_SEG:0)")
    print("first 32 bytes:", cpu.mem[out_start:out_start+32].hex())
