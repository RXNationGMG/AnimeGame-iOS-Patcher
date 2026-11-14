#!/usr/bin/env python3
"""Static audit of the payload's absolute memory references and branches.

Every adrp/add/adr/ldr/str chain in the *code* part of payload.bin is resolved
to an absolute address and checked against the segment table and the bind
table of the real executable.  Branches are checked to land inside the
payload or on a known original IMP.  This is what catches typed-in addresses
that no simulator can catch on its own, because the simulator would be handed
the same wrong constant.

Rules:
  * every addressed byte must be inside a mapped, protected segment
  * every 8-byte load from __DATA/__DATA_CONST must be a known bind slot, or
    hold a pointer inside the image, and pointers into __TEXT must look like
    readable strings when used as class/selector names
  * every direct branch must stay inside the payload code or target a known
    original IMP
"""
import json
import re
import struct
import sys

import capstone

sys.path.insert(0, ".")
import inspect2 as I

CODE_BASE = 0x1000031C0
ORIG_IMPS = (0x10001774C,)               # startUnity: (only IMP used by v7)

RE_ADRP = re.compile(r"^(x\d+), #(0x[0-9a-f]+)$")
RE_ADR = re.compile(r"^(x\d+), #(0x[0-9a-f]+)$")
RE_SP = re.compile(r"^(x\d+), \[(x\d+)(?:, #(0x[0-9a-f]+))?\]$")
RE_ADDI = re.compile(r"^(x\d+), (x\d+), #(0x[0-9a-f]+)$")


def build_index(path="main_signed.bin"):
    m = I.M(path)
    # keep initprot so __PAGEZERO (0 .. 4 GiB, prot 0) is not treated as memory
    segs = [(s[0], s[1], s[2], s[3], s[4], s[6]) for s in m.segs]
    o = m.cmds[I.LC_DYLD_INFO_ONLY][0]
    _ro, _rs, bo, bs, _wo, _ws, _lo, _ls, _eo, _es = struct.unpack_from(
        "<IIIIIIIIII", m.d, o + 8)
    binds = set()
    for segi, soff, sym in I.walk_bind(m, bo, bs, False):
        binds.add((segs[segi][1] + soff, sym))
    return m, segs, binds


def seg_of(segs, addr):
    for name, va, vs, fo, fs, prot in segs:
        if not prot or name == "__PAGEZERO":
            continue
        if va <= addr < va + vs:
            return name, va, vs, fo, fs
    return None


def audit(blob, path="main_signed.bin", code_end=None, verbose=True):
    m, segs, binds = build_index(path)
    bindmap = dict(binds)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    regs = {}
    errors = []
    refs = []
    branches = []

    if code_end is None:
        code_end = CODE_BASE + len(blob)
    code_blob = blob[:code_end - CODE_BASE]

    def note(kind, addr, slot=None):
        seg = seg_of(segs, addr)
        if seg is None:
            errors.append("%s target %#x is NOT mapped" % (kind, addr))
            return
        refs.append((kind, addr, seg[0], slot))

    for ins in md.disasm(code_blob, CODE_BASE):
        op = ins.mnemonic
        s = ins.op_str
        if op == "adrp":
            mm = RE_ADRP.match(s)
            if mm:
                regs[mm.group(1)] = int(mm.group(2), 16)
            else:
                errors.append("unparsed adrp %r" % s)
            continue
        if op == "adr":
            mm = RE_ADR.match(s)
            if mm:
                target = int(mm.group(2), 16)
                if not (CODE_BASE <= target < CODE_BASE + len(blob)):
                    errors.append("adr %s -> %#x outside payload"
                                  % (mm.group(1), target))
                else:
                    refs.append(("adr", target, "__TEXT", None))
                regs.pop(mm.group(1), None)
            else:
                errors.append("unparsed adr %r" % s)
            continue
        if op == "add":
            mm = RE_ADDI.match(s)
            if mm:
                dst, src, imm = mm.group(1), mm.group(2), int(mm.group(3), 16)
                if src in regs:
                    regs[dst] = regs[src] + imm
                else:
                    regs.pop(dst, None)
            else:
                regs.pop(s.split(",")[0].strip(), None)
            continue
        if op in ("ldr", "str", "ldrb", "strb", "ldp", "stp"):
            mm = RE_SP.match(s)
            if mm:
                base = mm.group(2)
                off = int(mm.group(3), 16) if mm.group(3) else 0
                if base in regs:
                    addr = regs[base] + off
                    if base != "sp":
                        note(op, addr)
                        if op == "ldr" and "[" in s and "#" not in s.split(",")[-1]:
                            pass
                        if op == "ldr":
                            seg = seg_of(segs, addr)
                            if seg and seg[0] in ("__DATA", "__DATA_CONST"):
                                fo = seg[3] + (addr - seg[1])
                                if fo + 8 <= len(m.d):
                                    val = struct.unpack_from("<Q", m.d, fo)[0]
                                    if addr in bindmap or val == 0:
                                        pass
                                    elif seg_of(segs, val) is None:
                                        errors.append(
                                            "slot %#x holds %#x (outside image)"
                                            % (addr, val))
                                    else:
                                        name = seg_of(segs, val)[0]
                                        if name == "__TEXT":
                                            cs = m.cstr(val)
                                            if not cs or not cs.isprintable():
                                                errors.append(
                                                    "slot %#x -> %#x is not a "
                                                    "string" % (addr, val))
            else:
                dst = s.split(",")[0].strip()
                regs.pop(dst, None)
            continue
        if op in ("b", "bl") or op.startswith("b.") or op in ("cbz", "cbnz"):
            tok = s.split(",")[-1].strip()
            if tok.startswith("#0x"):
                branches.append((op, int(tok[1:], 16)))
            dst = s.split(",")[0].strip()
            if op.startswith("b.") or op in ("b", "bl"):
                pass
            else:
                regs.pop(dst, None)
            continue
        # any other instruction that writes the destination register
        dst = s.split(",")[0].strip()
        if dst.startswith(("x", "w")):
            regs.pop(dst, None)

    for op, target in branches:
        inside = CODE_BASE <= target < code_end
        if not inside and target not in ORIG_IMPS:
            errors.append("branch %s -> %#x leaves the payload" % (op, target))

    if verbose:
        print("resolved absolute references: %d" % len(refs))
        seen = set()
        for kind, addr, seg, _sl in refs:
            key = (kind, addr)
            if key in seen:
                continue
            seen.add(key)
            extra = ""
            if addr in bindmap:
                extra = "  [bind %s]" % bindmap[addr]
            print("  %-4s %#x  %s%s" % (kind, addr, seg, extra))
        print("branches: %d (all inside payload or original IMPs)"
              % len(branches))
        print("\nerrors: %d" % len(errors))
        for e in errors:
            print("  !! " + e)
    return errors


def load_meta(path="payload.json"):
    try:
        return json.load(open(path))
    except OSError:
        return {}


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "payload.bin"
    blob = open(src, "rb").read()
    meta = load_meta()
    errs = audit(blob, code_end=meta.get("code_end"))
    print("\nRESULT:", "OK" if not errs else "FAIL")
    sys.exit(0 if not errs else 1)
