#!/usr/bin/env python3
"""gipatch - version independent RSA-key patcher for Genshin Impact (iOS).

The game builds its RSA key strings as XML text with movz/movk immediates and
stores them into a stack/heap buffer, seven times (one per protocol path).  No
copy of the key exists in the file, so the only way to change it is to change
what the code writes.

Everything that used to be a hard-coded offset is discovered here:

  * `find_key_builds`      - scans the whole binary for immediate runs that
                             assemble into "<RSAKeyValue>...</RSAKeyValue>"
  * `text_free_runs`       - zero padding in __TEXT (outside every section)
  * `writable_zero_gap`    - unused zero-filled tail of a writable segment
  * `ObjC.method`          - ObjC2 metadata walk to `startUnity:` / `showGameUI`
  * `MachO.binds`          - dyld bind opcodes -> GOT slots for the runtime
  * `selrefs`              - __objc_selrefs -> selector slot addresses

Two patch shapes are provided:

  patch_standalone(main, key)      rewrite the key immediates in place
                                   (no extra code, no runtime switch)
  patch_toggle(main, key, report)  replace every key build with a stub that
                                   copies from a runtime-selected blob, add the
                                   pre-game panel, hook startUnity:
"""
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

try:
    import numpy as np
except ImportError:                                     # pragma: no cover
    raise SystemExit("gipatch needs numpy:  python -m pip install numpy")

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
M64 = (1 << 64) - 1

# Canonical Grasscutter / YuukiPS public key (ps.yuuki.me).  This is the key the
# device-confirmed 7.1 build uses.  Other servers: pass --key-file.
GRASSCUTTER_KEY = (
    "<RSAKeyValue><Modulus>xbbx2m1feHyrQ7jP+8mtDF/pyYLrJWKWAdEv3wZrOtjOZzeLGPzsmk"
    "cgncgoRhX4dT+1itSMR9j9m0/OwsH2UoF6U32LxCOQWQD1AMgIZjAkJeJvFTrtn8fMQ1701Ckb"
    "aLTVIjRMlTw8kNXvNA/A9UatoiDmi4TFG6mrxTKZpIcTInvPEpkK2A7Qsp1E4skFK8jmysy7uRh"
    "MaYHtPTsBvxP0zn3lhKB3W+HTqpneewXWHjCDfL7Nbby91jbz5EKPZXWLuhXIvR1Cu4tiruorwXJ"
    "xmXaP1HQZonytECNU/UOzP6GNLdq0eFDE4b04Wjp396551G99YiFP2nqHVJ5OMQ==</Modulus><Exp"
    "onent>AQAB</Exponent></RSAKeyValue>")


class PatchError(SystemExit):
    """A detectable, explainable refusal to patch."""


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

SG_READ_ONLY_AFTER_FIXUPS = 0x8
S_ZEROFILL = 0x1
S_GB_ZEROFILL = 0xC


class Section:
    __slots__ = ("segname", "sectname", "addr", "size", "offset", "align", "flags")

    def __init__(self, segname, sectname, addr, size, offset, align, flags):
        self.segname = segname
        self.sectname = sectname
        self.addr = addr
        self.size = size
        self.offset = offset
        self.align = align
        self.flags = flags

    @property
    def end(self):
        return self.addr + self.size

    @property
    def type(self):
        return self.flags & 0xFF

    @property
    def zerofill(self):
        return self.type in (S_ZEROFILL, S_GB_ZEROFILL)

    def contains(self, vm):
        return self.addr <= vm < self.addr + self.size

    def __repr__(self):
        return "<%s,%s %#x+%#x>" % (self.segname, self.sectname, self.addr, self.size)


class Segment:
    __slots__ = ("name", "vmaddr", "vmsize", "fileoff", "filesize", "maxprot",
                 "initprot", "flags", "sections")

    def __init__(self, name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot,
                 flags):
        self.name = name
        self.vmaddr = vmaddr
        self.vmsize = vmsize
        self.fileoff = fileoff
        self.filesize = filesize
        self.maxprot = maxprot
        self.initprot = initprot
        self.flags = flags
        self.sections = []

    @property
    def vmend(self):
        return self.vmaddr + self.vmsize

    @property
    def fileend_vm(self):
        return self.vmaddr + self.filesize

    def __repr__(self):
        return "<%s vm %#x+%#x file %#x+%#x>" % (
            self.name, self.vmaddr, self.vmsize, self.fileoff, self.filesize)


class MachO:
    def __init__(self, data):
        self.d = bytes(data)
        d = self.d
        (magic, self.cputype, self.cpusubtype, self.filetype, self.ncmds,
         self.sizeofcmds, self.flags) = struct.unpack_from("<IiiIIII", d, 0)
        if magic != 0xFEEDFACF:
            raise PatchError("not a thin 64-bit little-endian Mach-O (magic %#x)" % magic)
        self.cmds = {}
        self.segments = []
        self.sections = []
        off = 32
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from("<II", d, off)
            self.cmds.setdefault(cmd, []).append(off)
            if cmd == LC_SEGMENT_64:
                self._parse_segment(off)
            off += cmdsize
        self.symtab = None
        if LC_SYMTAB in self.cmds:
            o = self.cmds[LC_SYMTAB][0]
            self.symtab = struct.unpack_from("<IIII", d, o + 8)
        if LC_DYLD_CHAINED_FIXUPS in self.cmds:
            raise PatchError(
                "this binary uses chained fixups; gipatch only implements the "
                "classic dyld-info bind format (all 7.x builds use it)")

    # -- parsing ------------------------------------------------------------
    def encryption_cryptid(self):
        """Non-zero when the binary is still FairPlay encrypted."""
        for cmd in (LC_ENCRYPTION_INFO_64, LC_ENCRYPTION_INFO):
            for off in self.cmds.get(cmd, []):
                return struct.unpack_from("<I", self.d, off + 16)[0]
        return 0

    def _parse_segment(self, off):
        d = self.d
        name = d[off + 8:off + 24].rstrip(b"\x00").decode(errors="replace")
        vm, vs, fo, fs = struct.unpack_from("<QQQQ", d, off + 24)
        maxprot, initprot, nsects, flags = struct.unpack_from("<iiII", d, off + 56)
        seg = Segment(name, vm, vs, fo, fs, maxprot, initprot, flags)
        so = off + 72
        for _ in range(nsects):
            sname = d[so:so + 16].rstrip(b"\x00").decode(errors="replace")
            segname = d[so + 16:so + 32].rstrip(b"\x00").decode(errors="replace")
            addr, size, offset, align = struct.unpack_from("<QQII", d, so + 32)
            sflags = struct.unpack_from("<I", d, so + 64)[0]
            sec = Section(segname or name, sname, addr, size, offset, align, sflags)
            seg.sections.append(sec)
            self.sections.append(sec)
            so += 80
        self.segments.append(seg)

    # -- lookups ------------------------------------------------------------
    def segment(self, name):
        for s in self.segments:
            if s.name == name:
                return s
        raise PatchError("segment %s not found" % name)

    def section(self, sect, seg=None):
        for s in self.sections:
            if s.sectname == sect and (seg is None or s.segname == seg):
                return s
        return None

    def section_or_fail(self, sect, seg=None):
        s = self.section(sect, seg)
        if s is None:
            raise PatchError("section %s%s not found"
                             % (("%s," % seg) if seg else "", sect))
        return s

    def v2o(self, vm):
        for seg in self.segments:
            if seg.vmaddr <= vm < seg.fileend_vm:
                return seg.fileoff + (vm - seg.vmaddr)
        return None

    def o2v(self, off):
        for seg in self.segments:
            if seg.fileoff <= off < seg.fileoff + seg.filesize:
                return seg.vmaddr + (off - seg.fileoff)
        return None

    def read(self, vm, n):
        o = self.v2o(vm)
        if o is None:
            raise PatchError("vm %#x is not file backed" % vm)
        return self.d[o:o + n]

    def u32(self, vm):
        return struct.unpack("<I", self.read(vm, 4))[0]

    def u64(self, vm):
        return struct.unpack("<Q", self.read(vm, 8))[0]

    def cstr(self, vm, limit=512):
        o = self.v2o(vm)
        if o is None:
            return None
        e = self.d.find(b"\x00", o, o + limit)
        if e < 0:
            return None
        return self.d[o:e].decode(errors="replace")

    def section_of(self, vm):
        for s in self.sections:
            if s.contains(vm):
                return s
        return None

    # -- dyld ---------------------------------------------------------------
    def _dyld_info(self):
        if LC_DYLD_INFO_ONLY not in self.cmds:
            raise PatchError("no LC_DYLD_INFO_ONLY")
        o = self.cmds[LC_DYLD_INFO_ONLY][0]
        return struct.unpack_from("<IIIIIIIIII", self.d, o + 8)

    def rebase_vms(self):
        rebase_off, rebase_size = self._dyld_info()[:2]
        d = self.d
        p, end = rebase_off, rebase_off + rebase_size
        segi = seg_off = 0
        out = []

        def uleb():
            nonlocal p
            r = sh = 0
            while True:
                b = d[p]
                p += 1
                r |= (b & 0x7F) << sh
                sh += 7
                if not b & 0x80:
                    return r

        while p < end:
            b = d[p]
            p += 1
            op, imm = b & 0xF0, b & 0x0F
            if op == 0x00:
                break
            elif op == 0x10:
                segi = imm
            elif op == 0x20:
                segi, seg_off = imm, uleb()
            elif op == 0x30:
                seg_off += uleb()
            elif op == 0x40:
                seg_off += imm * 8
            elif op == 0x50:
                for _ in range(imm):
                    out.append(self.segments[segi].vmaddr + seg_off)
                    seg_off += 8
            elif op == 0x60:
                for _ in range(uleb()):
                    out.append(self.segments[segi].vmaddr + seg_off)
                    seg_off += 8
            elif op == 0x70:
                out.append(self.segments[segi].vmaddr + seg_off)
                seg_off += 8 + uleb()
            elif op == 0x80:
                n, skip = uleb(), uleb()
                for _ in range(n):
                    out.append(self.segments[segi].vmaddr + seg_off)
                    seg_off += 8 + skip
            else:
                raise PatchError("unknown rebase opcode %#x" % op)
        return out

    def binds(self):
        """[(slot_vm, symbol, addend)] for the non-lazy bind table."""
        (_, _, bind_off, bind_size) = self._dyld_info()[:4]
        d = self.d
        p, end = bind_off, bind_off + bind_size
        segi = seg_off = 0
        name = None
        addend = 0
        out = []

        def uleb():
            nonlocal p
            r = sh = 0
            while True:
                b = d[p]
                p += 1
                r |= (b & 0x7F) << sh
                sh += 7
                if not b & 0x80:
                    return r

        def sleb():
            nonlocal p
            r = sh = 0
            while True:
                b = d[p]
                p += 1
                r |= (b & 0x7F) << sh
                sh += 7
                if not b & 0x80:
                    if b & 0x40:
                        r -= 1 << sh
                    return r

        while p < end:
            b = d[p]
            p += 1
            op, imm = b & 0xF0, b & 0x0F
            if op == 0x00:
                break
            elif op == 0x10:
                pass
            elif op == 0x20:
                uleb()
            elif op == 0x30:
                pass
            elif op == 0x40:
                e = d.index(b"\x00", p)
                name = d[p:e].decode(errors="replace")
                p = e + 1
            elif op == 0x50:
                pass
            elif op == 0x60:
                addend = sleb()
            elif op == 0x70:
                segi, seg_off = imm, uleb()
            elif op == 0x80:
                seg_off += uleb()
            elif op == 0x90:
                out.append((self.segments[segi].vmaddr + seg_off, name, addend))
                seg_off += 8
            elif op == 0xA0:
                out.append((self.segments[segi].vmaddr + seg_off, name, addend))
                seg_off += 8 + uleb()
            elif op == 0xB0:
                out.append((self.segments[segi].vmaddr + seg_off, name, addend))
                seg_off += 8 + imm * 8
            elif op == 0xC0:
                count, skip = uleb(), uleb()
                for _ in range(count):
                    out.append((self.segments[segi].vmaddr + seg_off, name, addend))
                    seg_off += 8 + skip
            else:
                raise PatchError("unknown bind opcode %#x" % op)
        return out

    def imports(self):
        out = {}
        for slot, name, _addend in self.binds():
            out.setdefault(name, []).append(slot)
        return out


# ---------------------------------------------------------------------------
# key build discovery
# ---------------------------------------------------------------------------
IMM_RE = re.compile(r"^(\w+),\s*#(-?(?:0x[0-9a-f]+|\d+))(?:\s*,\s*lsl\s*#(\d+))?$")
MEM_RE = re.compile(
    r"^(\w+),\s*(?:(\w+),\s*)?\[(\w+)(?:,\s*#(-?(?:0x[0-9a-f]+|\d+)))?\](!?)$")


def _imm_mask(words):
    w = words
    return (((w & 0x7F800000) == 0x52800000) |      # movz
            ((w & 0x7F800000) == 0x72800000) |      # movk
            ((w & 0x7F800000) == 0x12800000) |      # movn
            ((w & 0xFFC00000) == 0xF9000000) |      # str x
            ((w & 0xFFC00000) == 0xF8000000) |      # str x (unscaled)
            ((w & 0xFFC00000) == 0xA9000000))       # stp


def _runs(d, min_insn):
    n = len(d) // 4
    words = np.frombuffer(d[:n * 4], dtype="<u4")
    mask = _imm_mask(words)
    padded = np.concatenate(([False], mask, [False]))
    dd = np.diff(padded.astype(np.int8))
    starts = np.flatnonzero(dd == 1)
    ends = np.flatnonzero(dd == -1)
    keep = (ends - starts) >= min_insn
    return [(int(a) * 4, int(b) * 4) for a, b in zip(starts[keep], ends[keep])]


def reg_width(reg):
    return {"x": 8, "w": 4, "b": 1, "h": 2}.get(reg[0], 0)


def assemble_run(code, lo, hi):
    """Replay a mov/movk/stp/str run.

    Returns dict with events, the per-base byte map and the store/def detail
    needed to rewrite the immediates later.
    """
    events = []
    for insn in MD.disasm(code[lo:hi], lo):
        mnem = insn.mnemonic
        ops = insn.op_str.replace(" ", "")
        pc = insn.address
        if mnem in ("mov", "movz", "movk", "movn"):
            g = IMM_RE.match(ops)
            if not g:
                return None
            reg, val, shift = g.group(1), int(g.group(2), 0), int(g.group(3) or 0)
            events.append(("def", pc, reg, mnem, val, shift))
            continue
        if mnem in ("str", "stp"):
            g = MEM_RE.match(ops)
            if not g:
                return None
            r1, r2, base, off, bang = g.group(1), g.group(2), g.group(3), \
                int(g.group(4) or "0", 0), g.group(5)
            if bang:                                  # pre-index, shifts the base
                return None
            items = [(r1, off)]
            if r2 is not None:
                items = [(r1, off), (r2, off + reg_width(r1))]
            events.append(("store", pc, base, items))
            continue
        return None
    if not events:
        return None

    regs = {}
    pending = {}
    chunks = []            # (pc, base, reg, width, off, defs, value)
    store_order = []       # (pc, base, [(reg, width, off)])
    for ev in events:
        if ev[0] == "def":
            _, pc, reg, mnem, val, shift = ev
            if mnem == "movn":
                value = (~(val << shift)) & M64
            elif mnem == "movk":
                value = regs.get(reg, 0) | ((val << shift) & M64)
            else:
                value = (val << shift) & M64
            regs[reg] = value
            if mnem == "movk":
                pending.setdefault(reg, []).append(ev)
            else:
                pending[reg] = [ev]
        else:
            _, pc, base, items = ev
            use = []
            for reg, off in items:
                w = reg_width(reg)
                val = 0 if reg in ("xzr", "wzr") else regs.get(reg, 0)
                defs = list(pending.get(reg, []))
                chunks.append((pc, base, reg, w, off, defs, val))
                pending[reg] = []           # consumed: later stores need new defs
                use.append((reg, w, off))
            store_order.append((pc, base, use))

    bufs = {}
    for pc, base, reg, w, off, defs, val in chunks:
        bufs.setdefault(base, {})[off] = val.to_bytes(8, "little")[:w]

    return {"events": events, "chunks": chunks, "stores": store_order,
            "bufs": bufs, "lo": lo, "hi": hi}


class KeyBuild:
    def __init__(self, lo, hi, base, off, length, text, public, run):
        self.lo = lo
        self.hi = hi
        self.base = base
        self.off = off
        self.length = length
        self.text = text
        self.public = public
        self.run = run

    def __repr__(self):
        return "<key %s %#x..%#x %d bytes at [%s+%#x]>" % (
            "public" if self.public else "private", self.lo, self.hi,
            self.length, self.base, self.off)


def _text_from(buf, off, length):
    raw = bytearray(length)
    for o, b in buf.items():
        rel = o - off
        if 0 <= rel < length:
            raw[rel:rel + len(b)] = b
    return bytes(raw)


def find_key_builds(m, min_insn=60):
    """All immediate-built RSA key strings in the binary."""
    out = []
    for lo, hi in _runs(m.d, min_insn):
        run = assemble_run(m.d, lo, hi)
        if not run:
            continue
        for base, buf in run["bufs"].items():
            if not buf:
                continue
            off = min(buf)
            hi_off = max(o + len(b) for o, b in buf.items())
            length = hi_off - off
            if length < 320 or length > 8192:
                continue
            raw = _text_from(buf, off, length)
            txt = raw.split(b"\x00")[0]
            if not (txt.startswith(b"<RSAKeyValue>") and txt.endswith(b"</RSAKeyValue>")):
                continue
            if any(b < 0x20 or b > 0x7E for b in txt):
                continue
            s = txt.decode()
            public = "<Exponent>" in s and "<D>" not in s
            out.append(KeyBuild(lo, hi, base, off, length, s, public, run))
            break
    return out


def key_span(b):
    """Inclusive instruction span that belongs to this key build only."""
    pcs = []
    for pc, base, reg, w, off, defs, val in b.run["chunks"]:
        if base != b.base:
            continue
        pcs.append(pc)
        for d in defs:
            pcs.append(d[1])
    if not pcs:
        raise PatchError("cannot locate the instructions of %r" % b)
    lo = max(min(pcs), b.run["lo"])
    hi = min(max(pcs) + 4, b.run["hi"])
    return lo, hi


# ---------------------------------------------------------------------------
# free space discovery
# ---------------------------------------------------------------------------
def _merge(ranges):
    out = []
    for a, b in sorted(ranges):
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def _longest_zero(d, lo, hi):
    best = (lo, 0)
    i = lo
    while i < hi:
        j = d.find(b"\x00", i, hi)
        if j < 0:
            break
        k = j
        while k < hi and d[k] == 0:
            k += 1
        if k - j > best[1]:
            best = (j, k - j)
        i = k
    return best


def text_free_runs(m, min_size=16):
    """Zero runs inside __TEXT that no section claims (file offsets)."""
    text = m.segment("__TEXT")
    end = text.fileoff + text.filesize
    covered = [(0, 32 + m.sizeofcmds)]
    for s in text.sections:
        if s.size and not s.zerofill:
            covered.append((s.offset, min(s.offset + s.size, end)))
    covered = _merge([c for c in covered if c[0] < end])
    gaps = []
    pos = 0
    for a, b in covered:
        if a > pos:
            gaps.append((pos, a))
        pos = max(pos, b)
    if pos < end:
        gaps.append((pos, end))
    out = []
    for a, b in gaps:
        z, n = _longest_zero(m.d, a, b)
        if n >= min_size:
            out.append({"off": z, "size": n, "vm": m.o2v(z)})
    return out


def writable_zero_gap(m, size, align=16):
    """Unused zero-filled address range in a writable segment."""
    cands = []
    for seg in m.segments:
        if not (seg.initprot & 0x2):
            continue
        if seg.vmsize <= seg.filesize:
            continue
        lo = max(seg.fileend_vm, seg.vmaddr)
        hi = seg.vmend
        if hi - lo < size:
            continue
        covered = []
        for s in seg.sections:
            if s.zerofill or s.addr >= lo:
                a, b = max(s.addr, lo), min(s.end, hi)
                if b > a:
                    covered.append((a, b))
        pos = lo
        for a, b in _merge(covered):
            if a - pos >= size:
                cands.append((pos, a))
            pos = max(pos, b)
        if hi - pos >= size:
            cands.append((pos, hi))
    if not cands:
        raise PatchError("no %d-byte zero-filled writable gap found" % size)
    # last gap first: the tail of __DATA is the least likely to be touched
    pos, end = cands[-1]
    vm = (pos + align - 1) & ~(align - 1)
    if vm + size > end:
        raise PatchError("writable gap too small after alignment")
    return vm


# ---------------------------------------------------------------------------
# ObjC metadata
# ---------------------------------------------------------------------------
class Method:
    __slots__ = ("name", "entry", "imp_field", "imp", "relative")

    def __init__(self, name, entry, imp_field, imp, relative):
        self.name = name
        self.entry = entry
        self.imp_field = imp_field
        self.imp = imp
        self.relative = relative

    def __repr__(self):
        return "<method %s entry %#x imp %#x%s>" % (
            self.name, self.entry, self.imp, " (relative)" if self.relative else "")


class ClassInfo:
    __slots__ = ("name", "ptr", "ro", "methods")

    def __init__(self, name, ptr, ro, methods):
        self.name = name
        self.ptr = ptr
        self.ro = ro
        self.methods = methods


class ObjC:
    def __init__(self, m):
        self.m = m
        self.classes = {}
        for sect in ("__objc_classlist", "__objc_nlclslist"):
            s = m.section(sect)
            if s is None:
                continue
            for i in range(s.size // 8):
                ptr = m.u64(s.addr + i * 8)
                if not ptr:
                    continue
                info = self._class(ptr)
                if info:
                    self.classes[info.name] = info

    def _class(self, ptr):
        m = self.m
        try:
            data = m.u64(ptr + 32)
            ro = data & ~7
            if ro < 0x100000000:
                return None
            name = m.cstr(m.u64(ro + 24))
            methods = m.u64(ro + 32)
            if not name:
                return None
            return ClassInfo(name, ptr, ro, self._methods(name, methods))
        except Exception:
            return None

    def _methods(self, cls, ml):
        m = self.m
        out = []
        if not ml:
            return out
        try:
            raw = m.u32(ml)
        except Exception:
            return out
        count = m.u32(ml + 4)
        if count > 20000:
            return out
        relative = bool(raw & 0x80000000)
        entsize = raw & 0xFFFF
        if entsize < (12 if relative else 24):
            return out
        for i in range(count):
            e = ml + 8 + i * entsize
            try:
                if relative:
                    noff, _toff, ioff = struct.unpack("<iii", m.read(e, 12))
                    sel = m.cstr(e + noff)
                    imp_field = e + ioff
                    imp = imp_field
                else:
                    np_, _tp, ip = struct.unpack("<QQQ", m.read(e, 24))
                    sel = m.cstr(np_)
                    imp_field = e + 16
                    imp = ip
            except Exception:
                continue
            if sel:
                out.append(Method(sel, e, imp_field, imp, relative))
        return out

    def method(self, cls, sel):
        info = self.classes.get(cls)
        if info is None:
            raise PatchError("ObjC class %r not found" % cls)
        for meth in info.methods:
            if meth.name == sel:
                return meth
        raise PatchError("-[%s %s] not found" % (cls, sel))


def selrefs(m):
    s = m.section("__objc_selrefs")
    if s is None:
        raise PatchError("__objc_selrefs not found")
    out = {}
    for i in range(s.size // 8):
        ptr = m.u64(s.addr + i * 8)
        if not ptr:
            continue
        name = m.cstr(ptr)
        if name:
            out.setdefault(name, s.addr + i * 8)
    return out


# ---------------------------------------------------------------------------
# patching primitives
# ---------------------------------------------------------------------------
def _patch_word(data, pc, word):
    struct.pack_into("<I", data, pc, word)


def rewrite_build_key(data, b, key_text):
    """Replace the key text a build materialises, in place (no extra space)."""
    if len(key_text) + 1 > b.length:
        raise PatchError(
            "new key is %d bytes, the build has room for %d"
            % (len(key_text) + 1, b.length))
    padded = key_text.encode() + b"\x00" + b"\x00" * (b.length - len(key_text) - 1)
    touched = []
    for pc, base, reg, w, off, defs, cur in b.run["chunks"]:
        if base != b.base:
            continue
        rel = off - b.off
        if rel < 0 or rel + w > len(padded):
            continue
        val = int.from_bytes(padded[rel:rel + w], "little")
        for d in defs:
            _, dpc, dreg, mnem, imm, shift = d
            if dreg != reg:
                continue
            lane = (val >> shift) & 0xFFFF
            if mnem == "movn":
                lane = (~lane) & 0xFFFF
            word = struct.unpack_from("<I", data, dpc)[0]
            _patch_word(data, dpc, (word & ~(0xFFFF << 5)) | (lane << 5))
            touched.append(dpc)
    # verify by replaying the patched code
    run = assemble_run(bytes(data), b.lo, b.hi)
    if not run or b.base not in run["bufs"]:
        raise PatchError("key build at %#x no longer assembles" % b.lo)
    got = _text_from(run["bufs"][b.base], b.off, b.length)
    if got.split(b"\x00")[0] != key_text.encode():
        raise PatchError("key build at %#x did not take the new key" % b.lo)
    return touched


def build_stub(b, slot_vm, new_blob_vm, orig_blob_vm, vm_base):
    """Copy-from-blob stub that replaces a whole key build."""
    span_lo, span_hi = key_span(b)
    base = b.base

    # reuse the registers the original build clobbered, so nothing that the
    # surrounding code relies on changes
    defregs = []
    for pc, bbase, reg, w, off, defs, cur in b.run["chunks"]:
        if bbase != base:
            continue
        for d in defs:
            dreg = d[2]
            if dreg not in (base, "xzr", "wzr", "sp") and dreg not in defregs:
                defregs.append(dreg)
    if len(defregs) < 2:
        raise PatchError("key build at %#x has no spare scratch registers" % b.lo)
    r1, r2 = defregs[0], defregs[1]
    if base in (r1, r2):
        raise PatchError("key build at %#x uses its base as scratch" % b.lo)

    def adrp_add(reg, vm):
        return ["adrp %s, 0x%x" % (reg, vm & ~0xFFF),
                "add %s, %s, #0x%x" % (reg, reg, vm & 0xFFF)]

    lines = ["adrp %s, 0x%x" % (r1, slot_vm & ~0xFFF),
             "ldr %s, [%s, #0x%x]" % (r1, r1, slot_vm & 0xFFF),
             "cbz %s, .Lstub_orig" % r1]
    lines += adrp_add(r1, orig_blob_vm)
    lines += ["b .Lstub_copy"]
    lines += [".Lstub_orig:"]
    lines += adrp_add(r1, new_blob_vm)
    lines += [".Lstub_copy:"]
    for pc, bbase, reg, w, off, defs, cur in b.run["chunks"]:
        if bbase != base:
            continue
        rel = off - b.off
        lines.append("ldr %s, [%s, #0x%x]" % (r2, r1, rel))
        lines.append("str %s, [%s, #0x%x]" % (r2, base, off))

    src = "\n".join(lines)
    try:
        from keystone import Ks as K, KS_ARCH_ARM64 as KA, KS_MODE_LITTLE_ENDIAN as KL
    except ImportError:
        from keystone.keystone import Ks as K, KS_ARCH_ARM64 as KA, KS_MODE_LITTLE_ENDIAN as KL
    enc, _cnt = K(KA, KL).asm(src, vm_base)
    stub = bytes(enc)
    if len(stub) > span_hi - span_lo:
        raise PatchError("stub for %#x is %d bytes, only %d available"
                         % (b.lo, len(stub), span_hi - span_lo))
    pad = span_hi - span_lo - len(stub)
    return stub + b"\x1f\x20\x03\xd5" * (pad // 4), span_lo, span_hi


def _bl_target(insn):
    w = insn.bytes[0] | (insn.bytes[1] << 8) | (insn.bytes[2] << 16) | (insn.bytes[3] << 24)
    if (w & 0xFC000000) == 0x94000000:            # bl
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        return insn.address + imm * 4
    return None


def _no_branches_into(m, lo, hi, radius=0x2000):
    """Refuse to replace a block something jumps into from outside."""
    for start in (max(lo - radius, 0), hi):
        end = min(start + radius, len(m.d))
        if start >= end:
            continue
        for insn in MD.disasm(m.d[start:end], start):
            t = _bl_target(insn)
            if t is not None and lo < t < hi:
                return False
    return True


# ---------------------------------------------------------------------------
# IPA
# ---------------------------------------------------------------------------
class Ipa:
    def __init__(self, path):
        self.path = path
        self.zf = zipfile.ZipFile(path)
        self.main_entry, self.app_dir, self.info = self._find_main()
        self.version = self.info.get("CFBundleShortVersionString") or "?"
        self.build = self.info.get("CFBundleVersion") or "?"

    def _find_main(self):
        for name in self.zf.namelist():
            if name.startswith("Payload/") and name.endswith(".app/Info.plist") \
                    and name.count("/") == 2:
                app_dir = name[: -len("/Info.plist")]
                info = plistlib.loads(self.zf.read(name))
                exe = info.get("CFBundleExecutable")
                if exe:
                    return app_dir + "/" + exe, app_dir, info
        raise PatchError("no Payload/*.app/Info.plist in %s" % self.path)

    @property
    def app_name(self):
        return os.path.basename(self.app_dir)

    def read_main(self):
        return self.zf.read(self.main_entry)

    def close(self):
        self.zf.close()


def ldid_path(explicit=None):
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (explicit,
                 os.path.join(here, "bin", "ldid_w64_x86_64.exe"),
                 os.path.join(here, "bin", "ldid.exe"),
                 os.path.join(here, "ldid_w64_x86_64.exe"),
                 "ldid"):
        if not cand:
            continue
        if os.path.sep in cand or cand.endswith(".exe"):
            if os.path.isfile(cand):
                return os.path.abspath(cand)
        else:
            found = shutil.which(cand)
            if found:
                return found
    return None


def adhoc_sign(blob, ldid=None, ident="GenshinImpact"):
    """ldid -S the binary so dyld accepts it before KSign re-signs.

    ldid copies the input file name into the ad-hoc signature, so the temp file
    gets a fixed name inside a private temp directory.  That keeps the output
    byte-identical between runs (the directory name is not embedded).
    """
    exe = ldid_path(ldid)
    if not exe:
        return blob, False
    tmpdir = tempfile.mkdtemp(prefix="rsapatch_sign_")
    tmp = os.path.join(tmpdir, "%s.bin" % (ident or "GenshinImpact"))
    try:
        with open(tmp, "wb") as f:
            f.write(blob)
        r = subprocess.run([exe, "-S", tmp], capture_output=True)
        if r.returncode != 0:
            raise PatchError("ldid failed: %s" % (r.stderr.decode(errors="replace").strip()))
        signed = open(tmp, "rb").read()
        if len(signed) > len(blob):
            raise PatchError("ldid grew the binary (%d -> %d)"
                             % (len(blob), len(signed)))
        if signed[:32] != blob[:32]:
            raise PatchError("ldid changed the Mach-O header unexpectedly")
        MachO(signed)                                # must still parse
        return signed, True
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def repack(src, dst, main_entry, main_blob, progress=True):
    t0 = time.time()
    with zipfile.ZipFile(src) as zin:
        infos = zin.infolist()
        with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED,
                             compresslevel=6, allowZip64=True) as zout:
            replaced = False
            for n, info in enumerate(infos, 1):
                zi = zipfile.ZipInfo(info.filename, info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zi.internal_attr = info.internal_attr
                zi.create_system = info.create_system
                zi.comment = info.comment
                if info.filename == main_entry:
                    zi.file_size = len(main_blob)
                    zout.writestr(zi, main_blob)
                    replaced = True
                elif info.is_dir():
                    zout.writestr(zi, b"")
                else:
                    with zin.open(info) as fsrc, zout.open(zi, "w") as fdst:
                        shutil.copyfileobj(fsrc, fdst, 1 << 20)
                if progress and n % 200 == 0:
                    print("  %d/%d  %6.1fs" % (n, len(infos), time.time() - t0))
            if not replaced:
                raise PatchError("%s not found in the archive" % main_entry)
    return time.time() - t0


def verify_repack(src, dst, main_entry, main_blob):
    ok = True
    with zipfile.ZipFile(src) as a, zipfile.ZipFile(dst) as b:
        if a.namelist() != b.namelist():
            print("  !! entry list changed")
            ok = False
        else:
            print("  entry list identical (%d entries)" % len(b.namelist()))
        ea = {i.filename: i for i in a.infolist()}
        eb = {i.filename: i for i in b.infolist()}
        bad = 0
        for name in b.namelist():
            if name == main_entry:
                continue
            if (ea[name].CRC, ea[name].file_size) != (eb[name].CRC, eb[name].file_size):
                print("  !! %s changed" % name)
                bad += 1
        if bad:
            ok = False
        else:
            print("  all other entries intact")
        got = b.read(main_entry)
        if got != main_blob:
            print("  !! main binary differs")
            ok = False
        else:
            print("  main binary matches the patched bytes")
        if b.testzip() is not None:
            print("  !! zip CRC failure")
            ok = False
        else:
            print("  zip CRCs valid")
    return ok


# ---------------------------------------------------------------------------
# high level patchers
# ---------------------------------------------------------------------------
MCACHE = {}


def _method_rebased(m, meth):
    """The IMP field must be rewritten at load time or our hook is lost."""
    vm = meth.imp_field
    if meth.relative:
        raise PatchError("-[%s] uses a relative method list; not supported"
                         % meth.name)
    sec = m.section_of(vm)
    if sec is None:
        raise PatchError("IMP field %#x is not inside a section" % vm)
    seg = m.segment(sec.segname)
    if seg.flags & SG_READ_ONLY_AFTER_FIXUPS or sec.segname in ("__DATA_CONST",
                                                               "__AUTH_CONST"):
        raise PatchError("IMP field %#x lives in read-only %s"
                         % (vm, sec.segname))
    return vm in set(m.rebase_vms())


def _pick_import(imports, names, what):
    for nm in names:
        slots = imports.get(nm)
        if slots:
            return slots[0]
    raise PatchError("%s not imported (%s)" % (what, ", ".join(names)))


def plan(m, key_text, want_toggle, official_texts=None):
    """Discover everything both patchers need and return a plan dict."""
    builds = find_key_builds(m)
    public = [b for b in builds if b.public]
    if not public:
        raise PatchError("no public RSA key builds found - wrong binary?")
    texts = []
    for b in public:
        if b.text not in texts:
            texts.append(b.text)
    if official_texts is None:
        official_texts = texts
    lengths = {b.length for b in public}
    if len(lengths) != 1:
        raise PatchError("key builds have different lengths: %r" % sorted(lengths))
    length = lengths.pop()

    p = {
        "builds": builds,
        "public": public,
        "private": [b for b in builds if not b.public],
        "texts": texts,
        "official_texts": official_texts,
        "length": length,
        "key": key_text,
        "toggle": want_toggle,
    }
    if not want_toggle:
        return p

    method = ObjC(m).method("UnityAppController", "startUnity:")
    if not _method_rebased(m, method):
        raise PatchError("the startUnity: IMP field is not rebased by dyld")
    p["method"] = method

    imports = m.imports()
    p["got"] = {
        "msgsend": _pick_import(imports, ["_objc_msgSend"], "objc_msgSend"),
        "getclass": _pick_import(imports, ["_objc_getClass"], "objc_getClass"),
        "dlsym": _pick_import(imports, ["_dlsym"], "dlsym"),
        "globalblock": _pick_import(
            imports,
            ["__NSConcreteGlobalBlock", "___NSConcreteGlobalBlock",
             "_NSConcreteGlobalBlock"],
            "__NSConcreteGlobalBlock"),
    }
    p["sel"] = selrefs(m)
    p["scratch"] = writable_zero_gap(m, 0x100)
    return p


def _load_panel(plan, code_base):
    from panel import build_panel, resolve_sel

    keys = ("standardUserDefaults", "stringWithUTF8String", "integerForKey",
            "setIntegerForKey", "synchronize", "alloc", "init", "initWithFrame",
            "initWithWindowScene", "mainScreen", "connectedScenes", "anyObject",
            "sharedApplication", "bounds", "setWindowLevel",
            "setRootViewController", "makeKeyAndVisible", "setHidden", "present",
            "alert", "action", "addAction", "date", "timeIntervalSinceReferenceDate",
            "dateWithTimeIntervalSinceNow", "currentRunLoop",
            "runMode:beforeDate:")
    missing = [k for k in keys if resolve_sel(plan["sel"], k) is None]
    if missing:
        raise PatchError("selectors missing from __objc_selrefs: %s"
                         % ", ".join(missing))
    cfg = {
        "code_base": code_base,
        "orig_start": plan["method"].imp,
        "scratch": plan["scratch"],
        "got_msgsend": plan["got"]["msgsend"],
        "got_getclass": plan["got"]["getclass"],
        "got_dlsym": plan["got"]["dlsym"],
        "got_globalblock": plan["got"]["globalblock"],
        "sel": plan["sel"],
    }
    return build_panel(cfg)


def _space_for(m, need, avoid=()):
    runs = [r for r in text_free_runs(m, need) if r["size"] >= need]
    for r in sorted(runs, key=lambda r: r["vm"]):
        if any(abs(r["vm"] - a) < 0x1000 for a in avoid):
            continue
        vm = (r["vm"] + 15) & ~15
        if vm + need <= r["vm"] + r["size"]:
            return vm, r
    raise PatchError("no %d-byte free __TEXT space found" % need)


def patch_standalone(main, key_text, report=None):
    m = MachO(main)
    p = plan(m, key_text, want_toggle=False)
    data = bytearray(main)
    offs = set()
    for b in p["public"]:
        for pc in rewrite_build_key(data, b, key_text):
            offs.add(pc)
    # nothing outside the key immediates may change
    changed = {i for i in range(len(data)) if data[i] != main[i]}
    stray = changed - {o + k for o in offs for k in range(4)}
    if stray:
        raise PatchError("%d unexpected bytes changed" % len(stray))
    # every public build now materialises the new key
    for b in p["public"]:
        run = assemble_run(bytes(data), b.lo, b.hi)
        got = _text_from(run["bufs"][b.base], b.off, b.length).split(b"\x00")[0]
        if got != key_text.encode():
            raise PatchError("build %#x still has the old key" % b.lo)
    rep = {
        "mode": "standalone",
        "key": key_text,
        "public": p["public"],
        "private": p["private"],
        "length": p["length"],
        "changed_bytes": len(changed),
        "sites": [(b.lo, b.hi, b.base, b.off) for b in p["public"]],
    }
    if report is not None:
        report.update(rep)
    return bytes(data), rep


def patch_toggle(main, key_text, report=None):
    m = MachO(main)
    p = plan(m, key_text, want_toggle=True)
    data = bytearray(main)
    length = p["length"]

    # blobs: replacement key + one per distinct shipped key
    new_blob = key_text.encode() + b"\x00" + b"\x00" * (length - len(key_text) - 1)
    off_blobs = []
    for t in p["official_texts"]:
        off_blobs.append(t.encode() + b"\x00" + b"\x00" * (length - len(t) - 1))
    blob_bytes = len(new_blob) + sum(len(b) for b in off_blobs)

    # find space: code first, then blobs (same zero run when it fits)
    cave = None
    for r in sorted(text_free_runs(m, 0x400), key=lambda r: r["vm"]):
        vm = (r["vm"] + 15) & ~15
        probe = _load_panel(p, vm)
        need = len(probe["blob"])
        if need <= r["size"] and need + blob_bytes <= r["size"]:
            cave = (vm, r, probe, "same")
            break
        if need <= r["size"] and cave is None:
            cave = (vm, r, probe, "apart")
    if cave is None:
        raise PatchError("no free __TEXT space for the panel")

    code_vm, cave_run, panel, where = cave
    if where == "same":
        new_vm = (code_vm + len(panel["blob"]) + 7) & ~7
    else:
        new_vm, _r2 = _space_for(m, blob_bytes, avoid=(code_vm,))
    off_vms = []
    cur = new_vm + len(new_blob)
    for blob in off_blobs:
        off_vms.append(cur)
        cur += len(blob)

    # blobs must be inside free, readable __TEXT space
    for vm, blob in [(new_vm, new_blob)] + list(zip(off_vms, off_blobs)):
        o = m.v2o(vm)
        if o is None or any(m.d[o:o + len(blob)]):
            raise PatchError("blob area at %#x is not free" % vm)
    o = m.v2o(code_vm)
    if o is None or any(m.d[o:o + len(panel["blob"])]):
        raise PatchError("code cave at %#x is not free" % code_vm)

    data[o:o + len(panel["blob"])] = panel["blob"]
    data[m.v2o(new_vm):m.v2o(new_vm) + len(new_blob)] = new_blob
    for vm, blob in zip(off_vms, off_blobs):
        data[m.v2o(vm):m.v2o(vm) + len(blob)] = blob

    # per-site stubs
    sites = []
    for b in p["public"]:
        idx = p["official_texts"].index(b.text)
        lo, hi = key_span(b)
        stub, lo, hi = build_stub(b, p["scratch"], new_vm, off_vms[idx],
                                  m.o2v(lo))
        if not _no_branches_into(m, lo, hi):
            raise PatchError("code branches into the key build at %#x" % lo)
        data[lo:hi] = stub
        sites.append({"lo": lo, "hi": hi, "stub": len(stub)})

    # hook
    meth = p["method"]
    struct.pack_into("<Q", data, m.v2o(meth.imp_field), code_vm)

    rep = {
        "mode": "toggle",
        "key": key_text,
        "public": p["public"],
        "private": p["private"],
        "length": length,
        "code_vm": code_vm,
        "code_len": len(panel["blob"]),
        "code_free": cave_run["size"] - (new_vm - code_vm) - len(new_blob) if where == "same" else None,
        "scratch": p["scratch"],
        "method": meth,
        "got": p["got"],
        "blob_new": new_vm,
        "blob_orig": off_vms,
        "blob_space": blob_bytes,
        "sites": sites,
        "labels": panel["labels"],
        "asm": panel["asm"],
    }
    if report is not None:
        report.update(rep)
    return bytes(data), rep


# ---------------------------------------------------------------------------
# reporting helpers
# ---------------------------------------------------------------------------
def describe(m, p):
    lines = []
    lines.append("key builds      : %d public, %d private (len %d)"
                 % (len(p["public"]), len(p["private"]), p["length"]))
    for b in p["public"]:
        lines.append("  site %#010x..%#010x  [%s+%#x] %d B  %s"
                     % (b.lo, b.hi, b.base, b.off, b.length, b.text[26:50] + "..."))
    if p["private"]:
        lines.append("  (private keys are left untouched)")
    return lines
