#!/usr/bin/env python3
"""Replace Genshin's inline RSA-key string builds with a copy from memory.

Why this shape: the key is not computed, it is a 344-char XML string
("<RSAKeyValue><Modulus>...</Modulus>...") materialised by MOVZ/MOVK immediates
and stored into [x0+0x20].  Because the bytes are instruction immediates, the
only way to switch keys at runtime is to change code -- and patching __TEXT of a
signed binary needs CS_GET_TASK_ALLOW.  So instead we patch the code *offline*
to copy the string from a writable slot, and the runtime library just flips that
slot.  Writing __DATA needs no entitlement at all.

usage:
  keypatch.py analyze <binary|ipa>
  keypatch.py patch   <in> <out> [--default yuuki|official] [--slot VMADDR]
"""
import re
import struct
import sys
import zipfile

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
SITES_71 = [0x3F6330, 0x408A18, 0x40EAC0, 0x413464, 0x41A080, 0x3973EC4, 0x39852C0]
SITES_72 = [0x62356C8, 0x623CE04, 0x68BDDF4, 0x68BF898, 0x68C576C, 0x68CCF24, 0x68D5094]

HOYO = ("<RSAKeyValue><Modulus>15RBm/vARY0axYksImhsTicpv09OYfS4+wCvmE7psOvZhW2URZ2Rlf5D"
        "sEtuRG/7v5W/2obqqVkf+1dorPcR2iqrYZ4VVPf7KU3Cgqh0kzLGxWOpGxzwJULEyFVaiMDWbk7"
        "gr8rik/jYyhLiLc52zz3E3whTUPleKhOhXnxx1iOKY+TPVI8jJfDNiQoh0UvgjnkigJ/saPzjo"
        "geig/4McBc4l5cDkvttkKQKq7oXe9OCBClgKlYjcc1CNalwMlTz7NvLEko+ZLTgpA+kElZumyBX"
        "T67mmW7t7IDXorscAI7auwusKWmq797alFkQ/6sUqs8KKGnqQ2fwHfa/RYDhEw==</Modulus><Exp"
        "onent>AQAB</Exponent></RSAKeyValue>")
# Canonical YuukiPS key: the one the device-confirmed working build
# (GenshinImpact_7.1.0_YuukiPS_patched_ldid.ipa / backup ..._working_2026-11-10)
# bakes into all seven public-key build sites.  Do NOT take this key from the
# AGP "CustomServer" module (lib/arm64-v8a/libtersafe3.so): that string is a
# different modulus (…TKZpIcRInv… instead of …TKZpIcTInv…, one base64 char) and
# belongs to the com.yuuki.gios custom-server client, not to ps.yuuki.me.
YUUKI = ("<RSAKeyValue><Modulus>xbbx2m1feHyrQ7jP+8mtDF/pyYLrJWKWAdEv3wZrOtjOZzeLGPzsmk"
         "cgncgoRhX4dT+1itSMR9j9m0/OwsH2UoF6U32LxCOQWQD1AMgIZjAkJeJvFTrtn8fMQ1701Ckb"
         "aLTVIjRMlTw8kNXvNA/A9UatoiDmi4TFG6mrxTKZpIcTInvPEpkK2A7Qsp1E4skFK8jmysy7uRh"
         "MaYHtPTsBvxP0zn3lhKB3W+HTqpneewXWHjCDfL7Nbby91jbz5EKPZXWLuhXIvR1Cu4tiruorwXJ"
         "xmXaP1HQZonytECNU/UOzP6GNLdq0eFDE4b04Wjp396551G99YiFP2nqHVJ5OMQ==</Modulus><Exp"
         "onent>AQAB</Exponent></RSAKeyValue>")
KEYS = {"hoyo": HOYO, "official": HOYO, "yuuki": YUUKI}
BUF_OFF = 0x20          # string lives at [x0 + 0x20]
BUF_LEN = 416           # 0x20 .. 0x1c0, key padded with zeros
STR_OFF = BUF_OFF + 0x10  # first instruction after the shared "<RSAKeyValue><M"

IMM_OPS = ("mov", "movk", "str", "stp")
STP_RE = re.compile(r"(\w+), (\w+), \[(\w+)(?:, #(-?0x[0-9a-f]+))?\]")
STR_RE = re.compile(r"(\w+), \[(\w+)(?:, #(-?0x[0-9a-f]+))?\]")


# ---------------------------------------------------------------- encoders
def _adrp(rd, pc, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return (0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd)


def _add_imm(rd, rn, imm):
    assert 0 <= imm < 4096
    return 0x91000000 | (imm << 10) | (rn << 5) | rd


def _ldr_w(rt, rn, off):
    assert off % 4 == 0 and 0 <= off < 16384
    return 0xB9400000 | ((off // 4) << 10) | (rn << 5) | rt


def _ldr_x(rt, rn, off):
    assert off % 8 == 0 and 0 <= off < 32768
    return 0xF9400000 | ((off // 8) << 10) | (rn << 5) | rt


def _ldr_post(rt, rn, imm):
    assert -256 <= imm <= 255
    return 0xF8400400 | ((imm & 0x1FF) << 12) | (rn << 5) | rt


def _str_off(rt, rn, off):
    assert off % 8 == 0 and 0 <= off < 32768
    return 0xF9000000 | ((off // 8) << 10) | (rn << 5) | rt


def _lsl(rd, rn, sh):
    assert 1 <= sh <= 63
    return 0xD3400000 | ((64 - sh) << 16) | ((63 - sh) << 10) | (rn << 5) | rd


def _cbnz(rt, imm):
    assert imm % 4 == 0 and -1048576 <= imm < 1048576
    return 0xB5000000 | ((imm // 4 & 0x7FFFF) << 5) | rt


NOP = 0xD503201F
X0, X8, X9 = 0, 8, 9


def dis1(d, a):
    ins = list(MD.disasm(d[a:a + 4], a))
    return ins[0] if ins else None


def is_imm_insn(i):
    return i is not None and i.mnemonic in IMM_OPS and "#" in i.op_str


def walk_build(d, site):
    """Return (start, end) of the key build containing/adjacent to site."""
    lo = site
    while lo >= 4 and is_imm_insn(dis1(d, lo - 4)):
        lo -= 4
    regs, seen = {}, set()
    hi = lo
    while hi < len(d):
        i = dis1(d, hi)
        if not is_imm_insn(i):
            break
        m, o = i.mnemonic, i.op_str
        if m in ("mov", "movk"):
            rd = o.split(",")[0].strip()
            imm = int(o.split("#")[1].split(",")[0], 0)
            sh = int(o.split("lsl #")[1], 0) if "lsl #" in o else 0
            regs[rd] = imm if m == "mov" else regs.get(rd, 0) | (imm << sh)
        elif m == "stp":
            t = STP_RE.match(o)
            if t:
                seen.add(int(t.group(4) or 0, 0))
                seen.add(int(t.group(4) or 0, 0) + 8)
        elif m == "str":
            t = STR_RE.match(o)
            if t:
                seen.add(int(t.group(3) or 0, 0))
        hi += 4
        if (BUF_OFF + BUF_LEN - 8) in seen:
            break
    return lo, hi


def assemble(d, lo, hi):
    """Rebuild the buffer the build writes. Returns (base, min_off, bytes)."""
    regs, buf, base = {}, {}, None
    for i in MD.disasm(d[lo:hi], lo):
        m, o = i.mnemonic, i.op_str
        if m in ("mov", "movk"):
            rd = o.split(",")[0].strip()
            imm = int(o.split("#")[1].split(",")[0], 0)
            sh = int(o.split("lsl #")[1], 0) if "lsl #" in o else 0
            regs[rd] = imm if m == "mov" else regs.get(rd, 0) | (imm << sh)
        elif m == "stp":
            t = STP_RE.match(o)
            if not t:
                continue
            r1, r2, base, off = t.group(1), t.group(2), t.group(3), int(t.group(4) or 0, 0)
            buf[off] = regs.get(r1, 0).to_bytes(8, "little")
            buf[off + 8] = regs.get(r2, 0).to_bytes(8, "little")
        elif m == "str":
            t = STR_RE.match(o)
            if not t:
                continue
            r, base, off = t.group(1), t.group(2), int(t.group(3) or 0, 0)
            buf[off] = regs.get(r, 0).to_bytes(8, "little")
    if not buf:
        return None
    mn = min(buf)
    raw = bytearray(max(buf) + 8 - mn)
    for o, v in buf.items():
        raw[o - mn:o - mn + 8] = v
    return base, mn, bytes(raw)


def blob(key):
    s = KEYS[key].encode()
    assert len(s) == BUF_LEN - 1, len(s)   # 415 chars + NUL
    return s + b"\x00" * (BUF_LEN - len(s))


def find_segments(d):
    magic, _, _, _, ncmds, _, _ = struct.unpack_from("<IiiIIII", d, 0)
    off, segs, sig = 32, [], None
    for _ in range(ncmds):
        c, s = struct.unpack_from("<II", d, off)
        if c == 0x19:
            nm = d[off + 8:off + 24].rstrip(b"\x00").decode()
            va, vs, fo, fs = struct.unpack_from("<QQQQ", d, off + 24)
            segs.append({"name": nm, "vm": va, "vs": vs, "file": fo, "fs": fs,
                         "cmd": off, "nsect": struct.unpack_from("<I", d, off + 64)[0]})
        elif c == 0x1D:
            sig = (off,) + struct.unpack_from("<II", d, off + 8)
        off += s
    return segs, sig


def section_end(d, seg):
    end = seg["vm"]
    for k in range(seg["nsect"]):
        so = seg["cmd"] + 72 + k * 80
        sa, ss = struct.unpack_from("<QQ", d, so + 32)
        end = max(end, sa + ss)
    return end


def stub(site_vm, blob_vm, slot_vm, buf_off, buf_len):
    """Emit: src = *(u64*)slot ?: default_blob ; copy buf_len bytes to [x0+buf_off].

    site_vm is the *mapped* address of the stub, not the file offset.
    """
    n = buf_len // 8
    words = []
    pc = site_vm
    words.append(_adrp(X8, pc, slot_vm)); pc += 4
    words.append(_ldr_x(X8, X8, slot_vm & 0xFFF)); pc += 4
    words.append(_cbnz(X8, 12)); pc += 4
    words.append(_adrp(X8, pc, blob_vm)); pc += 4
    words.append(_add_imm(X8, X8, blob_vm & 0xFFF)); pc += 4
    for k in range(n):
        words.append(_ldr_post(X9, X8, 8))
        words.append(_str_off(X9, X0, buf_off + 8 * k))
    return words


def simulate_stub(d, lo_file, vm_bias, slot_value, blob_vm, slot_addr, sources):
    """Run the patched stub symbolically; return the 416 bytes written to [x0+0x20].

    sources maps a base address to the bytes readable there.
    """
    regs = {0: 0x100000}   # x0 = pretend object
    out = {}
    pc = lo_file + vm_bias
    n = BUF_LEN // 8
    for _ in range(5 + 2 * n + 8):
        w = struct.unpack_from("<I", d, pc - vm_bias)[0]
        if w == NOP:
            break
        pc += 4
        if (w & 0x9F000000) == 0x90000000:      # adrp
            rd = w & 31
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = ((immhi << 2) | immlo)
            if imm & (1 << 20):
                imm -= 1 << 21
            regs[rd] = ((pc - 4) & ~0xFFF) + (imm << 12)
        elif (w & 0xFFC00000) == 0xF9400000:    # ldr x, [x, #imm]
            rn, rt = (w >> 5) & 31, w & 31
            off = ((w >> 10) & 0xFFF) * 8
            assert regs.get(rn, 0) + off == slot_addr, "slot load address wrong"
            regs[rt] = slot_value
        elif (w & 0x7F000000) == 0x35000000:    # cbnz x
            rt = w & 31
            imm = (w >> 5) & 0x7FFFF
            if imm & (1 << 18):
                imm -= 1 << 19
            if regs.get(rt, 0):
                pc = (pc - 4) + imm * 4
        elif (w & 0xFF800000) == 0x91000000:    # add x, x, #imm
            rn, rd = (w >> 5) & 31, w & 31
            regs[rd] = regs.get(rn, 0) + ((w >> 10) & 0xFFF)
        elif (w & 0xFFC00000) == 0xF8400000:    # ldr x, [x], #imm
            rn, rt = (w >> 5) & 31, w & 31
            off = (w >> 12) & 0x1FF
            if off & 0x100:
                off -= 0x200
            addr = regs.get(rn, 0)
            data = b""
            for b, buf in sources.items():
                if b <= addr <= b + len(buf) - 8:
                    o = addr - b
                    data = buf[o:o + 8]
                    break
            assert len(data) == 8, f"unreadable source {addr:#x}"
            regs[rt] = int.from_bytes(data, "little")
            regs[rn] = addr + off
        elif (w & 0xFFC00000) == 0xF9000000:    # str x, [x, #imm]
            rn, rt = (w >> 5) & 31, w & 31
            off = ((w >> 10) & 0xFFF) * 8
            out[off] = regs.get(rt, 0)
        else:
            raise SystemExit(f"bad stub insn {w:#x} at {pc - 4:#x}")
    raw = bytearray(BUF_LEN)
    for off, v in out.items():
        assert BUF_OFF <= off <= BUF_OFF + BUF_LEN - 8
        raw[off - BUF_OFF:off - BUF_OFF + 8] = v.to_bytes(8, "little")
    return bytes(raw)


def patch(src, dst, default="yuuki"):
    d = load(src)
    segs, sig = find_segments(d)
    text = next(s for s in segs if s["name"] == "__TEXT")
    data = next(s for s in segs if s["name"] == "__DATA")
    sizeofcmds = struct.unpack_from("<I", d, 20)[0]
    lc_end = 32 + sizeofcmds
    blob_addr = (lc_end + 0x100 + 15) & ~15
    text_start = min(struct.unpack_from("<I", d, s["cmd"] + 72 + 48)[0]
                     for s in segs if s["name"] == "__TEXT")
    assert blob_addr + BUF_LEN <= text_start, (hex(blob_addr), hex(text_start))
    slot_addr = (data["vm"] + data["vs"] - 0x1000) & ~15
    assert slot_addr >= section_end(d, data), "no free __DATA tail"
    assert slot_addr + 8 <= data["vm"] + data["vs"]

    payload = blob(default)
    print(f"blob  @ {blob_addr:#x} (file) vm {text['vm'] + blob_addr:#x}  {len(payload)}B")
    print(f"slot  @ {slot_addr:#x}  (__DATA free tail, zero-filled)")
    d[blob_addr:blob_addr + BUF_LEN] = payload

    sites = 0
    starts = []
    for site in SITES_71:
        lo, hi = walk_build(d, site)
        base, mn, raw = assemble(d, lo, hi)
        assert raw == blob("hoyo") and mn == BUF_OFF and base == "x0", hex(site)
        words = stub(text["vm"] + lo, text["vm"] + blob_addr, slot_addr, BUF_OFF, BUF_LEN)
        body = b"".join(struct.pack("<I", w) for w in words)
        assert len(body) <= hi - lo, (hex(site), len(body), hi - lo)
        d[lo:hi] = body + b"\x00" * (hi - lo - len(body))
        for k in range(len(body), hi - lo, 4):
            struct.pack_into("<I", d, lo + k, NOP)
        starts.append(lo)
        sites += 1
    print(f"patched {sites} site(s)")

    first = starts[0]
    blob_vm = text["vm"] + blob_addr
    got = simulate_stub(d, first, text["vm"], 0, blob_vm, slot_addr, {blob_vm: payload})
    assert got == payload, "stub does not reproduce the default key"
    print("simulation: default path reproduces the key exactly")
    alt = blob("hoyo")
    got2 = simulate_stub(d, first, text["vm"], 0xDEAD0000, blob_vm, slot_addr,
                         {0xDEAD0000: alt})
    assert got2 == alt, "override path does not read the caller's buffer"
    print("simulation: override path reads the caller's buffer")

    with open(dst, "wb") as f:
        f.write(d)
    print("wrote", dst, len(d), "bytes")


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    mode, src = sys.argv[1], sys.argv[2]
    if mode == "analyze":
        ok = analyze(src, SITES_71)
        print("RESULT:", "OK" if ok else "FAIL")
    elif mode == "patch":
        default = "yuuki"
        if "--default" in sys.argv:
            default = sys.argv[sys.argv.index("--default") + 1]
        patch(src, sys.argv[3], default)
    else:
        raise SystemExit("unknown mode")


def analyze(path, sites):
    d = load(path)
    ok = True
    for site in sites:
        lo, hi = walk_build(d, site)
        r = assemble(d, lo, hi)
        if not r:
            print(f"{site:#x}: no build"); ok = False; continue
        base, mn, raw = r
        want = blob("hoyo")
        good = (base == "x0" and mn == BUF_OFF and raw == want)
        print(f"{site:#x}: build {lo:#x}..{hi:#x} ({(hi - lo)}B, {(hi - lo) // 4} insn) "
              f"base {base} off {mn:#x} len {len(raw)} -> {'OK' if good else 'MISMATCH'}")
        if not good:
            ok = False
            print("   got ", raw[:60])
            print("   want", want[:60])
    return ok


def load(path):
    if path.lower().endswith(".ipa"):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.endswith(".app/GenshinImpact") and n.count("/") == 2:
                    return bytearray(z.read(n))
        raise SystemExit("no main binary in " + path)
    with open(path, "rb") as f:
        return bytearray(f.read())


if __name__ == "__main__":
    main()
