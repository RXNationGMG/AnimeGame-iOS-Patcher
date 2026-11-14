#!/usr/bin/env python3
"""Inject the v7 blocking server-select panel into the main Genshin executable.

Writes three things into main_signed.bin and nothing else (no new load
commands, no segment changes, no protection changes):

  file 0x000031C0   payload code                __TEXT header padding
  file 0x139F34A8   official RSA key (416 B)    __TEXT __eh_frame gap
  file 0x152C58C0   IMP of -[UnityAppController startUnity:]
                    -> hook_start               __DATA (writable, rebased)

`showGameUI` is deliberately left alone: the panel no longer lives there, so
that IMP still points at 0x1000195E0 (checked below).

The key slot the seven patched key-build sites read stays a zero-filled
pointer in __DATA (0x11604F000): zero means "use the baked-in Yuuki key".
Only hook_start writes it, before UnityInitApplication.
"""
import json
import struct
import sys

import capstone

import keypatch

YUUKI = keypatch.YUUKI
assert len(YUUKI) == 415

HOYO = ("<RSAKeyValue><Modulus>15RBm/vARY0axYksImhsTicpv09OYfS4+wCvmE7psOvZhW2URZ2Rlf5D"
        "sEtuRG/7v5W/2obqqVkf+1dorPcR2iqrYZ4VVPf7KU3Cgqh0kzLGxWOpGxzwJULEyFVaiMDWbk7gr8"
        "rik/jYyhLiLc52zz3E3whTUPleKhOhXnxx1iOKY+TPVI8jJfDNiQoh0UvgjnkigJ/saPzjogeig/4M"
        "cBc4l5cDkvttkKQKq7oXe9OCBClgKlYjcc1CNalwMlTz7NvLEko+ZLTgpA+kElZumyBXT67mmW7t7"
        "IDXorscAI7auwusKWmq797alFkQ/6sUqs8KKGnqQ2fwHfa/RYDhEw==</Modulus><Exponent>AQAB"
        "</Exponent></RSAKeyValue>")
assert len(HOYO) == 415

CODE_OFF = 0x31C0          # vm 0x1000031C0
CODE_VM = 0x100000000 + CODE_OFF
CODE_SPAN = 0xE40          # zero run ends at 0x100004000 (first __text insn)

KEY_OFF = 0x139F34A8       # vm 0x1139F34A8
KEY_VM = 0x100000000 + KEY_OFF
KEY_SPAN = 416

SHOW_IMP_OFF = 0x152C5680  # vm 0x1152C5680  (must stay untouched)
SHOW_IMP_VM = 0x100000000 + SHOW_IMP_OFF
SHOW_IMP_ORIG = 0x1000195E0
SHOW_ENTRY = 0x1152C5670

START_IMP_OFF = 0x152C58C0  # vm 0x1152C58C0
START_IMP_VM = 0x100000000 + START_IMP_OFF
START_IMP_OLD = 0x10001774C
START_ENTRY = 0x1152C58B0

METHOD_LIST = 0x1152C54E8


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


SEGS = [
    ("__TEXT", 0x100000000, 329220096, 0, 329220096),
    ("__DATA_CONST", 0x1139F8000, 24608768, 0x139F8000, 24608768),
    ("__DATA", 0x115170000, 15597568, 0x15170000, 3850240),
    ("__LLVM_COV", 0x116050000, 425984, 0x1551C000, 425984),
    ("__LINKEDIT", 0x1160B8000, 8519680, 0x1559C000, 8513312),
]


def v2o(vm):
    for name, va, vs, fo, fs in SEGS:
        if va <= vm < va + fs:
            return fo + (vm - va)
    return None


def cstr(d, o):
    e = d.index(b"\x00", o)
    return d[o:e].decode()


def find_entry(d, name):
    ml = METHOD_LIST
    entsize, count = u32(d, v2o(ml)), u32(d, v2o(ml) + 4)
    if entsize != 0x18 or count > 5000:
        raise SystemExit("unexpected method list header")
    for i in range(count):
        e = v2o(ml) + 8 + i * entsize
        if cstr(d, v2o(u64(d, e))) == name:
            return ml + 8 + i * entsize
    raise SystemExit("method %r not found in the list" % name)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "main_signed.bin"
    dst = sys.argv[2] if len(sys.argv) > 2 else "main_patched.bin"
    d = bytearray(open(src, "rb").read())
    payload = open("payload.bin", "rb").read()
    meta = json.load(open("payload.json"))
    LAB = meta["labels"]

    print("in  %s  %d bytes" % (src, len(d)))
    print("payload %d bytes at vm %#x (span %#x)" % (len(payload), CODE_VM, CODE_SPAN))
    if len(payload) > CODE_SPAN:
        raise SystemExit("payload does not fit in the header padding")
    if meta["code_end"] > CODE_VM + len(payload):
        raise SystemExit("payload.json code_end is outside the blob")

    # ---- preconditions -----------------------------------------------------
    got_entry = find_entry(d, "startUnity:")
    if got_entry != START_ENTRY:
        raise SystemExit("startUnity: entry moved: %#x != %#x"
                         % (got_entry, START_ENTRY))
    if v2o(START_IMP_VM) != START_IMP_OFF:
        raise SystemExit("startUnity: imp vm/file mismatch")
    cur = u64(d, START_IMP_OFF)
    print("%-13s entry %#x  imp %#x -> %#x" % ("startUnity:", START_ENTRY, cur,
                                               LAB["hook_start"]))
    if cur != START_IMP_OLD:
        raise SystemExit("startUnity: IMP is %#x, expected %#x"
                         % (cur, START_IMP_OLD))

    # showGameUI must still be stock: the panel does not live there any more
    cur_show = u64(d, SHOW_IMP_OFF)
    print("%-13s entry %#x  imp %#x (must stay stock)" % ("showGameUI", SHOW_ENTRY,
                                                          cur_show))
    if cur_show != SHOW_IMP_ORIG:
        raise SystemExit("showGameUI IMP is %#x, expected stock %#x"
                         % (cur_show, SHOW_IMP_ORIG))

    # the field we rewrite must be rebased by dyld, or it will not survive
    # the slide
    import check_rebase
    import inspect2 as I
    src_m = I.M(src)             # load commands are identical in dst
    segs_vm = [(s[0], s[1], s[2]) for s in src_m.segs]
    want = {START_IMP_VM}
    rebased = set()
    for segi, off in check_rebase.walk_rebase(src_m):
        vm = segs_vm[segi][1] + off
        if vm in want:
            rebased.add(vm)
    missing = want - rebased
    if missing:
        raise SystemExit("IMP fields not rebased: %s"
                         % ", ".join(hex(x) for x in sorted(missing)))
    print("startUnity: IMP field is covered by the dyld rebase table")

    for name, off, span in (("code", CODE_OFF, CODE_SPAN),
                            ("key", KEY_OFF, KEY_SPAN)):
        if any(d[off:off + span]):
            raise SystemExit("%s region at %#x is not zero" % (name, off))
    print("free regions verified zero")

    # ---- patch -------------------------------------------------------------
    if v2o(KEY_VM) != KEY_OFF:
        raise SystemExit("key vm/file mismatch: %r" % v2o(KEY_VM))
    d[CODE_OFF:CODE_OFF + len(payload)] = payload
    key = HOYO.encode() + b"\x00"
    assert len(key) == KEY_SPAN
    d[KEY_OFF:KEY_OFF + KEY_SPAN] = key
    struct.pack_into("<Q", d, START_IMP_OFF, LAB["hook_start"])
    open(dst, "wb").write(d)
    print("wrote %s" % dst)

    # ---- verify ------------------------------------------------------------
    v = open(dst, "rb").read()
    good = True
    if v[CODE_OFF:CODE_OFF + len(payload)] != payload:
        print("!! payload bytes differ")
        good = False
    if v[KEY_OFF:KEY_OFF + KEY_SPAN] != key:
        print("!! key bytes differ")
        good = False
    if v[KEY_OFF:KEY_OFF + 23] != b"<RSAKeyValue><Modulus>1":
        print("!! key does not start like the official key")
        good = False
    got = u64(v, START_IMP_OFF)
    print("%-13s IMP now %#x %s" % ("startUnity:", got,
                                    "OK" if got == LAB["hook_start"] else "WRONG"))
    if got != LAB["hook_start"]:
        good = False
    if u64(v, SHOW_IMP_OFF) != SHOW_IMP_ORIG:
        print("!! showGameUI IMP changed")
        good = False
    if v[0x3020:0x3020 + KEY_SPAN] != YUUKI.encode() + b"\x00":
        print("!! baked Yuuki key does not match the canonical Yuuki key")
        good = False

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for label in ("hook_start",):
        addr = LAB[label]
        o = CODE_OFF + (addr - CODE_VM)
        print("\nentry disassembly at %s (%#x):" % (label, addr))
        for ins in md.disasm(v[o:o + 0x20], addr):
            print("  %#012x  %-7s %s" % (ins.address, ins.mnemonic, ins.op_str))

    print("\nsize %d (was %d)" % (len(v), len(d)))
    print("RESULT:", "OK" if good else "FAIL")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
