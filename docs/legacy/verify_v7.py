#!/usr/bin/env python3
"""Verify a repacked toggle IPA against its source archive and main_final.bin.

Checks, in order:
  * entry count and name list identical to the source (nothing added/dropped)
  * every entry except main has an identical CRC to the source entry
  * main's CRC differs (i.e. it really was replaced)
  * the extracted main is byte-identical to main_final.bin
  * the payload, official key, IMP patch, baked Yuuki key and code-signature
    magic are all present in the extracted main
  * the new archive reads back cleanly entry by entry (CRC verify)
"""
import struct
import sys
import zipfile

MAIN = "Payload/GenshinImpact.app/GenshinImpact"
CODE_VM = 0x1000031C0
KEY_VM = 0x1139F34A8
IMP_OFF = 0x152C58C0
SHOW_IMP_OFF = 0x152C5680
YUUKI_OFF = 0x3020


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "GenshinImpact_7.1.0_YuukiPS_patched_ldid.ipa"
    dst = sys.argv[2] if len(sys.argv) > 2 else "GenshinImpact_7.1.0_Toggle_v7.ipa"
    binp = sys.argv[3] if len(sys.argv) > 3 else "main_final.bin"
    payload = open("payload.bin", "rb").read()
    ok = True

    def bad(msg):
        nonlocal ok
        print("!! " + msg)
        ok = False

    a = zipfile.ZipFile(src)
    b = zipfile.ZipFile(dst)
    ba = b.BadZipFile if False else None

    na = a.namelist()
    nb = b.namelist()
    print("source entries %d, new entries %d" % (len(na), len(nb)))
    if na != nb:
        bad("entry list differs")
        missing = set(na) - set(nb)
        extra = set(nb) - set(na)
        if missing:
            print("   missing:", list(missing)[:5])
        if extra:
            print("   extra  :", list(extra)[:5])

    ia = {i.filename: i for i in a.infolist()}
    ib = {i.filename: i for i in b.infolist()}
    changed = []
    for name in na:
        x, y = ia[name], ib.get(name)
        if y is None:
            continue
        if x.CRC != y.CRC:
            changed.append(name)
    print("entries with a different CRC: %d %s"
          % (len(changed), changed[:5] if len(changed) <= 5 else changed[:5] + ["..."]))
    if changed != [MAIN]:
        bad("expected exactly %s to change, got %r" % (MAIN, changed))

    print("verifying every entry's CRC in the new archive ...")
    bad_entries = 0
    for i in b.infolist():
        try:
            with b.open(i) as f:
                while f.read(1 << 20):
                    pass
        except Exception as exc:
            bad_entries += 1
            print("   %s: %s" % (i.filename, exc))
    if bad_entries:
        bad("%d entries failed to read back" % bad_entries)
    else:
        print("   all %d entries read back cleanly" % len(nb))

    with b.open(MAIN) as f:
        d = f.read()
    ref = open(binp, "rb").read()
    print("main extracted %d bytes, main_final.bin %d bytes" % (len(d), len(ref)))
    if d != ref:
        bad("extracted main is not byte-identical to %s" % binp)

    if d[0x31C0:0x31C0 + len(payload)] != payload:
        bad("payload bytes missing from the packed main")
    else:
        print("payload  : %d bytes at vm %#x" % (len(payload), CODE_VM))
    if d[0x139F34A8:0x139F34A8 + 13] != b"<RSAKeyValue>":
        bad("official key missing")
    else:
        print("official key present at vm %#x" % KEY_VM)
    if d[YUUKI_OFF:YUUKI_OFF + 13] != b"<RSAKeyValue>":
        bad("baked Yuuki key missing")
    else:
        print("Yuuki key present at file 0x%x" % YUUKI_OFF)

    # content checks: a one-character key difference is invisible above but
    # breaks the handshake (4214), so compare against the canonical blobs.
    import inject_main
    import keypatch
    ykey = keypatch.YUUKI.encode() + b"\x00"
    okey = inject_main.HOYO.encode() + b"\x00"
    if d[YUUKI_OFF:YUUKI_OFF + 416] != ykey:
        bad("baked Yuuki key is not the canonical YuukiPS modulus")
    else:
        print("Yuuki key matches canonical modulus  (...%s...)"
              % keypatch.YUUKI[178:200])
    if d[KEY_VM - 0x100000000:KEY_VM - 0x100000000 + 416] != okey:
        bad("official key is not the canonical HoYoverse modulus")
    else:
        print("official key matches canonical modulus")
    imp = struct.unpack_from("<Q", d, IMP_OFF)[0]
    show = struct.unpack_from("<Q", d, SHOW_IMP_OFF)[0]
    print("startUnity IMP %#x (want %#x)" % (imp, CODE_VM))
    print("showGameUI IMP %#x (want stock 0x1000195e0)" % show)
    if imp != CODE_VM:
        bad("startUnity IMP wrong")
    if show != 0x1000195E0:
        bad("showGameUI IMP not stock")
    if d.find(b"\xfa\xde\x0c\xc0") < 0:
        bad("no code signature blob")

    print("\nRESULT:", "OK" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
