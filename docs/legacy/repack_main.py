#!/usr/bin/env python3
"""Repack the patched IPA: replace only the main executable.

No files are added or removed, no load commands change, so the archive keeps
its original entry list and order.  Everything is streamed so a 3.3 GB archive
does not need 3.3 GB of RAM.
"""
import shutil
import sys
import time
import zipfile

MAIN = "Payload/GenshinImpact.app/GenshinImpact"


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else \
        "GenshinImpact_7.1.0_YuukiPS_patched_ldid.ipa"
    dst = sys.argv[2] if len(sys.argv) > 2 else \
        "GenshinImpact_7.1.0_Toggle_v4.ipa"
    new_main = sys.argv[3] if len(sys.argv) > 3 else "main_final.bin"

    blob = open(new_main, "rb").read()
    print("new main binary : %s  %d bytes" % (new_main, len(blob)))

    t0 = time.time()
    with zipfile.ZipFile(src) as zin:
        infos = zin.infolist()
        print("source          : %s  %d entries" % (src, len(infos)))
        if not any(i.filename == MAIN for i in infos):
            raise SystemExit("main binary not found in archive")

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
                zi.file_size = info.file_size
                zi.CRC = info.CRC

                if info.filename == MAIN:
                    print("  [%d/%d] replacing main binary (%d -> %d bytes)"
                          % (n, len(infos), info.file_size, len(blob)))
                    zi.file_size = len(blob)
                    zi.compress_type = info.compress_type
                    zout.writestr(zi, blob)
                    replaced = True
                elif info.is_dir():
                    zout.writestr(zi, b"")
                else:
                    with zin.open(info) as fsrc, zout.open(zi, "w") as fdst:
                        shutil.copyfileobj(fsrc, fdst, 1 << 20)

                if n % 200 == 0:
                    print("  %d/%d  %6.1fs" % (n, len(infos), time.time() - t0))
            if not replaced:
                raise SystemExit("main binary entry never visited")

    print("wrote %s in %.1fs" % (dst, time.time() - t0))

    # ---- verify ------------------------------------------------------------
    print("\nverifying...")
    ok = True
    with zipfile.ZipFile(src) as a, zipfile.ZipFile(dst) as b:
        an, bn = a.namelist(), b.namelist()
        if an != bn:
            print("!! entry list changed")
            ok = False
        else:
            print("  entry list identical (%d entries)" % len(bn))
        ea = {i.filename: i for i in a.infolist()}
        eb = {i.filename: i for i in b.infolist()}
        bad = 0
        for name in bn:
            ia, ib = ea[name], eb[name]
            if name == MAIN:
                continue
            if (ia.CRC, ia.file_size) != (ib.CRC, ib.file_size):
                print("  !! %s crc/size changed" % name)
                bad += 1
        print("  non-main entries intact: %s" % ("yes" if not bad else "NO"))
        if bad:
            ok = False

        got = b.read(MAIN)
        print("  main binary  : %d bytes" % len(got))
        if got != blob:
            print("  !! main binary bytes differ")
            ok = False
        else:
            print("  main binary matches main_final.bin")
        if b.testzip() is not None:
            print("  !! zip crc failure")
            ok = False
        else:
            print("  zip CRCs valid")

    print("\nRESULT:", "OK" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
