"""Shared patch pipeline.

`rsa_patch.py` (the friendly front-end) and the two command line scripts all
call `run()` from here, so every entry point patches and verifies the IPA in
exactly the same way.

    run("standalone", "game.ipa")   # always private server
    run("toggle", "game.ipa")       # pre-game selection panel

The input must be a *decrypted* IPA (a .zip with Payload/*.app inside).  Only
the app's main executable is rewritten; every other archive entry is copied
through byte for byte, in its original order.
"""
import argparse
import hashlib
import os
import sys
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import gipatch as G                                          # noqa: E402

MODES = ("standalone", "toggle")
SUFFIX = {"standalone": "_RSApatch_standalone", "toggle": "_RSApatch_toggle"}

DESCRIPTION = {
    "standalone": "always use the private server key (no menu in game)",
    "toggle": "choose private or official from a pre-game panel",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def load_key(path=None):
    """Return (key_text, description) for the private-server key."""
    if not path:
        return G.GRASSCUTTER_KEY, "built-in Grasscutter / YuukiPS key"
    try:
        with open(path, "rb") as f:
            raw = f.read().decode("utf-8", "replace")
    except OSError as exc:
        raise G.PatchError("cannot read the key file: %s" % exc)
    txt = "".join(raw.split())
    if not (txt.startswith("<RSAKeyValue>") and txt.endswith("</RSAKeyValue>")):
        raise G.PatchError("%s is not a single <RSAKeyValue>...</RSAKeyValue> "
                           "file" % path)
    if "<Modulus>" not in txt:
        raise G.PatchError("%s has no <Modulus> element" % path)
    return txt, path


def default_output(src, mode):
    base, ext = os.path.splitext(src)
    if ext.lower() not in (".ipa", ".zip"):
        ext = ".ipa"
    return base + SUFFIX[mode] + ".ipa"


def human_bytes(n):
    for unit in ("bytes", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return ("%d %s" % (n, unit)) if unit == "bytes" else \
                   ("%.2f %s" % (n, unit))
        n /= 1024.0
    return "%d bytes" % n


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def free_space(path):
    try:
        return __import__("shutil").disk_usage(os.path.dirname(
            os.path.abspath(path))).free
    except OSError:
        return None


# ---------------------------------------------------------------------------
# the pipeline
# ---------------------------------------------------------------------------
def run(mode, src, out=None, key_file=None, report_only=False, sign=True,
        ldid=None, overwrite=False, verbose=False, echo=print):
    """Patch one IPA.

    Returns a dict with `output`, `size`, `sha256`, `changed`, `seconds` and
    `report` (the patcher's own report).  Raises gipatch.PatchError on any
    explainable refusal, after removing a half-written output file.
    """
    if mode not in MODES:
        raise ValueError("mode must be one of %r" % (MODES,))
    if not os.path.isfile(src):
        raise G.PatchError("file not found: %s" % src)

    t0 = time.time()
    key, key_src = load_key(key_file)
    ipa = G.Ipa(src)
    try:
        echo("Reading %s" % os.path.basename(src))
        echo("  app         : %s %s (%s)"
             % (ipa.app_name, ipa.version, ipa.build))
        echo("  main binary : %s" % ipa.main_entry)
        echo("  key         : %s" % key_src)

        main = ipa.read_main()
        echo("  main size   : %s" % human_bytes(len(main)))

        m = G.MachO(main)
        if m.encryption_cryptid():
            raise G.PatchError(
                "this IPA is still encrypted - decrypt it first "
                "(cryptid != 0)")
        plan = G.plan(m, key, want_toggle=(mode == "toggle"))

        n_pub, n_priv = len(plan["public"]), len(plan["private"])
        echo("")
        echo("Found %d public key build%s%s."
             % (n_pub, "" if n_pub == 1 else "s",
                " and %d private one%s (left alone)"
                % (n_priv, "" if n_priv == 1 else "s") if n_priv else ""))
        if mode == "toggle":
            echo("  panel hook  : -[UnityAppController startUnity:] "
                 "(entry %#x, imp %#x)"
                 % (plan["method"].entry, plan["method"].imp))
            echo("  key slots   : private -> 0, official -> 1")
        if verbose:
            echo("")
            for line in G.describe(m, plan):
                echo("  " + line)

        if report_only:
            echo("")
            echo("Report only - nothing was written.")
            return {"output": None, "size": 0, "sha256": None, "changed": 0,
                    "seconds": time.time() - t0, "report": None,
                    "plan": plan}

        out = out or default_output(src, mode)
        out = os.path.abspath(out)
        if os.path.exists(out) and not overwrite:
            raise G.PatchError("output already exists: %s" % out)
        if os.path.dirname(out) and not os.path.isdir(os.path.dirname(out)):
            os.makedirs(os.path.dirname(out))

        echo("")
        echo("Patching ...")
        if mode == "standalone":
            patched, rep = G.patch_standalone(main, key)
            echo("  changed     : %d bytes in %d key builds"
                 % (rep["changed_bytes"], len(rep["public"])))
        else:
            patched, rep = G.patch_toggle(main, key)
            echo("  panel       : %d bytes of code at %#x"
                 % (rep["code_len"], rep["code_vm"]))
            echo("  stubs       : %d key builds now load their key at runtime"
                 % len(rep["sites"]))
            if verbose:
                for s in rep["sites"]:
                    echo("                %#010x..%#010x -> stub %d"
                         % (s["lo"], s["hi"], s["stub"]))

        if sign:
            patched, signed = G.adhoc_sign(
                patched, ldid, ident=os.path.basename(ipa.main_entry))
            echo("  ad-hoc sign : %s" % (
                "done (ldid)" if signed else
                "skipped, ldid not found (KSign will sign it)"))
        else:
            echo("  ad-hoc sign : skipped (--no-sign)")

        echo("")
        echo("Packing ...")
        try:
            secs = G.repack(src, out, ipa.main_entry, patched)
        except BaseException:
            _discard(out)
            raise
        echo("  packed      : %.1f s" % secs)

        echo("")
        echo("Verifying ...")
        try:
            if not G.verify_repack(src, out, ipa.main_entry, patched):
                raise G.PatchError("the repacked IPA did not verify")
            with zipfile.ZipFile(out) as z:
                written = z.read(ipa.main_entry)
            wm = G.MachO(written)

            if mode == "standalone":
                bad = 0
                for b in G.plan(wm, key, want_toggle=False)["public"]:
                    insn = G.assemble_run(written, b.lo, b.hi)
                    got = G._text_from(insn["bufs"][b.base], b.off,
                                       b.length).split(b"\x00")[0]
                    if got != key.encode():
                        bad += 1
                total = len(plan["public"])
                echo("  new key     : %d/%d key builds" % (total - bad, total))
                if bad:
                    raise G.PatchError("the written IPA carries the wrong key")
            else:
                hook_ok = wm.u64(plan["method"].imp_field) == rep["code_vm"]
                code_ok = written[wm.v2o(rep["code_vm"]):
                                  wm.v2o(rep["code_vm"]) + rep["code_len"]] == \
                    patched[wm.v2o(rep["code_vm"]):
                            wm.v2o(rep["code_vm"]) + rep["code_len"]]
                blob_ok = written[wm.v2o(rep["blob_new"]):
                                  wm.v2o(rep["blob_new"]) + len(key)] == \
                    key.encode()
                shipped_ok = all(
                    written[wm.v2o(vm):wm.v2o(vm) + len(t)] == t.encode()
                    for vm, t in zip(rep["blob_orig"], plan["official_texts"]))
                sites_ok = all(written[s["lo"]:s["hi"]] ==
                               patched[s["lo"]:s["hi"]] for s in rep["sites"])
                echo("  hook        : %s" % ("ok" if hook_ok else "WRONG"))
                echo("  panel code  : %s" % ("ok" if code_ok else "WRONG"))
                echo("  key blob    : %s" % ("ok" if blob_ok else "WRONG"))
                echo("  shipped key : %s" % ("ok" if shipped_ok else "WRONG"))
                echo("  stubs       : %s" % ("ok" if sites_ok else "WRONG"))
                if not all((hook_ok, code_ok, blob_ok, shipped_ok, sites_ok)):
                    raise G.PatchError("the written IPA did not verify")
        except BaseException:
            _discard(out)
            raise

        size = os.path.getsize(out)
        seconds = time.time() - t0
        echo("")
        echo("Done in %.1f s." % seconds)
        return {"output": out, "size": size, "sha256": sha256_file(out),
                "changed": rep.get("changed_bytes", 0), "seconds": seconds,
                "report": rep, "plan": plan}
    finally:
        ipa.close()


def _discard(path):
    """Never leave a half-written or unverified IPA behind."""
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# small CLI used by patch_standalone.py / patch_toggle.py
# ---------------------------------------------------------------------------
def cli(mode, argv=None):
    ap = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]) if argv is None else None,
        description="Patch a decrypted Genshin Impact IPA: %s."
                    % DESCRIPTION[mode])
    ap.add_argument("input", help="decrypted Genshin Impact .ipa (or .zip)")
    ap.add_argument("output", nargs="?",
                    help="output IPA (default: <input>%s.ipa)" % SUFFIX[mode])
    ap.add_argument("--key-file", help="XML <RSAKeyValue> with the private key")
    ap.add_argument("--report-only", action="store_true",
                    help="analyse only, write nothing")
    ap.add_argument("--no-sign", action="store_true",
                    help="do not ad-hoc sign with ldid")
    ap.add_argument("--ldid", help="path to the ldid executable")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print every discovered site")
    args = ap.parse_args(argv)

    try:
        res = run(mode, args.input, args.output, args.key_file,
                  report_only=args.report_only, sign=not args.no_sign,
                  ldid=args.ldid, overwrite=True, verbose=args.verbose)
    except G.PatchError as exc:
        raise SystemExit(str(exc))

    if res["output"]:
        print("")
        print("output       : %s" % res["output"])
        print("size         : %d bytes (%.2f GiB)"
              % (res["size"], res["size"] / (1 << 30)))
        print("sha256       : %s" % res["sha256"])
        print("elapsed      : %.1f s" % res["seconds"])
        print("")
        print("Install the IPA with KSign or Sideloadly.")
