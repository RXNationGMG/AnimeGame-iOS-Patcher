"""Genshin Impact iOS - RSA Patcher (friendly front-end).

Double-click START_HERE.bat on Windows (or run `python rsa_patch.py`) and
answer the two questions.  Nothing else is needed.

Command line, if you prefer:

    python rsa_patch.py game.ipa                 # asks which build
    python rsa_patch.py game.ipa --mode toggle   # panel build
    python rsa_patch.py game.ipa --mode 1 -y     # always private, no prompts

The input must be a *decrypted* IPA.  Only the app's main executable is
patched; everything else in the archive is copied through unchanged.
"""
import argparse
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gipatch as G                                          # noqa: E402
import pipeline                                              # noqa: E402

VERSION = "1.1.0"
RULE = "=" * 62

# What each mode does, in plain words.
MODE_NAMES = {
    "1": "standalone",
    "2": "toggle",
    "standalone": "standalone",
    "toggle": "toggle",
    "s": "standalone",
    "t": "toggle",
}
MODE_TEXT = {
    "standalone": "always connect to the private server (simplest)",
    "toggle": "ask me on every launch (panel before the game)",
}

HINTS = {
    "still encrypted": "You need a decrypted copy of the game, not the App "
                       "Store download. Decrypt it on a jailbroken device or "
                       "get an already-decrypted IPA.",
    "no Payload/": "This file does not look like an IPA. Pick the .ipa you "
                   "decrypted, not a .zip of something else.",
    "no public RSA key": "The game's RSA key code was not found. Likely the "
                         "file is encrypted, is not Genshin Impact, or this "
                         "game version changed the way it builds keys.",
    "chained fixups": "This game build uses a newer Mach-O format that the "
                      "scripts do not support yet.",
    "relative method list": "This game build uses a newer ObjC format that the "
                            "panel build does not support. Use the standalone "
                            "build instead.",
    "no free __TEXT": "There was not enough free space in the binary for the "
                      "panel. Use the standalone build instead.",
    "selectors missing": "This game build no longer exposes a selector the "
                         "panel needs. Use the standalone build instead.",
    "ldid": "Code signing failed. Re-run with --no-sign and let KSign do the "
            "signing.",
    "No space left": "Your disk is full. Free up space and try again.",
}


def clean_path(text):
    """Accept paths dragged into the terminal (quoted, with trailing space)."""
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    return os.path.expandvars(os.path.expanduser(text.strip()))


def ask(prompt, default=""):
    suffix = " [%s]" % default if default else ""
    try:
        answer = input("  %s%s: " % (prompt, suffix)).strip()
    except EOFError:
        print()
        raise SystemExit("No answer given. Pass the IPA path on the command "
                         "line instead.")
    return answer or default


def ask_yes(prompt, default=True):
    default_text = "Y/n" if default else "y/N"
    while True:
        answer = ask("%s [%s]" % (prompt, default_text)).lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  Please answer y or n.")


def ask_input_file():
    while True:
        answer = clean_path(ask("Drag your decrypted .ipa here and press Enter"))
        if not answer:
            print("  Nothing entered. Try again.")
            continue
        if os.path.isdir(answer):
            found = [os.path.join(answer, n) for n in sorted(os.listdir(answer))
                     if n.lower().endswith(".ipa")]
            if len(found) == 1:
                print("  Using %s" % os.path.basename(found[0]))
                return found[0]
            print("  That is a folder. Drag the .ipa file itself.")
            continue
        if not os.path.isfile(answer):
            print("  I cannot find that file. Check the path and try again.")
            continue
        if not answer.lower().endswith((".ipa", ".zip")):
            print("  That is not an .ipa or .zip file.")
            if not ask_yes("Use it anyway?", default=False):
                continue
        return answer


def ask_mode():
    print()
    print("  What should the patched game do?")
    print()
    print("    1) Always use the private server      (simplest, no menu)")
    print("    2) Let me choose at every launch      (small panel first)")
    print()
    while True:
        answer = ask("Choose 1 or 2", "1").lower()
        if answer in MODE_NAMES:
            return MODE_NAMES[answer]
        print("  Please type 1 or 2.")


def explain_error(exc):
    text = str(exc)
    print()
    print("  Could not patch this file.")
    print("  Reason: %s" % text)
    for needle, hint in HINTS.items():
        if needle.lower() in text.lower():
            print()
            print("  What to try: %s" % hint)
            break
    else:
        print()
        print("  If this keeps happening, run again with -v and share the "
              "output.")


def print_summary(res, mode):
    print()
    print(RULE)
    print("  DONE - your patched IPA is ready")
    print(RULE)
    print("  File   : %s" % res["output"])
    print("  Size   : %s" % pipeline.human_bytes(res["size"]))
    print("  SHA256 : %s" % res["sha256"])
    print()
    print("  What now?")
    print("    1) Install that IPA on your iPhone with KSign (or Sideloadly).")
    if mode == "toggle":
        print("    2) Open the game. Pick \"Grasscutter (private)\" or "
              "\"HoYoverse (official)\".")
        print("       Switching later restarts the game - that is normal.")
    else:
        print("    2) Open the game. It will always use the private server.")
    print()
    print("  A paid Apple Developer certificate is not required for the patch")
    print("  itself; a free Apple ID works for signing (it expires after 7 days).")
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Patch a decrypted Genshin Impact IPA for a private "
                    "server. With no arguments it asks you two questions.")
    ap.add_argument("input", nargs="?", help="decrypted Genshin Impact .ipa")
    ap.add_argument("-m", "--mode", choices=sorted(MODE_NAMES),
                    help="1/standalone = always private, 2/toggle = panel")
    ap.add_argument("-o", "--output", help="where to write the patched IPA")
    ap.add_argument("--key-file", help="XML <RSAKeyValue> of another server")
    ap.add_argument("--report-only", action="store_true",
                    help="only analyse, write nothing")
    ap.add_argument("--no-sign", action="store_true",
                    help="skip ldid (KSign will sign anyway)")
    ap.add_argument("--ldid", help="path to the ldid executable")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show every discovered address")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="never ask, use the given/default answers")
    ap.add_argument("--version", action="version",
                    version="Genshin RSA Patcher " + VERSION)
    args = ap.parse_args(argv)

    interactive = not args.yes
    print()
    print(RULE)
    print("  Genshin Impact - iOS RSA Patcher %s" % VERSION)
    print(RULE)
    print("  Makes a decrypted Genshin Impact IPA talk to a private server.")
    print()

    src = clean_path(args.input) if args.input else None
    if src and os.path.isdir(src):
        print("  That is a folder, not an IPA: %s" % src)
        src = None
    if src and not os.path.isfile(src):
        raise SystemExit("File not found: %s" % src)
    if not src:
        if not interactive:
            raise SystemExit("No IPA given. Usage: rsa_patch.py <game.ipa>")
        src = ask_input_file()

    if args.mode:
        mode = MODE_NAMES[args.mode]
    elif interactive:
        mode = ask_mode()
    else:
        mode = "standalone"

    out = os.path.abspath(args.output or pipeline.default_output(src, mode))
    print()
    print("  File : %s" % src)
    print("  Mode : %s" % MODE_TEXT[mode])
    print("  Out  : %s" % out)

    if os.path.exists(out) and not args.report_only:
        if not interactive:
            raise SystemExit("Output already exists: %s" % out)
        if not ask_yes("That output file already exists. Overwrite it?",
                       default=False):
            print("  Nothing was changed.")
            return 1

    need = os.path.getsize(src) + (1 << 30)
    free = pipeline.free_space(out)
    if free is not None and free < need and not args.report_only:
        print()
        print("  Warning: only %s free on that drive; about %s is needed."
              % (pipeline.human_bytes(free), pipeline.human_bytes(need)))
        if interactive and not ask_yes("Continue anyway?", default=False):
            print("  Nothing was changed.")
            return 1

    if interactive:
        print()
        if not ask_yes("Start patching now?", default=True):
            print("  Nothing was changed.")
            return 1
    print()

    try:
        res = pipeline.run(mode, src, out, args.key_file,
                           report_only=args.report_only,
                           sign=not args.no_sign, ldid=args.ldid,
                           overwrite=True, verbose=args.verbose)
    except G.PatchError as exc:
        explain_error(exc)
        return 2
    except zipfile.BadZipFile:
        print()
        print("  That file is not a valid IPA/zip archive.")
        return 2
    except OSError as exc:
        print()
        print("  A file error stopped the patch: %s" % exc)
        if getattr(exc, "errno", None) == 28:
            print("  Your disk is full - free some space and try again.")
        return 2
    except MemoryError:
        print()
        print("  Out of memory. Close other apps and try again.")
        return 2
    except KeyboardInterrupt:
        print()
        print("  Cancelled.")
        return 130

    if res["output"]:
        print_summary(res, mode)
    return 0


if __name__ == "__main__":
    sys.exit(main())
