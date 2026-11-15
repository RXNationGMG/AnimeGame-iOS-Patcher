# Genshin Impact iOS — RSA Patcher

Patch a **decrypted** Genshin Impact IPA so the client accepts a private
server's RSA key (Grasscutter, YuukiPS, or your own).

* **Simple.** One command, or double-click `START_HERE.bat` and answer two
  questions.
* **Version independent.** No game addresses are hard-coded: every patch site,
  code cave, key blob and Objective-C method is found inside the binary, so new
  Genshin releases work without editing anything.
* **Verified.** Every run re-reads what it wrote and refuses to leave a broken
  IPA behind.
* **Reproducible.** The same input and options produce the same IPA bytes.

---

## What you need

| | |
|---|---|
| A computer | Windows, macOS or Linux |
| Python | 3.10 or newer (Windows: tick **Add python.exe to PATH** when installing) |
| The game | a **decrypted** Genshin Impact `.ipa` (not the App Store download) |
| To install | KSign, Sideloadly, or any other sideload tool |

A paid Apple Developer certificate is **not** needed to run the patcher. It is
also not needed to install: a free Apple ID works, it just expires after 7 days.

Encrypted App Store IPAs cannot be patched — decrypt the game first.

---

## Quick start

### Windows

1. Install Python from [python.org](https://www.python.org/downloads/)
   (**tick "Add python.exe to PATH"**).
2. Double-click **`START_HERE.bat`**. The first run installs the few packages it
   needs.
3. Drag your decrypted `.ipa` into the window, press Enter.
4. Type `1` (always private) or `2` (choose at launch), press Enter.
5. Wait. The patched IPA is written next to the original and the window shows
   where it is.

### macOS / Linux

```bash
./start.sh
```

### Any OS, command line

```bash
pip install -r requirements.txt

python rsa_patch.py game.ipa                  # asks which build
python rsa_patch.py game.ipa --mode toggle    # panel build
python rsa_patch.py game.ipa --mode 1 -y      # always private, no questions
```

---

## The two builds

| Build | Behaviour |
|---|---|
| **Standalone** (`--mode 1`) | Always uses the private key. No menu, no extra code — the key immediates in the binary are rewritten in place. |
| **Toggle** (`--mode 2`) | Shows a small panel before Unity starts: **Grasscutter (private)** or **HoYoverse (official)**. Switching restarts the app. |

The toggle panel is presented from `-[UnityAppController startUnity:]`, i.e.
before the engine draws anything, so it cannot be skipped or covered by the
game:

```
RSA Patch Selection
Choose your RSA Patch. Switching requires you to restart the app.

  Grasscutter (private)
  HoYoverse (official)
```

The choice is stored in `NSUserDefaults` as `rsapatch.mode` (`1` = private,
`2` = official). The official choice uses the key the installed build shipped
with, read from the binary itself — nothing is hard-coded.

---

## Using your own server key

```bash
python rsa_patch.py game.ipa --mode 1 --key-file my_server_key.xml
```

The file must contain one `<RSAKeyValue>…</RSAKeyValue>` block (the thing a
private server operator usually hands out). Whitespace and line breaks are
fine. Without `--key-file` the built-in Grasscutter / YuukiPS key is used.

---

## Options

`rsa_patch.py`:

| Option | Meaning |
|---|---|
| `-m`, `--mode 1\|2` | `1`/`standalone` = always private, `2`/`toggle` = panel |
| `-o`, `--output PATH` | where to write the patched IPA |
| `-y`, `--yes` | never ask, use the given/default answers |
| `--key-file FILE` | install another server's `<RSAKeyValue>` |
| `--report-only` | analyse and print the discovered sites, write nothing |
| `--no-sign` | skip the included `ldid` step (KSign will sign anyway) |
| `--ldid PATH` | use a specific `ldid` binary |
| `-v`, `--verbose` | print every discovered address |

`patch_standalone.py` and `patch_toggle.py` accept the same input, output and
switches (minus `--mode`) if you prefer one script per build type:

```bash
python patch_toggle.py game.ipa [output.ipa] [--report-only] [--no-sign] ...
```

`bin/ldid_w64_x86_64.exe` is bundled for Windows so the patched main binary is
ad-hoc signed before repacking. On macOS/Linux install `ldid` in `PATH`
(`brew install ldid` / `apt install ldid`) or pass `--ldid`.

---

## Output

Default names, written next to the input:

```
<name>_RSApatch_standalone.ipa
<name>_RSApatch_toggle.ipa
```

Only the app's main executable is replaced. Every other archive entry is copied
through byte for byte with the original entry order, and the result is verified:
entry list, CRCs, and the patched bytes are re-read from the written IPA.

Two packaging tweaks are applied on purpose, because some on-device signing
tools refuse the raw archives they come from:

* packaging-only entries are dropped — Apple Archive Utility metadata
  (`META-INF/…`) and `Payload/decrypt.day` markers, neither of which iOS reads;
* the archive is rewritten without ZIP64 records (plain 32-bit zip), since the
  data fits and on-device extractors are not always compiled with ZIP64 support.

The output therefore has the same layout as a store-issued IPA.

---

## Troubleshooting

**"This IPA is still encrypted"** — the file is the App Store download. You
need a decrypted copy.

**"No public RSA key builds found"** — the file is not Genshin Impact, is
encrypted, or the game changed how it builds keys. The last case is the only
one this project cannot handle automatically; see
[docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

**App installs but the handshake fails / error 4214** — the key does not match
your server. Pass the server's key with `--key-file`.

**The panel does not appear** — it is shown by the pre-game build only, and
only for a few seconds before Unity starts. It disappears once the game is
running (by design).

More in [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

---

## How it works

Genshin does not store the RSA key in the file; it builds the key string at
runtime from `movz`/`movk` immediates, once per protocol path. The patcher scans
the binary for those immediate runs, classifies each as public or private, then:

* **standalone** — rewrites only the immediates of the public builds, so the
  patched code produces exactly the key you asked for;
* **toggle** — replaces every public build with a small stub that copies the
  key from a runtime-selected blob, adds the panel code in free `__TEXT`
  padding, stores both key blobs next to it, and repoints the `startUnity:` IMP
  at the panel hook.

Everything else — free code space, scratch memory, the ObjC method list, the
GOT slots for `objc_msgSend` / `objc_getClass` / `dlsym` /
`__NSConcreteGlobalBlock`, and the selector refs — is discovered per binary.

Details: [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

---

## Version support

| Version | Status |
|---|---|
| 7.1.0 (1242) | Full build; both modes device-confirmed. |
| 7.2.0 | Full build; both modes device-confirmed. |

The scripts refuse binaries using **chained fixups**
(`LC_DYLD_CHAINED_FIXUPS`) or relative ObjC method lists. All 7.x builds use the
classic `LC_DYLD_INFO_ONLY` format. If a future release changes format the
patcher stops with a clear message instead of producing a broken IPA.

---

## Repository layout

```
rsa_patch.py          friendly front-end (start here)
pipeline.py           the patch + verify pipeline used by every entry point
gipatch.py            Mach-O parsing, key discovery, patches, repack
panel.py              the Objective-C panel generator
patch_standalone.py   CLI wrapper: always-private build
patch_toggle.py       CLI wrapper: panel build
START_HERE.bat        double-click launcher (Windows)
start.sh              launcher (macOS/Linux)
bin/                  bundled ldid (Windows)
docs/                 internals and troubleshooting
tests/                smoke tests (no game files needed)
builds/               prebuilt example IPAs - NOT tracked by git
```

`builds/*.ipa` is ignored on purpose: game binaries are copyrighted and must
never be committed. Use the scripts on your own decrypted copy.

---

## Credits and licence

MIT — see [LICENSE](LICENSE).

Not affiliated with HoYoverse or Cognosphere. Only patch IPAs you legally own,
and only connect to servers you are allowed to use.
