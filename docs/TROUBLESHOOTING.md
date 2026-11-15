# Troubleshooting

## Before anything else

* Is the IPA **decrypted**? An App Store download still has `cryptid = 1` and
  cannot be patched or even analysed.
* Is it really Genshin Impact? Other HoYoverse titles (Star Rail, ZZZ) do not
  use the same key construction.
* Are the packages installed?

  ```bash
  python -m pip install -r requirements.txt
  ```

* Is Python 3.10 or newer? Check with `python --version`.

---

## Error messages

| Message | Meaning | Fix |
|---|---|---|
| `this IPA is still encrypted` | FairPlay-encrypted App Store IPA | use a decrypted copy |
| `no Payload/*.app/Info.plist` | the file is not an IPA | pick the `.ipa`, not a folder or `.zip` of something else |
| `no public RSA key builds found` | wrong binary, encrypted binary, or the game changed its key construction | check the version note below |
| `this binary uses chained fixups` | newer Mach-O format | not supported yet; the scripts stop instead of writing a broken IPA |
| `-[…] uses a relative method list` | newer ObjC format | use the standalone build (`--mode 1`) |
| `no free __TEXT space` / `no …-byte free __TEXT space found` | binary layout leaves no room for the panel | use the standalone build |
| `selectors missing from __objc_selrefs` | the build no longer references a selector the panel needs | use the standalone build |
| `ldid failed` / `ldid grew the binary` | the bundled signer could not run | re-run with `--no-sign`; KSign signs the IPA anyway |
| `output already exists` | the target file is there | delete/rename it, or pass `-o other.ipa` |
| `repacked IPA did not verify` | the archive was modified while being read | close tools touching the IPA, retry |
| Signing app says it cannot extract the IPA | the source archive carried `META-INF/` / `decrypt.day` metadata, or ZIP64 records | builds from this version drop those; if it still happens, check free space on the iPhone |
| Installs, shows a white screen, then closes | the panel sent a selector to an object that does not implement it. Known cases: `setMasksToBounds:` sent to a `UIButton` (it is a `CALayer` property; `UIView` uses `clipsToBounds`), that selector's receiver register being reused for the title label, and older builds resolving `action` / `present` to lookalike Unity selectors | builds from this version no longer send `masksToBounds` at all and resolve selectors through the exact alias table; rebuild and reinstall |
| Installs with the new bundle ID, shows a white screen, then closes, while the original-ID build works | the retagged app starts with an empty container, and the game may bail out on its first launch | install the patched app, let it create its container, then reopen it; if it still closes, rebuild with `--bundle-id ""` to keep `com.miHoYo.GenshinImpact` |
| Panel appears shifted right with the buttons cut off | the layout used `-window.bounds`, which follows the scene's launch coordinate space rather than the displayed orientation | builds from this version size the panel from the screen plus the scene's `interfaceOrientation` and re-lay out whenever the size changes; rebuild and reinstall |

### "Installs, then the app closes before the panel"

A crash before the panel appears means the panel called `objc_msgSend` with a
selector that exists in the binary but is not implemented by the receiver. The
selector table only proves the *string* is somewhere in the app — `CALayer`
methods are in there too — so the receiver class matters:

* `setCornerRadius:` must go to the button's **layer**, not to the `UIButton`,
  and the layer must stay in its register until the send. The panel does not use
  `setMasksToBounds:` at all.
* `action` and `present` exist in Unity but are not the UIKit methods the panel
  wants, so short names go through `SEL_ALIASES` and are never guessed.

The horizontal panel installs its two button methods
(`rsaPatchPickPrivate:` / `rsaPatchPickOfficial:`) at runtime with
`class_addMethod`, so it does not depend on `UIAction` or blocks. If a future
game version triggers this again, run `--report-only -v` and check the selector
list it prints.

### "The app installs, but replaces the official Genshin"

That is the bundle identifier: 1.2.0 retags the app to `com.yuuki.gios` by
default, which is a *different* app ID from `com.miHoYo.GenshinImpact`. If your
signing tool still installs over the official client, check that KSign used the
new identifier and not the old one. Pass `--bundle-id ""` if you deliberately
want the original identifier back.

A new identifier also means a **new app container**: iOS will not reuse data
from a build installed under another bundle ID, so the game downloads its
resources again. That is normal and not a patch failure.

### "The panel is sideways / buttons overlap"

The 1.2.0 panel is a single row of two buttons sized from the window's
`-bounds`. Rebuild with the current scripts; older prebuilt IPAs still carry the
vertical alert. If a future iOS changes button metrics, the panel is still
readable but the titles shrink; report the version and window size.

### "No public RSA key builds found"

In order of likelihood:

1. the IPA is encrypted (most common);
2. it is another game;
3. the build changed how it builds keys — in that case the key discovery in
   `gipatch.find_key_builds()` needs updating. Run with `--report-only -v` and
   open an issue with the printed output.

---

## Install / launch problems

**KSign refuses to install.** Re-sign the IPA in KSign with your certificate;
the bundled `ldid` signature is only a placeholder. Make sure the certificate
is valid and the device is registered.

**Installs but closes immediately.** Sign with `--no-sign` and let KSign do the
whole signature, then reinstall. Also check the IPA came from a build you did
not interrupt.

**Handshake fails, error 4214, "connection failed".** The client key does not
match the server. Pass the server's own key with `--key-file`. Grasscutter
servers usually publish theirs; the built-in key is YuukiPS'.

**Official mode returns to the panel every launch.** That is expected: the
panel appears before the game starts, every launch. Pick the mode you want each
time; the game uses the stored value immediately.

**Panel does not show at all.** It is part of the toggle build only, and it
appears before Unity initialises. If the screen is black/white for a moment and
then the game starts, the panel was missed or was dismissed after the 60 s
fail-safe. The stored mode was used.

**Free Apple ID build expired (7 days).** Re-sign and reinstall; the patch
itself is unaffected. A paid developer certificate removes the 7-day limit.

---

## Runtime and disk

* Patching: ~40 s. Repacking: ~5 min for 3.2 GB / 842 entries.
* Need roughly twice the IPA size free.
* Antivirus can slow the repack down substantially; exclude the output folder
  if it crawls.

---

## Checking a build

```bash
python rsa_patch.py game.ipa --mode toggle --report-only -v
```

prints the discovered key builds, the panel hook, the scratch area and the GOT
slots without writing anything. Useful to confirm a new game version is still
supported before spending time on a full repack.
