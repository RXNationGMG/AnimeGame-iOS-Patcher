# How it works

This is the "why does it survive new game versions" document. Nothing here is
needed to use the patcher.

---

## 1. The key is built, not stored

Genshin's client does not keep the RSA public key in `__TEXT` as a ready-made
string. Each protocol path builds it at runtime:

```
movz  w8, #'<', lsl #0
movk  w8, #'R', lsl #16
...
strb  w8, [x20, #0x10]
```

followed by `movz`/`movk` + `str`/`stp` pairs that assemble the whole
`<RSAKeyValue><Modulus>…</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>`
string (416 bytes) into a buffer. In 7.1 and 7.2 there are seven such builds:
seven public-key paths plus six private-key paths that are left untouched.

So a patch is not "find a string and replace it". It has to understand the
instruction run that produces the string.

---

## 2. Finding the builds

`gipatch.find_key_builds()` disassembles the main binary with Capstone and
looks for runs of instructions whose 16-bit immediates, concatenated in
register order, look like an XML key:

1. collect candidate runs (`movz`/`movk` into the same register, then a
   store), at least 60 instructions long;
2. emulate the run into its destination buffer (`assemble_run`);
3. keep it if the produced text starts with `<RSAKeyValue>` and ends with
   `</RSAKeyValue>`;
4. classify **public** (`<Exponent>` present, no `<D>`) vs **private**.

The span of instructions belonging to each build (`key_span`) is derived from
the same emulation, so the patcher knows exactly which bytes to touch.

This is why there are no offsets in the source: on 7.1.0 the seven builds sit
at `0x3F6300 … 0x398528C`, on 7.2.0 at `0x6235694 … 0x68D5060`. Same code.

---

## 3. Standalone build

For each public build the patcher rewrites the 16-bit lanes of the `movz` /
`movk` immediates (`rewrite_build_key`) so the run assembles your key instead
of HoYoverse's. Every changed byte is inside the original instruction run: no
code is added, no cave is used, no branches are touched.

Afterwards the run is re-emulated and must produce exactly the requested key,
and the total change set is compared against the expected instruction lanes —
any stray byte aborts the run (`unexpected bytes changed`).

---

## 4. Toggle build

Three things are added.

**Stubs.** Each public build's instruction span is overwritten with a stub
(`build_stub`):

```
adrp x9, scratch
add  x9, x9, #(slot * 16)
ldp  q0, q1, [x9]          ; 32 bytes of key ...
...                        ; ... copied to the build's own buffer
b    <after the build>
```

`slot 0` holds your key, `slot 1` the key the installed build shipped with.
Because the shipped key is read back from the binary's own public builds, no
key material is hard-coded, and "official" really is whatever that build
shipped with. The stubs tolerate the differing scratch usage of each site: the
`__DATA` zero-fill tail is used as scratch (`writable_zero_gap`), and every
register the stub clobbers is one the original run did not need afterwards.

**Panel.** `panel.py` assembles a small Objective-C panel with Keystone in free
`__TEXT` padding (`_space_for`), and `_load_panel` resolves the GOT slots the
code calls through: `objc_msgSend`, `objc_getClass` and `dlsym`. Selectors are
loaded from `__objc_selrefs` instead of from string literals, so no `__cstring`
space is needed. Every short name goes through the exact-match `SEL_ALIASES`
table: Unity itself has selectors called `action` and `present`, so a name that
is merely present in the binary would pick the wrong slot and crash with
`unrecognized selector`.

The panel is a custom horizontal picker: a `UILabel` title, a `UILabel` message
and two `UIButton`s side by side, laid out from the displayed size
(margin 24, gap 12, button height 56). `UIAlertController` is deliberately not
used because its actions are always stacked vertically. Button titles are set on
`button.titleLabel` with `adjustsFontSizeToFitWidth`, so
"Grasscutter (private)" stays on one line on narrow phones.

The size is decided in one place, `relayout()`. It takes the two side lengths
from `[UIScreen mainScreen] -bounds`, asks the panel window's scene for
`interfaceOrientation` and picks width = long side when the interface is
landscape (3/4) or short side when it is portrait (1/2), pins the panel window to
`{0, 0, width, height}` and then re-frames the labels and buttons. Measuring
`-window.bounds` instead is wrong: a window created with
`initWithWindowScene:` keeps the scene's coordinate space, which can still be
the launch orientation (844x390) while the glass shows 390x844, so the panel
laid out 844 pt wide and the right-hand button ran off the edge. The wait loop
probes the size every tick and calls `relayout()` again if it moved by more than
0.5 pt, so a rotation while the panel is up is followed instead of leaving the
row half off-screen.

Rounded corners go through the button's **layer**, never the button:
`setCornerRadius:` is a `CALayer` method, and its receiver must stay in one
register until the send. `setMasksToBounds:` is not used at all — a rounded
layer background does not need it, and sending it to a `UIButton` (or to a
`UILabel` that reused the register) raises `unrecognized selector` and kills the
app before the first frame.

`UIButton` target-action needs a `SEL`, and these methods do not exist in the
game, so the panel calls `sel_registerName("rsaPatchPickPrivate:" / "…Official:")`
and installs the two IMPs (`pick_private`, `pick_official`) on
`UIViewController` with `class_addMethod`. That avoids blocks
(`__NSConcreteGlobalBlock`) and `UIAction`, which requires iOS 14 while this
build's minimum is iOS 13. The buttons are wired with
`addTarget:action:forControlEvents:` (`UIControlEventTouchUpInside` = 64).

The panel blocks in short run-loop slices until a button is pressed, and falls
back to the stored mode after 60 seconds so a missed tap cannot hang the app.

**Hook.** `gipatch.ObjC` walks `__objc_classlist` → class → method list →
`startUnity:` entry, checks that the IMP field is rebased by dyld (it is), and
points it at the panel code. The panel saves `x0`–`x8`, `x19`, `x20` and `x30`,
runs, restores them and tail-calls the original IMP with `br x16`, so Unity
starts exactly as before.

Mode switching writes `rsapatch.mode` to `NSUserDefaults`, calls
`synchronize`, and `exit(0)`. The next launch reads it before any key string is
built.

---

## 5. Bundle identifier

Both builds retag the main app so it can coexist with the official client. The
default is `com.yuuki.gios`; `--bundle-id ""` keeps whatever the source IPA
shipped with. Only `Payload/<app>.app/Info.plist` is rewritten — embedded
bundles and frameworks keep their own identifiers.

`gipatch.rewrite_bundle_id` loads the plist with `plistlib`, sets
`CFBundleIdentifier`, and writes it back in the same format it was read in
(XML or binary). The replacement bytes go through the same `repack` /
`verify_repack` path as the main binary, so the archive entry list and order
stay untouched and the written plist is compared byte for byte.

---

## 6. Verification

Before anything is written:

* every rewritten key build is re-emulated and must produce the requested key;
* the panel may only use selector slots that hold the *exact* selector it calls
  — `action` and `present` also exist as real selectors in Unity, so a short
  name is resolved through `SEL_ALIASES` and never guessed from the binary;
* the panel and the key stubs must address the same scratch block (the stubs
  read the slot the panel writes);
* the standalone change set must match the expected instruction lanes exactly.

After writing:

* archive entry list and order are compared with the source IPA;
* every untouched entry's CRC and size must be unchanged;
* the rewritten `Info.plist` must contain the requested bundle identifier;
* the written main binary must equal the patched bytes and the zip CRCs must be
  valid;
* the written IPA is re-read: the hook, panel bytes, both key blobs and every
  stub are checked again.

If any check fails the output file is deleted.

---

## 7. Failure modes it refuses

| Condition | Why |
|---|---|
| `LC_DYLD_CHAINED_FIXUPS` | classic bind/rebase walking is what the discovery relies on; chained fixups change the format |
| relative ObjC method lists | the IMP field would not be rebased, so the hook would be lost |
| `cryptid != 0` | encrypted text cannot be disassembled meaningfully |
| no free `__TEXT` space | the panel code would overwrite live code |
| missing selectors | the panel would call a selector the app never registers |
| panel loads a lookalike selector (`action`, `present`) | those exist in Unity but are not the UIKit methods the panel calls, so it would crash with `unrecognized selector` |
| panel state is not addressed from the scratch block | an unaligned scratch base without the matching `add` writes over live `__DATA` |

Each of these raises a message explaining what happened instead of producing an
IPA that crashes on device.

---

## 8. Signing
`ldid -S` replaces the shipped (App Store) code signature of the main binary
with an ad-hoc one so dyld accepts the modified binary; KSign/Sideloadly then
re-sign the whole IPA with a real certificate. This is why the main binary
shrinks slightly (the App Store signature block is larger than an ad-hoc one) —
only signature bytes differ from an unsigned build.

ldid puts the signed file's name into the signature, so the pipeline signs a
copy with a fixed name (`<binary>.bin`) inside a private temp directory. That
keeps rebuilds byte-identical; nothing about it reaches the device, because
KSign replaces the signature anyway.

---

## 9. Archive packaging

Repacking copies every entry in its original order. The patched main binary and
(when the bundle identifier is changed) the main app's `Info.plist` are the only
entries whose bytes differ.

Two things are normalised while repacking so that on-device signing tools
accept the result:

* **Packaging-only entries are dropped.** Some IPA sources carry Apple Archive
  Utility metadata (`META-INF/com.apple.ZipMetadata.plist`,
  `META-INF/com.apple.FixedZipMetadata.bin`) and service markers such as
  `Payload/decrypt.day`. iOS never reads any of them, and at least one popular
  on-device signer fails to extract archives that contain them.
* **No ZIP64.** Python switches to ZIP64 once offsets pass 2 GiB, even though
  plain 32-bit fields work up to 4 GiB. `strip_zip64()` rewrites the central
  directory and end record with 32-bit values (and removes the ZIP64 extra
  fields), so the archive looks exactly like a store-issued IPA. If a future
  archive really needed ZIP64 the function refuses instead of corrupting it.

## 10. Performance

Patching itself takes about 40 seconds on a 3.2 GB IPA. Repacking dominates:
every entry is recompressed, roughly 5 minutes for 842 entries on a modern SSD.
Plan for ~2× the IPA size in free disk space.
