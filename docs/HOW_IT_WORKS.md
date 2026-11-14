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
code calls through: `objc_msgSend`, `objc_getClass`, `dlsym` and
`__NSConcreteGlobalBlock`. Selectors are loaded from `__objc_selrefs` instead
of from string literals, so no `__cstring` space is needed; the generator
accepts both `foo:` and `foo` spellings (`SEL_ALIASES`).

The panel shows a `UIAlertController` with the two choices, blocks in short
run-loop slices until a button is pressed, and falls back to the stored mode
after 60 seconds so a missed tap cannot hang the app.

**Hook.** `gipatch.ObjC` walks `__objc_classlist` → class → method list →
`startUnity:` entry, checks that the IMP field is rebased by dyld (it is), and
points it at the panel code. The panel saves `x0`–`x8`, `x19`, `x20` and `x30`,
runs, restores them and tail-calls the original IMP with `br x16`, so Unity
starts exactly as before.

Mode switching writes `rsapatch.mode` to `NSUserDefaults`, calls
`synchronize`, and `exit(0)`. The next launch reads it before any key string is
built.

---

## 5. Verification

Before anything is written:

* every rewritten/stubbed site is re-emulated;
* the toggle stubs are run under Unicorn: slot 0 must yield your key, slot 1 the
  shipped key (7.1 and 7.2 both checked);
* the standalone change set must match the expected instruction lanes exactly.

After writing:

* archive entry list and order are compared with the source IPA;
* every other entry's CRC and size must be unchanged;
* the written main binary must equal the patched bytes and the zip CRCs must be
  valid;
* the written IPA is re-read: the hook, panel bytes, both key blobs and every
  stub are checked again.

If any check fails the output file is deleted.

---

## 6. Failure modes it refuses

| Condition | Why |
|---|---|
| `LC_DYLD_CHAINED_FIXUPS` | classic bind/rebase walking is what the discovery relies on; chained fixups change the format |
| relative ObjC method lists | the IMP field would not be rebased, so the hook would be lost |
| `cryptid != 0` | encrypted text cannot be disassembled meaningfully |
| no free `__TEXT` space | the panel code would overwrite live code |
| missing selectors | the panel would call a selector the app never registers |

Each of these raises a message explaining what happened instead of producing an
IPA that crashes on device.

---

## 7. Signing

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

## 8. Performance

Patching itself takes about 40 seconds on a 3.2 GB IPA. Repacking dominates:
every entry is recompressed, roughly 5 minutes for 842 entries on a modern SSD.
Plan for ~2× the IPA size in free disk space.
