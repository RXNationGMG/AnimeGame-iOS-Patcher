# Changelog

## 1.1.0 - 2026-11-15

Bug-fix release for the pre-game panel build (`--mode 2` / toggle).

### Fixed

* **Panel crashed right after launch (white screen, then close).** The panel
  asked `__objc_selrefs` for `action` and `present`, which are real selectors in
  Unity but not the methods it wanted. It now resolves every short name through
  the exact `SEL_ALIASES` table, so it calls
  `actionWithTitle:style:handler:` and
  `presentViewController:animated:completion:`.
* **Panel state could land outside its reserved block.** The scratch area is
  only 16-byte aligned, but the panel addressed it by page alone. It now emits
  the matching `add x22, x22, #low`, the same address the key stubs read, so the
  selected mode is always the key the game boots with.
* **Fallback window could be zero-sized.** `CGRect` is an HFA of four doubles:
  iOS returns it in `d0-d3`. The frame is now stored from those registers (and
  from the `x8` buffer, for safety).
* **KSign could not extract the built IPA.** Packaging-only entries
  (`META-INF/*`, `Payload/decrypt.day`) are dropped and the tail is rewritten
  without ZIP64 records, producing the plain 32-bit layout KSign expects.

### Added

* Build-time guards in `gipatch.patch_toggle`: it refuses to emit a panel that
  loads a lookalike selector or uses a scratch page without rebasing it.
* Regression tests for both crashes, the `CGRect` return path, the scratch
  layout and the ZIP64 rewriter.
* `.gitattributes` so the Windows launcher keeps CRLF while everything else is
  checked out with LF.
* Panel internals and troubleshooting entries for the white-screen failure.

### Device status

| Version | Toggle panel | Always-private |
|---|---|---|
| 7.1.0 (1242) | confirmed | confirmed |
| 7.2.0 | confirmed | confirmed |
