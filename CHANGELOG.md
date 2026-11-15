# Changelog

## 1.2.0 - 2026-11-15

Feature release for the toggle panel (`--mode 2`) and for sideloading.

### Added

* **Bundle identifier is now retagged to `com.yuuki.gios` by default.** The
  patched app can be installed next to the official client instead of
  replacing it. Only the main `Payload/GenshinImpact.app/Info.plist` is
  rewritten (XML or binary plist, format preserved); embedded frameworks and
  bundles keep their identifiers. Override with `--bundle-id ID`, or pass
  `--bundle-id ""` to keep the original.
* **The RSA panel is horizontal.** The two choices now sit side by side in one
  row, with the title and message above them, instead of a vertical
  `UIAlertController` list. The panel is a custom `UILabel` + `UIButton` layout
  sized from the screen and the current interface orientation, so it fits
  iPhone and iPad in portrait or landscape, and the button titles shrink to fit
  instead of truncating on narrow screens.
* **Button handlers are Objective-C methods, not blocks.** The panel registers
  `rsaPatchPickPrivate:` / `rsaPatchPickOfficial:` with `sel_registerName` and
  installs their IMPs on `UIViewController` with `class_addMethod`, then wires
  the buttons with `addTarget:action:forControlEvents:`. This drops the
  `__NSConcreteGlobalBlock` dependency and avoids `UIAction` (iOS 14+; the game
  still supports iOS 13).
* Tests for the horizontal layout, the runtime method registration, the
  scratch-slot map, plist rewriting (XML and binary) and entry replacement
  during repack.

### Fixed

* **Panel builds could close on launch with only a white screen.** Two
  `CALayer` messages were sent to the wrong receiver while the buttons were
  styled. `masksToBounds` is a `CALayer` property (`UIView` has
  `clipsToBounds`), and an earlier revision also reused the register that held
  the layer for the title label, so the send landed on a `UILabel`. Either way
  the app aborted with `unrecognized selector` before the panel drew its first
  frame. `setMasksToBounds:` is gone (a rounded layer background does not need
  it) and the title label now lives in its own register; a test pins both.
* **The panel laid out horizontally at the wrong width on first launch.** It
  measured `-window.bounds`, and a window created with
  `initWithWindowScene:` reports the scene's coordinate space, which can still
  be the launch orientation while the screen rotates. The panel then drew
  844 pt wide on a 390 pt wide screen and the buttons ran off the right edge.
  The size now comes from the screen (short/long side) with the axis taken from
  the window scene's `interfaceOrientation`, and the panel window is pinned to
  that frame. The wait loop re-checks the size every tick and moves the views
  if it changes, so rotating the phone while the panel is up is handled too.

### Changed

* The panel's scratch block now stores layout doubles (width, height, row
  position, button width) in the slots that used to hold the global blocks and
  alert controller. `SCRATCH_SIZE` is unchanged.
* The panel draws a translucent dark scrim, white title/message text and dark
  rounded buttons, so it stays readable over the Unity splash.

### Device status

| Version | Toggle panel | Always-private |
|---|---|---|
| 7.1.0 (1242) | not yet tested | not yet tested |
| 7.2.0 | 1.2.0 confirmed (`com.yuuki.gios`) | 1.2.0 confirmed (`com.yuuki.gios`) |

The 1.2.0 toggle panel was confirmed on a 7.2.0 build: it installs under
`com.yuuki.gios`, shows the horizontal picker with both choices on screen when
the phone is held upright, follows a rotation while the panel is up, and the
game starts in the chosen mode. The retag was verified on the same build.

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
