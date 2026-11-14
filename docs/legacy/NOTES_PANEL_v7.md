# Genshin 7.1.0 — server toggle, panel v7 (blocking, pre-Unity)

Status: built, not yet device-tested.
Output: `GenshinImpact_7.1.0_Toggle_v7.ipa`
  3,265,920,625 bytes (3.04 GB), 842 entries
  SHA-256 `3BCA01C112717F3FF217A9E79E071DBEEF87C677D48980A91BD2CD36E9180A54`
  (uncompressed IPA, sign it with KSign before installing)

Device-confirmed backup (do not touch): `GenshinImpact_7.1.0_YuukiPS_patched_ldid.ipa`
— always YuukiPS, no panel.

---

## 1. What the panel does

On every launch, **before Unity initialises**, an alert asks which server to use:

```
Genshin server
Choose your server. Switching restarts the app.
[ YuukiPS (private) ]  [ HoYoverse (official) ]
```

* Tap the server that is **already active** → panel disappears, the game starts
  normally, nothing is written, nothing restarts. (A fresh launch is *not*
  needed when the key did not change.)
* Tap the **other** server → the choice is stored in `NSUserDefaults`, flushed,
  and the process calls `exit(0)`. The user relaunches and the game boots with
  the other key. This restart is unavoidable: see §5.
* Nobody taps for 60 s → the panel is dismissed and the game starts with the
  key that was applied at the start of the launch. **No key is ever wrong**,
  every path uses a complete, consistent key.

The panel only exists before Unity starts; there is no way to open it in game.

## 2. Why the hook is on `startUnity:`

`startUnity:` is **not** called directly from `didFinishLaunching`. The
controller schedules it:

```
[self performSelector:@selector(startUnity:) withObject:app afterDelay:0.0]
```

Verified call sites in `main` (both pass `d0 = 0.0` and a third object arg):

* `0x100017F6C` in `-[UnityAppController applicationDidBecomeActive:]`
* `0x1000184FC` in `-[UnityAppController requestUnityStart]`

So it runs on the **next main-run-loop turn, after `didFinishLaunching` has
returned**. At that moment:

* UIApplication's run loop is live → touch delivery works while we block;
* no launch watchdog is pending → blocking is safe;
* nothing of Unity exists yet → nothing can cover our window (this is exactly
  what killed v6, where the panel lived in `showGameUI` and was covered by
  Unity's view a frame later).

The one-shot byte at `0x11551A022` guards both call sites, so `startUnity:` can
never be scheduled twice per process, i.e. the panel cannot appear twice.

## 3. Binary layout

Only three regions of `main` are touched. No new load commands, no segment
changes, no protection changes.

| what | vm | file | section | size |
|---|---|---|---|---|
| payload code | `0x1000031C0` | `0x31C0` | `__TEXT` header padding | 2120 B (1528 B free) |
| official RSA key | `0x1139F34A8` | `0x139F34A8` | `__TEXT,__eh_frame` gap | 416 B |
| `startUnity:` IMP | `0x1152C58C0` | `0x152C58C0` | `__DATA` method list | 8 B |

`showGameUI`'s IMP (`0x1152C5680`) is deliberately **left stock**
(`0x1000195E0`); the injector asserts this so a stale v6 hook cannot survive.

The IMP field is covered by the dyld rebase table (checked by
`check_rebase.py` through `inject_main.py`), so the patched pointer survives
ASLR.

### Key slot

The seven RSA-key build sites read a pointer from a zero-filled `__DATA` slot
at `0x11604F000` (`+0`). `0` means "use the baked-in Yuuki key at file
`0x3020`", any other value is a VM address of a key string. Only `hook_start`
ever writes that slot, and it does so **before** `UnityInitApplication`, so all
seven sites see the same key.

### Scratch block (`__DATA` zero-fill tail at `0x11604F000`)

| off | use | off | use |
|---|---|---|---|
| `+0x000` | key slot (u64) | `+0x078..0x090` | NSStrings (title/msg/official/yuuki) |
| `+0x008` | panel-shown flag (u8) | `+0x098` | NSUserDefaults object |
| `+0x00C` | choice (u32) | `+0x0A0` | `@"keyswitch.mode"` |
| `+0x020` | global block (Yuuki) | `+0x0A8` | mode applied this launch |
| `+0x040` | global block (Official) | `+0x0B0` | `@"kCFRunLoopDefaultMode"` |
| `+0x060` | our UIWindow | `+0x0C0` | CGRect staged for the fallback |
| `+0x068` | root UIViewController | `+0x0E0` | double, panel start time |
| `+0x070` | UIAlertController | | |

## 4. The window must belong to the scene

This app is scene-based:

```
UIApplicationSceneManifest
  UIApplicationSupportsMultipleScenes = false
  UIWindowSceneSessionRoleApplication -> UISceneDelegateClassName = SceneDelegate
MinimumOSVersion = 13.0
```

`SceneDelegate` is Swift; `scene:willConnectToSession:options:` (`0x100008CA0`)
creates the app window with `[[UIWindow alloc] initWithWindowScene:]`
(`initWithWindowScene:` selref `0x11527B180`). On iOS 13+ a window created with
`initWithFrame:` in such an app **is never displayed** — the alert would be
invisible while the run loop is blocked, and the game would hang for 60 s on
every launch. So the payload builds its window with the same initialiser:

```
find_scene:  [UIApplication sharedApplication].connectedScenes.anyObject
window     = [[UIWindow alloc] initWithWindowScene:scene]
window.windowLevel = 2001.0            // UIWindowLevelAlert + 1
window.rootViewController = [[UIViewController alloc] init]
[window makeKeyAndVisible]
```

`find_scene` pumps the run loop (0.1 s slices, up to 20 = 2 s) while the scene
is not connected yet, and returns 0 if it never appears. If there is no scene,
the payload falls back to `initWithFrame:[UIScreen mainScreen].bounds` for a
legacy app; if there is no `UIScreen` either, the panel is skipped entirely and
startup continues (no exit, so no restart loop).

The one run-loop turn after `makeKeyAndVisible` is what lets the root view
controller appear and commit its layer tree before the alert is presented on it
(`presentViewController:animated:NO`).

Touch delivery works because the pump uses
`[[NSRunLoop currentRunLoop] runMode:@"kCFRunLoopDefaultMode" beforeDate:+0.1s]`
— the string is byte-identical to `NSDefaultRunLoopMode`, and touch events are
delivered in common modes.

Teardown: after the handler has unwound, the pump notices the choice and hides
the window (`setHidden:YES`), restoring the app's own window as key. UIKit is
never re-entered from inside the handler.

## 5. Why a restart is required to switch servers

The seven key build sites run inside `UnityInitApplication`, i.e. **after**
`startUnity:` returns. v5/v6 wrote the slot from a later hook (`showGameUI`)
and the engine ended up holding a mix of old and new keys — the server answered
`4214`. The key is baked into engine state during init and cannot be swapped in
place, so the choice is persisted and the process exits; the next launch applies
it in `apply_mode`, before Unity exists.

`choose` refuses to exit if `NSUserDefaults` or the key object is unavailable —
an exit without a persisted choice would loop the panel forever.

## 6. Build chain (Windows, no Mac)

```
python payload.py          # keystone -> payload.bin / payload.s / payload.json
python audit_payload.py    # every adrp/adr/ldr/branch target must be sane
python sim_payload.py      # Unicorn: 11 scenarios, mocked UIKit/ObjC runtime
python inject_main.py      # main_signed.bin -> main_patched.bin (3 regions)
copy main_patched.bin main_final.bin
ldid_w64_x86_64.exe -S main_final.bin     # keeps the file size
python repack_main.py <patched.ipa> GenshinImpact_7.1.0_Toggle_v7.ipa main_final.bin
```

`main_signed.bin` is the pristine ldid-signed, key-stubbed base (366,618,400 B);
every build starts from it, so builds are reproducible.

### Checks that gate the build

* `audit_payload.py` — 0 errors, `RESULT: OK` (58 branch targets, all absolute
  refs inside payload/`__TEXT`/known `__DATA` slots).
* `sim_payload.py` — `RESULT: PASS`, 11 scenarios:
  1. first launch, tap active server → key slot 0 at `startUnity:`, no write, no exit
  2. first launch, tap other server → one write of mode 2, `synchronize`, `exit(0)`, Unity never starts
  3. relaunch with mode 2 → official key in the slot before `startUnity:`, tap official → no restart
  4. switch back → persist 1 + exit; relaunch → Yuuki key before `startUnity:`
  5. panel ignored → 60 s failsafe, hide, `startUnity:` runs, slot unchanged
  6. no scene + no `UIScreen` → no alert, no exit, `startUnity:` still runs
  7. no scene → 20 pump slices, then `initWithFrame:` with `[UIScreen bounds]`
  8. scene connects late (4 turns) → retry pump finds it, scene path used
  9. `startUnity:` twice in one process → panel presented once, original runs twice
  10. no `NSUserDefaults` → cannot persist → continue, never exit
* `inject_main.py` — payload/key regions zero before the patch, `startUnity:` IMP
  rebased, `showGameUI` IMP stock, byte-for-byte verification after the write.

## 7. Signing / sideload

Sign the final IPA with the paid certificate (Team `DZNQ8CR9C8`) in KSign.
Runtime `__TEXT` patching is impossible under a distribution/Ad Hoc signature,
which is why the key blob and the code live in `__TEXT` as *static* content
signed with the rest of the binary, and only the `__DATA` IMP is rewritten.

## 8. What to check on the device

1. Cold launch → panel appears **before** the Unity splash and stays visible.
2. Tap the highlighted server → panel goes away, game boots, log in.
3. Tap the other server → app quits immediately (that is the restart).
   Relaunch → the game boots with the other server's key.
4. If login fails with `4214`, that is a key mismatch — report which button was
   tapped and the resulting mode, plus the `global-metadata` login log line.

Send back: which button was tapped, whether the panel stayed visible, whether
the app exited, and the crash report (`.ips`) if it does not launch.

## 9. v8 fix: wrong YuukiPS modulus (4214)

v7 always used the **wrong YuukiPS key**. It was taken from the AGP
"CustomServer" module (`5.8_Genshin_CustomServer_AGP_v3.4_OSREL_YuukiPS.apk` ->
`assets/lspatch/modules/xuoos.animegamesproxy.apk` ->
`lib/arm64-v8a/libtersafe3.so`, plain modulus string at `0x2B3DD0`), i.e. the
key of the **`com.yuuki.gios` custom-server client**, not of the public
`ps.yuuki.me` service the user logs into.

The two keys differ by exactly one base64 character in the modulus:

    ps.yuuki.me   ...i4TFG6mrxTKZpIcTInvPEpkK2A7Qsp1E4skFK8...
    com.yuuki.gios ...i4TFG6mrxTKZpIcRInvPEpkK2A7Qsp1E4skFK8...
                                          ^
One changed base64 char yields a different 2048-bit modulus, so the client
encrypted with a key the YuukiPS server does not hold -> handshake fails ->
the door screen reports **4214** ("Unable to connect to server"). The official
path was never affected, which is why HoYoverse login kept working.

Proof (device-confirmed reference): `GenshinImpact_7.1.0_YuukiPS_patched_ldid.ipa`
is byte-identical to `backup/GenshinImpact_7.1.0_YuukiPS_working_2026-11-10.ipa`;
assembling any of its seven public-key build sites yields the `...TInv...`
modulus (sha1 `2465eb23e62833251c8371c4cbf1ab8e26f1604c`). v7 baked the
`...RInv...` modulus (sha1 `da8f32e46338006973e8d958beb97622c7e77f86`).

Fix applied:

* `keypatch.py` - `YUUKI` restored to the canonical `...TInv...` modulus, with
  a comment saying where it must (and must not) come from.
* `main_signed.bin` - the 416-byte Yuuki blob at file `0x3020` rewritten with
  the canonical key (nothing else touched).
* `inject_main.py` - now asserts the baked blob equals `keypatch.YUUKI + NUL`,
  so a key swap can never pass silently again.
* `verify_v7.py` - now compares the *content* of both key blobs (Yuuki and
  official) against the canonical moduli, not just the `<RSAKeyValue>` prefix.

Build v8 (identical payload, only the Yuuki blob differs from v7):

    GenshinImpact_7.1.0_Toggle_v8.ipa
    size   3,265,920,622 bytes
    sha256 5cd237b78b6c217f59d02e8e34bd65445e28071c26f528169122bd264353cdf0
    gates  audit_payload OK (0 errors), sim_payload PASS (11 scenarios),
           inject_main RESULT OK (incl. canonical-key check),
           repack_main RESULT OK (842 entries), verify_v7 RESULT OK

