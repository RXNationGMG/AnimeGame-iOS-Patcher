# Prebuilt IPAs (not part of the git repository)

These files are **ignored by git** on purpose: game binaries are copyrighted
and far too large for a repository. They are kept here so the build that was
tested on device can be reinstalled without re-running the patcher.

| File | What it is |
|---|---|
| `com.miHoYo.GenshinImpact_7.1.0_und3fined_RSApatch_standalone.ipa` | Always-private build produced by this toolkit (7.1.0). |
| `com.miHoYo.GenshinImpact_7.1.0_und3fined_RSApatch_toggle.ipa` | Panel build produced by this toolkit (7.1.0), current strings. |
| `GenshinImpact_7.1.0_Toggle_v8.ipa` | Device-confirmed panel build kept as a fallback. |

Install with KSign (or Sideloadly): the bundled `ldid` signature is only a
placeholder, KSign re-signs the IPA with your certificate.

`SHA256SUMS.txt` lets you confirm a copy is intact:

```bash
sha256sum -c SHA256SUMS.txt
# Windows
certutil -hashfile <file> SHA256
```

To rebuild any of them from your own decrypted IPA:

```bash
python rsa_patch.py <decrypted.ipa> --mode 1   # standalone
python rsa_patch.py <decrypted.ipa> --mode 2   # toggle
```
