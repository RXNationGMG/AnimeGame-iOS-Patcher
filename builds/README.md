# Builds

This folder is where the patcher writes prebuilt IPAs, but **no game files are
shipped here**: they are copyrighted, huge, and ignored by git.

Build your own from a decrypted IPA:

```bash
python rsa_patch.py <decrypted.ipa> --mode 1   # always private
python rsa_patch.py <decrypted.ipa> --mode 2   # pre-game panel
```

With the default settings the output lands next to the input IPA. Pass `-o
builds/<name>.ipa` (or use the CLI wrappers) if you want it in this folder.

Install the result with KSign or Sideloadly; the bundled `ldid` signature is
only a placeholder.

After building, check the file is intact:

```bash
sha256sum <file>
# Windows
certutil -hashfile <file> SHA256
```
