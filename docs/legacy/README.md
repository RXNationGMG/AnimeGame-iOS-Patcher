# Legacy material (historical, not used by the current code)

These files are kept for provenance only. The current toolkit lives in the
repository root (`gipatch.py`, `panel.py`, `pipeline.py`, `rsa_patch.py`).

| File | What it was |
|---|---|
| `NOTES_PANEL_v7.md` | Design notes for the hand-built v7 panel and the root cause of the v8 crash that the current generator fixed. |
| `payload.py`, `sim_payload.py` | The first panel generator; assembled a panel payload against hard-coded addresses. |
| `inject_main.py`, `keypatch.py` | Early hand-written patchers for the first build (fixed offsets, manual key rewrite). |
| `repack_main.py`, `audit_payload.py`, `verify_v7.py` | Throwaway repack/verification helpers. |

Nothing here is imported by the current scripts and nothing here is needed to
build an IPA. They are leftovers from reverse-engineering the first
device-confirmed build.
