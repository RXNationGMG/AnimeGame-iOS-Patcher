#!/usr/bin/env python3
"""Toggle build: choose the key from a panel before the game starts.

    python patch_toggle.py <decrypted.ipa> [output.ipa] [options]

New here?  Run `python rsa_patch.py` instead - it asks two questions and does
the same thing.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pipeline                                              # noqa: E402

if __name__ == "__main__":
    pipeline.cli("toggle")
