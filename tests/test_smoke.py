"""Smoke tests - no game files required.

    python -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import gipatch as G                                          # noqa: E402
import panel                                                 # noqa: E402
import pipeline                                              # noqa: E402
import rsa_patch                                             # noqa: E402


class SelMap(dict):
    """Accept any selector name and hand out a fake __objc_selrefs address."""

    def __init__(self, base=0x100004000):
        super().__init__()
        self._next = base

    def __contains__(self, key):
        return True

    def __getitem__(self, key):
        if key not in dict.keys(self):
            dict.__setitem__(self, key, self._next)
            self._next += 8
        return dict.__getitem__(self, key)


def panel_cfg(code_base=0x100003000):
    return {
        "code_base": code_base,
        "orig_start": 0x10001774C,
        "scratch": 0x100020000,
        "got_msgsend": 0x1139F9B70,
        "got_getclass": 0x1139F9B48,
        "got_dlsym": 0x1139F8C40,
        "got_globalblock": 0x1139F8B90,
        "sel": SelMap(),
    }


class TestKeyFile(unittest.TestCase):
    def test_built_in_key(self):
        text, desc = pipeline.load_key()
        self.assertEqual(text, G.GRASSCUTTER_KEY)
        self.assertIn("built-in", desc)
        self.assertEqual(len(text), 415)

    def test_accepts_line_breaks(self):
        wrapped = G.GRASSCUTTER_KEY.replace("><", ">\n  <")
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(wrapped)
            name = f.name
        try:
            text, desc = pipeline.load_key(name)
            self.assertEqual(text, G.GRASSCUTTER_KEY)
            self.assertEqual(desc, name)
        finally:
            os.unlink(name)

    def test_rejects_garbage(self):
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write("not a key")
            name = f.name
        try:
            with self.assertRaises(G.PatchError):
                pipeline.load_key(name)
        finally:
            os.unlink(name)


class TestNames(unittest.TestCase):
    def test_default_output(self):
        self.assertTrue(pipeline.default_output("a/b.ipa", "standalone")
                        .endswith("b_RSApatch_standalone.ipa"))
        self.assertTrue(pipeline.default_output("a/b.zip", "toggle")
                        .endswith("b_RSApatch_toggle.ipa"))
        self.assertTrue(pipeline.default_output("a/b.ipa", "toggle")
                        .endswith("b_RSApatch_toggle.ipa"))

    def test_human_bytes(self):
        self.assertEqual(pipeline.human_bytes(512), "512 bytes")
        self.assertEqual(pipeline.human_bytes(1536), "1.50 KiB")

    def test_mode_aliases(self):
        self.assertEqual(rsa_patch.MODE_NAMES["1"], "standalone")
        self.assertEqual(rsa_patch.MODE_NAMES["2"], "toggle")
        self.assertEqual(rsa_patch.MODE_NAMES["t"], "toggle")

    def test_dragged_path_is_cleaned(self):
        self.assertEqual(rsa_patch.clean_path('  "C:\\a b\\x.ipa"  '),
                         "C:\\a b\\x.ipa")


class TestPipelineGuards(unittest.TestCase):
    def test_missing_input(self):
        with self.assertRaises(G.PatchError):
            pipeline.run("standalone", "does-not-exist.ipa")

    def test_bad_mode(self):
        with self.assertRaises(ValueError):
            pipeline.run("nonsense", "does-not-exist.ipa")


class TestPanel(unittest.TestCase):
    def test_builds_and_is_deterministic(self):
        a = panel.build_panel(panel_cfg())
        b = panel.build_panel(panel_cfg())
        blob = a["blob"]
        self.assertGreater(len(blob), 512)
        self.assertEqual(len(blob) % 4, 0)
        self.assertEqual(blob, b["blob"])
        self.assertIn(panel.TITLE.encode(), blob)
        self.assertIn(panel.LABEL_PRIVATE.encode(), blob)
        self.assertIn(panel.LABEL_OFFICIAL.encode(), blob)
        self.assertIn(panel.MODE_KEY.encode(), blob)
        self.assertTrue(a["asm"])

    def test_code_base_moves(self):
        a = panel.build_panel(panel_cfg(0x100003000))
        b = panel.build_panel(panel_cfg(0x100005000))
        # same size, different adrp/immediate targets
        self.assertEqual(len(a["blob"]), len(b["blob"]))
        self.assertNotEqual(a["blob"], b["blob"])


if __name__ == "__main__":
    unittest.main()
