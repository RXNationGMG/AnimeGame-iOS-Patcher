"""Smoke tests - no game files required.

    python -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest
import zipfile

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


class TestZipNormalise(unittest.TestCase):
    def _handmade_zip64(self, path):
        """One stored entry, written with ZIP64 records by hand."""
        import struct
        import zlib

        name = b"a.txt"
        data = b"hi"
        crc = zlib.crc32(data) & 0xFFFFFFFF
        local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 45, 0, 0, 0, 0x21,
                            crc, len(data), len(data), len(name), 0) + name
        body = local + data
        cd_off = len(body)
        extra = struct.pack("<HHQQQ", 0x0001, 24, len(data), len(data),
                            0)  # entry offset is 0
        central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 45, 45, 0, 0,
                              0, 0x21, crc, 0xFFFFFFFF, 0xFFFFFFFF,
                              len(name), len(extra), 0, 0, 0, 0x81A40000,
                              0xFFFFFFFF) + name + extra
        cd = cd_off
        z64 = struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, 1, 1,
                          len(central), cd)
        loc = struct.pack("<IIQI", 0x07064B50, 0, cd + len(central), 1)
        eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0)
        with open(path, "wb") as f:
            f.write(body + central + z64 + loc + eocd)

    def test_strip_zip64_keeps_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.zip")
            self._handmade_zip64(path)
            self.assertTrue(G.strip_zip64(path))
            with zipfile.ZipFile(path) as z:
                self.assertEqual(z.namelist(), ["a.txt"])
                self.assertEqual(z.read("a.txt"), b"hi")
                self.assertIsNone(z.testzip())
            self.assertFalse(G.strip_zip64(path))

    def test_packaging_noise(self):
        self.assertTrue(pipeline.packaging_noise("META-INF/"))
        self.assertTrue(pipeline.packaging_noise("META-INF/com.apple.ZipMetadata.plist"))
        self.assertTrue(pipeline.packaging_noise("Payload/decrypt.day"))
        self.assertFalse(pipeline.packaging_noise("Payload/GenshinImpact.app/Info.plist"))


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

    def test_alias_beats_lookalike_selector(self):
        # Unity really has selectors called `action` and `present`; picking
        # them crashes with "unrecognized selector".
        sel = {
            "action": 0x100010000,
            "present": 0x100020000,
            "actionWithTitle:style:handler:": 0x100030000,
            "presentViewController:animated:completion:": 0x100040000,
        }
        self.assertEqual(panel.resolve_sel(sel, "action"),
                         "actionWithTitle:style:handler:")
        self.assertEqual(panel.resolve_sel(sel, "present"),
                         "presentViewController:animated:completion:")

    def test_payload_uses_no_lookalike_selectors(self):
        cfg = panel_cfg()
        panel.build_panel(cfg)
        requested = set(dict.keys(cfg["sel"]))
        self.assertNotIn("action", requested)
        self.assertNotIn("present", requested)
        self.assertIn("actionWithTitle:style:handler:", requested)
        self.assertIn("presentViewController:animated:completion:", requested)

    def test_unaligned_scratch_is_addressed_exactly(self):
        cfg = panel_cfg()
        cfg["scratch"] = 0x100023A0
        built = panel.build_panel(cfg)
        self.assertEqual(built["asm"].count("adrp x22, 0x10002000"), 3)
        self.assertEqual(built["asm"].count("add x22, x22, #0x3a0"), 3)

    def test_scratch_layout_fits(self):
        # gipatch reserves SCRATCH_SIZE bytes for the panel's state block
        self.assertLessEqual(panel.S_T0 + 8, panel.SCRATCH_SIZE)
        self.assertEqual(panel.SCRATCH_SIZE, 0x100)

    def test_cgrect_return_covers_both_conventions(self):
        built = panel.build_panel(panel_cfg())
        # CGRect is an HFA of four doubles: d0-d3 is the real return path.
        for i, off in enumerate((0xC0, 0xC8, 0xD0, 0xD8)):
            self.assertIn("str d%d, [x22, #0x%x]" % (i, off), built["asm"])
        # the indirect buffer is also set, in case a callee uses x8
        self.assertIn("add x8, x22, #0xc0", built["asm"])

    def test_code_base_moves(self):
        a = panel.build_panel(panel_cfg(0x100003000))
        b = panel.build_panel(panel_cfg(0x100005000))
        # same size, different adrp/immediate targets
        self.assertEqual(len(a["blob"]), len(b["blob"]))
        self.assertNotEqual(a["blob"], b["blob"])


class TestBuildGuards(unittest.TestCase):
    """gipatch must refuse to emit the two device-crash regressions."""

    def test_slots_are_decoded(self):
        asm = "adrp x9, 0x10002000\nldr x9, [x9, #0x1f8]"
        self.assertEqual(G._panel_slots(asm), [0x100021f8])

    def test_rejects_lookalike_selector_slot(self):
        built = panel.build_panel(panel_cfg())
        lookalike = "adrp x9, 0x10002000\nldr x9, [x9, #0x100]"
        fake = {"asm": built["asm"] + "\n" + lookalike}
        with self.assertRaises(G.PatchError):
            G._guard_panel(fake, {"action": 0x10002100}, 0x100023A0)

    def test_rejects_unrebased_scratch(self):
        built = panel.build_panel(panel_cfg())
        asm = built["asm"].replace("add x22, x22, #0x3a0\n", "")
        with self.assertRaises(G.PatchError):
            G._guard_panel({"asm": asm}, {}, 0x100023A0)

    def test_accepts_the_real_panel(self):
        cfg = panel_cfg()
        built = panel.build_panel(cfg)
        G._guard_panel(built, cfg["sel"], cfg["scratch"])


if __name__ == "__main__":
    unittest.main()
