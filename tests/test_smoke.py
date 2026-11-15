"""Smoke tests - no game files required.

    python -m unittest discover -s tests
"""
import os
import plistlib
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
        # them crashed the old alert.  The alias table must always win.
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
        self.assertIn("addTarget:action:forControlEvents:", requested)
        self.assertIn("buttonWithType:", requested)
        self.assertIn("setTitle:forState:", requested)
        self.assertIn("titleLabel", requested)
        self.assertIn("setAdjustsFontSizeToFitWidth:", requested)

    def test_horizontal_layout_uses_two_buttons_in_one_row(self):
        cfg = panel_cfg()
        built = panel.build_panel(cfg)
        asm = built["asm"]
        # two separate UIButton instances, both added to the controller's view
        btn = built["labels"]["cstr_UIButton"]
        seq = "adrp x0, 0x%x\nadd x0, x0, #0x%x" % (btn & ~0xFFF, btn & 0xFFF)
        self.assertEqual(asm.count(seq), 2)
        self.assertEqual(asm.count("ldr x3, [x22, #0x%x]" % panel.S_SEL_P), 1)
        self.assertEqual(asm.count("ldr x3, [x22, #0x%x]" % panel.S_SEL_O), 1)
        # the second button is offset to the right of the first
        self.assertIn("fadd d4, d3, d2", asm)
        self.assertIn("str d4, [x22, #0x%x]" % panel.S_LX2, asm)
        # no vertical UIAlertController remains
        self.assertNotIn("UIAlertController", built["blob"].decode("latin-1"))
        self.assertNotIn("UIAlertAction", built["blob"].decode("latin-1"))
        self.assertNotIn(b"NSConcreteGlobalBlock", built["blob"])

    def test_panel_size_follows_the_displayed_orientation(self):
        # `initWithWindowScene:` gives the window the scene's coordinate space,
        # fixed at creation.  While the interface rotates that space can still
        # be landscape (844x390) on a portrait screen (390x844), and a layout
        # from -window.bounds then pushes the right-hand button off the edge.
        # The size therefore comes from the screen (short/long side) and the
        # axis from the scene's interfaceOrientation.
        cfg = panel_cfg()
        built = panel.build_panel(cfg)
        asm = [line.strip() for line in built["asm"].splitlines()]
        start = asm.index("panel_size:")
        end = asm.index(".Lps_ret:")
        block = asm[start:end]

        self.assertIn("fmin d4, d2, d3", block)                  # short side
        self.assertIn("fmax d5, d2, d3", block)                  # long side
        self.assertIn("cmp w0, #2", block)                       # 1/2 = portrait
        self.assertIn("b.hi .Lps_have", block)                   # 3/4 = landscape
        for name in ("mainScreen", "bounds", "windowScene",
                     "interfaceOrientation"):
            vm = cfg["sel"][name]
            pair = ["adrp x9, 0x%x" % (vm & ~0xFFF),
                    "ldr x9, [x9, #0x%x]" % (vm & 0xFFF)]
            joined = "\n".join(block)
            self.assertIn("\n".join(pair), joined,
                          "%s is not sent from panel_size" % name)
        # portrait -> width = short side, landscape -> width = long side
        self.assertIn("fmov d0, d4", block)
        self.assertIn("fmov d0, d5", block)

    def test_relayout_pins_the_window_and_moves_every_view(self):
        # relayout() is the single place that turns a size into frames: it
        # pins the panel window, recomputes the scalars and re-frames the four
        # subviews, so a size change (rotation) is followed in place.
        cfg = panel_cfg()
        built = panel.build_panel(cfg)
        asm = [line.strip() for line in built["asm"].splitlines()]
        start = asm.index("relayout:")
        end = asm.index(".Lrl_ret:")
        block = asm[start:end]

        send = "ldr x9, [x9, #0x%x]" % (cfg["sel"]["setFrame:"] & 0xFFF)
        sends = [i for i, line in enumerate(block) if line == send]
        # one for the window, four for the subviews
        self.assertEqual(len(sends), 5)
        self.assertLess(block.index("ldr x0, [x22, #0x%x]" % panel.S_WINDOW),
                        sends[0])
        self.assertIn("cbz x0, .Lrl_math", block[sends[0] - 8:sends[0]])
        for slot in (panel.S_V_TITLE, panel.S_V_MSG, panel.S_V_PRIV,
                     panel.S_V_OFF):
            self.assertIn("ldr x0, [x22, #0x%x]" % slot, block)

        # the wait loop re-checks the size every tick
        loop = asm[asm.index(".Lp_loop:"):asm.index(".Lp_choice:")]
        self.assertIn("bl relayout_if_needed", loop)
        self.assertLess(loop.index("bl relayout_if_needed"),
                        loop.index("bl pump_once"))
        # ... and only re-lays out when the size really moved
        check = asm[asm.index("relayout_if_needed:"):
                    asm.index("now_seconds:")]
        self.assertIn("fabs d4, d4", check)
        self.assertIn("fcmp d4, d6", check)
        self.assertIn("bl relayout", check)

    def test_views_are_registered_for_re_framing(self):
        cfg = panel_cfg()
        built = panel.build_panel(cfg)
        asm = [line.strip() for line in built["asm"].splitlines()]
        for slot in (panel.S_V_TITLE, panel.S_V_MSG, panel.S_V_PRIV,
                     panel.S_V_OFF):
            # zeroed on entry, then filled by make_label/make_button
            self.assertIn("str xzr, [x22, #0x%x]" % slot, asm)
            store = [line for line in asm
                     if line in ("str x21, [x22, #0x%x]" % slot,
                                 "str x23, [x22, #0x%x]" % slot)]
            self.assertTrue(store, "view slot %#x is never filled" % slot)

    def test_layer_send_is_not_clobbered_before_corner_radius(self):
        # setCornerRadius: / setMasksToBounds: are CALayer methods; sending one
        # of them to a UIButton or UILabel raises "unrecognized selector" and
        # kills the app before the panel draws (white launch screen, then
        # close).  The panel now sends only cornerRadius, to the layer in x21,
        # and keeps the title label in x24 so it cannot reuse x21 in between.
        cfg = panel_cfg()
        built = panel.build_panel(cfg)
        asm = [line.strip() for line in built["asm"].splitlines()]

        self.assertNotIn("setMasksToBounds", panel.SEL_ALIASES)
        # SelMap records every selector the panel asks to resolve, so this
        # proves the message is never even looked up.  (It must go through
        # dict.keys: SelMap.__contains__ is a stub that accepts anything.)
        self.assertNotIn("setMasksToBounds:", dict.keys(cfg["sel"]))
        self.assertNotIn(b"setMasksToBounds", built["blob"])

        def uses(sel_name):
            ldr = "ldr x9, [x9, #0x%x]" % (cfg["sel"][sel_name] & 0xFFF)
            return [i for i, line in enumerate(asm) if line == ldr]

        layers = uses("layer")
        radii = uses("setCornerRadius:")
        self.assertEqual(len(layers), 2)
        self.assertEqual(len(radii), 2)
        for radius in radii:
            layer = max(i for i in layers if i < radius)
            seg = asm[layer:radius]
            # the layer arrives in x0, is parked in x21, and stays there
            self.assertIn("mov x21, x0", seg)
            parked = max(i for i, line in enumerate(asm) if line == "mov x21, x0"
                         and layer < i < radius)
            writes = [l for l in asm[parked + 1:radius]
                      if l.startswith(("mov x21,", "ldr x21,", "add x21,"))]
            self.assertEqual(writes, [],
                             "x21 must still hold the layer at setCornerRadius:")

        # the title label must live in x24 so it cannot clobber the layer
        titles = uses("titleLabel")
        shrinks = uses("setAdjustsFontSizeToFitWidth:")
        self.assertEqual(len(titles), 2)
        self.assertEqual(len(shrinks), 2)
        for shrink in shrinks:
            title = max(i for i in titles if i < shrink)
            seg = asm[title:shrink]
            self.assertIn("mov x24, x0", seg)
            self.assertNotIn("mov x21,", seg)
            self.assertIn("mov x0, x24", asm[shrink - 4:shrink])

    def test_button_handlers_are_registered_objc_methods(self):
        cfg = panel_cfg()
        built = panel.build_panel(cfg)
        blob = built["blob"]
        for text in (b"sel_registerName", b"class_addMethod",
                     panel.SEL_PICK_PRIVATE.encode(),
                     panel.SEL_PICK_OFFICIAL.encode(),
                     panel.METHOD_TYPES.encode()):
            self.assertIn(text, blob)
        # the IMPs must be labels inside the blob
        self.assertIn("pick_private", built["labels"])
        self.assertIn("pick_official", built["labels"])

    def test_unaligned_scratch_is_addressed_exactly(self):
        cfg = panel_cfg()
        cfg["scratch"] = 0x100023A0
        built = panel.build_panel(cfg)
        self.assertEqual(built["asm"].count("adrp x22, 0x10002000"), 3)
        self.assertEqual(built["asm"].count("add x22, x22, #0x3a0"), 3)

    def test_scratch_layout_fits(self):
        # gipatch reserves SCRATCH_SIZE bytes for the panel's state block
        self.assertLessEqual(panel.S_T0 + 8, panel.SCRATCH_SIZE)
        self.assertLessEqual(panel.S_V_OFF + 8, panel.SCRATCH_SIZE)
        self.assertEqual(panel.SCRATCH_SIZE, 0x100)

    def test_scratch_slots_do_not_overlap(self):
        slots = {
            "S_KEY": (panel.S_KEY, 8),
            "S_SHOWN": (panel.S_SHOWN, 1),
            "S_CHOICE": (panel.S_CHOICE, 4),
            "S_V_TITLE": (panel.S_V_TITLE, 8),
            "S_V_MSG": (panel.S_V_MSG, 8),
            "S_LW": (panel.S_LW, 8),
            "S_LH": (panel.S_LH, 8),
            "S_LTY": (panel.S_LTY, 8),
            "S_LMY": (panel.S_LMY, 8),
            "S_LY": (panel.S_LY, 8),
            "S_LBW": (panel.S_LBW, 8),
            "S_LX2": (panel.S_LX2, 8),
            "S_LWD": (panel.S_LWD, 8),
            "S_WINDOW": (panel.S_WINDOW, 8),
            "S_VC": (panel.S_VC, 8),
            "S_SEL_P": (panel.S_SEL_P, 8),
            "S_S_TITLE": (panel.S_S_TITLE, 8),
            "S_S_MSG": (panel.S_S_MSG, 8),
            "S_S_OFFICIAL": (panel.S_S_OFFICIAL, 8),
            "S_S_PRIVATE": (panel.S_S_PRIVATE, 8),
            "S_DEFAULTS": (panel.S_DEFAULTS, 8),
            "S_KEYOBJ": (panel.S_KEYOBJ, 8),
            "S_MODE": (panel.S_MODE, 8),
            "S_RUNMODE": (panel.S_RUNMODE, 8),
            "S_SEL_O": (panel.S_SEL_O, 8),
            "S_T0": (panel.S_T0, 8),
            "S_V_PRIV": (panel.S_V_PRIV, 8),
            "S_V_OFF": (panel.S_V_OFF, 8),
        }
        spans = sorted((off, off + size, name)
                       for name, (off, size) in slots.items())
        for (a0, a1, an), (b0, b1, bn) in zip(spans, spans[1:]):
            self.assertLessEqual(a1, b0, "%s overlaps %s" % (an, bn))

    def test_window_is_pinned_to_the_measured_size(self):
        # the size travels in d0/d1 from panel_size to relayout and is then
        # handed to the window as {0, 0, W, H}; no scratch CGRect is needed.
        built = panel.build_panel(panel_cfg())
        asm = [line.strip() for line in built["asm"].splitlines()]
        block = asm[asm.index("relayout:"):asm.index(".Lrl_ret:")]
        self.assertEqual(block[1:9], [
            "sub sp, sp, #0x10",
            "stp x29, x30, [sp, #0x00]",
            "bl panel_size",
            "fcmp d0, #0.0",
            "b.le .Lrl_ret",
            "fcmp d1, #0.0",
            "b.le .Lrl_ret",
            "str d0, [x22, #0x20]",
        ])
        self.assertIn("fmov d2, d0", block)
        self.assertIn("fmov d3, d1", block)
        self.assertIn("fmov d0, xzr", block)
        self.assertIn("fmov d1, xzr", block)

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


class TestBundleId(unittest.TestCase):
    def test_xml_round_trip(self):
        raw = plistlib.dumps({"CFBundleIdentifier": "com.old", "Keep": 1})
        out = G.rewrite_bundle_id(raw, "com.yuuki.gios")
        self.assertNotEqual(raw, out)
        info = plistlib.loads(out)
        self.assertEqual(info["CFBundleIdentifier"], "com.yuuki.gios")
        self.assertEqual(info["Keep"], 1)
        self.assertFalse(out.startswith(b"bplist00"))

    def test_binary_round_trip_preserves_format(self):
        raw = plistlib.dumps({"CFBundleIdentifier": "com.old"},
                             fmt=plistlib.FMT_BINARY)
        out = G.rewrite_bundle_id(raw, "com.yuuki.gios")
        self.assertTrue(out.startswith(b"bplist00"))
        self.assertEqual(plistlib.loads(out)["CFBundleIdentifier"],
                         "com.yuuki.gios")

    def test_empty_or_same_keeps_bytes(self):
        raw = plistlib.dumps({"CFBundleIdentifier": "com.old"})
        self.assertEqual(G.rewrite_bundle_id(raw, ""), raw)
        self.assertEqual(G.rewrite_bundle_id(raw, None), raw)
        same = plistlib.dumps({"CFBundleIdentifier": "com.yuuki.gios"})
        self.assertEqual(G.rewrite_bundle_id(same, "com.yuuki.gios"), same)

    def test_pipeline_default(self):
        self.assertEqual(pipeline.DEFAULT_BUNDLE_ID, "com.yuuki.gios")


class TestRepackReplace(unittest.TestCase):
    def test_replaces_info_plist_and_verifies(self):
        app = "Payload/Game.app"
        info = plistlib.dumps({"CFBundleIdentifier": "com.old"})
        new_info = G.rewrite_bundle_id(info, "com.yuuki.gios")
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in.ipa")
            dst = os.path.join(tmp, "out.ipa")
            with zipfile.ZipFile(src, "w") as z:
                z.writestr(app + "/", b"")
                z.writestr(app + "/Info.plist", info)
                z.writestr(app + "/Game", b"OLD")
            G.repack(src, dst, app + "/Game", b"NEW", progress=False,
                     replace={app + "/Info.plist": new_info})
            with zipfile.ZipFile(dst) as z:
                self.assertEqual(z.read(app + "/Game"), b"NEW")
                self.assertEqual(z.read(app + "/Info.plist"), new_info)
            self.assertTrue(G.verify_repack(
                src, dst, app + "/Game", b"NEW",
                replace={app + "/Info.plist": new_info}))
            self.assertFalse(G.verify_repack(
                src, dst, app + "/Game", b"NEW",
                replace={app + "/Info.plist": info}))


if __name__ == "__main__":
    unittest.main()
