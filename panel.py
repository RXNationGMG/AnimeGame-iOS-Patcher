import struct

try:
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
except ImportError:                                     # older/odd builds
    from keystone.keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

S_KEY = 0x000        # u64 0 = replacement key, 1 = shipped key
S_SHOWN = 0x008      # u8  panel already presented in this process
S_CHOICE = 0x00C     # u32 0 = none yet, else the mode the user picked
S_V_TITLE = 0x010    # UILabel* title, re-framed when the size changes
S_V_MSG = 0x018      # UILabel* message
S_LW = 0x020         # f64 width the panel is laid out for (see relayout)
S_LH = 0x028         # f64 height the panel is laid out for
S_LTY = 0x030        # f64 y of the title label
S_LMY = 0x038        # f64 y of the message label
S_LY = 0x040         # f64 y of the button row
S_LBW = 0x048        # f64 width of one button
S_LX2 = 0x050        # f64 x of the right-hand button
S_LWD = 0x058        # f64 width of the labels
S_WINDOW = 0x060
S_VC = 0x068
S_SEL_P = 0x070      # SEL for the private button's target-action
S_S_TITLE = 0x078
S_S_MSG = 0x080
S_S_OFFICIAL = 0x088
S_S_PRIVATE = 0x090
S_DEFAULTS = 0x098
S_KEYOBJ = 0x0A0
S_MODE = 0x0A8
S_RUNMODE = 0x0B0
S_SEL_O = 0x0B8      # SEL for the official button's target-action
S_T0 = 0x0E0
S_V_PRIV = 0x0E8     # UIButton* private, re-framed when the size changes
S_V_OFF = 0x0F0      # UIButton* official

MODE_PRIVATE = 1
MODE_OFFICIAL = 2

WINDOW_LEVEL = 2001.0    # UIWindowLevelAlert + 1
TICK = 0.1
PANEL_CAP = 60.0
LAYOUT_EPS = 0.5         # pt; a size change bigger than this re-lays out

# Layout of the horizontal picker (points).  Two buttons share one row; the
# title and message sit above it, centred.
MARGIN = 24.0
GAP = 12.0
BUTTON_H = 56.0
BUTTON_ROW_DY = 20.0
TITLE_H = 30.0
TITLE_DY = 92.0          # title y = button row y - TITLE_DY
MSG_H = 40.0
MSG_DY = 52.0            # message y = button row y - MSG_DY

TITLE = "RSA Patch Selection"
MSG = "Choose your RSA Patch. Switching requires you to restart the app."
LABEL_OFFICIAL = "HoYoverse (official)"
LABEL_PRIVATE = "Grasscutter (private)"
MODE_KEY = "rsapatch.mode"
RUNMODE = "kCFRunLoopDefaultMode"

# The two button handlers are Objective-C methods added to UIViewController at
# runtime.  UIButton target-action needs a SEL, so these names are registered
# with sel_registerName(); the IMPs live in the panel blob.
SEL_PICK_PRIVATE = "rsaPatchPickPrivate:"
SEL_PICK_OFFICIAL = "rsaPatchPickOfficial:"
METHOD_TYPES = "v@:@"

# Friendly short names used by the payload -> exact selector text in the binary.
# Every name the payload uses is listed here, including the ones whose short
# form is already a real selector.  That matters: `action` and `present` exist
# as selectors in Unity, so guessing by name returns the wrong `selref` and the
# game dies with "unrecognized selector" if such a name is ever reused.
SEL_ALIASES = {
    # Kept deliberately: these names exist as *different* real selectors in
    # Unity, so any payload that ever asks for the short form must still get
    # the exact UIKit method rather than the lookalike.
    "alert": "alertControllerWithTitle:message:preferredStyle:",
    "action": "actionWithTitle:style:handler:",
    "present": "presentViewController:animated:completion:",
    "setIntegerForKey": "setInteger:forKey:",
    "stringWithUTF8String": "stringWithUTF8String:",
    "integerForKey": "integerForKey:",
    "initWithFrame": "initWithFrame:",
    "initWithWindowScene": "initWithWindowScene:",
    "setWindowLevel": "setWindowLevel:",
    "setRootViewController": "setRootViewController:",
    "setHidden": "setHidden:",
    "dateWithTimeIntervalSinceNow": "dateWithTimeIntervalSinceNow:",
    "standardUserDefaults": "standardUserDefaults",
    "alloc": "alloc",
    "init": "init",
    "makeKeyAndVisible": "makeKeyAndVisible",
    "mainScreen": "mainScreen",
    "bounds": "bounds",
    "synchronize": "synchronize",
    "sharedApplication": "sharedApplication",
    "connectedScenes": "connectedScenes",
    "anyObject": "anyObject",
    "windowScene": "windowScene",
    "interfaceOrientation": "interfaceOrientation",
    "currentRunLoop": "currentRunLoop",
    "runMode:beforeDate:": "runMode:beforeDate:",
    "date": "date",
    "timeIntervalSinceReferenceDate": "timeIntervalSinceReferenceDate",
    # horizontal picker
    "buttonWithType": "buttonWithType:",
    "setFrame": "setFrame:",
    "setTitle": "setTitle:forState:",
    "setTitleColor": "setTitleColor:forState:",
    "addTarget": "addTarget:action:forControlEvents:",
    "setText": "setText:",
    "setTextColor": "setTextColor:",
    "setFont": "setFont:",
    "titleLabel": "titleLabel",
    "setAdjustsFontSizeToFitWidth": "setAdjustsFontSizeToFitWidth:",
    "setNumberOfLines": "setNumberOfLines:",
    "setTextAlignment": "setTextAlignment:",
    "systemFontOfSize": "systemFontOfSize:",
    "boldSystemFontOfSize": "boldSystemFontOfSize:",
    "colorWithWhite": "colorWithWhite:alpha:",
    "whiteColor": "whiteColor",
    "addSubview": "addSubview:",
    "view": "view",
    "setBackgroundColor": "setBackgroundColor:",
    "layer": "layer",
    "setCornerRadius": "setCornerRadius:",
    # deliberately no setMasksToBounds: it is a CALayer property, and the one
    # place it was used (the button border) is not worth an unrecognized
    # selector crash before the first frame.
}


def resolve_sel(sel, name):
    """Map a payload selector name to the exact key used by `selrefs`.

    The alias table always wins, so a short name that also happens to be a
    different real selector (`action`, `present`) can never resolve to it.
    Full selector names are still accepted verbatim.
    """
    if name in SEL_ALIASES:
        alias = SEL_ALIASES[name]
        return alias if alias in sel else None
    if name in sel:
        return name
    return None

SCRATCH_SIZE = 0x100


class Asm:
    """Emit instructions/data while tracking the pc so labels are known
    before the assembler runs."""

    def __init__(self, base):
        self.lines = []
        self.pc = base
        self.labels = {}
        self.base = base

    def __call__(self, insn):
        assert ":" not in insn, insn
        self.lines.append(insn)
        self.pc += 4

    def many(self, insns):
        for i in insns:
            self(i)

    def adr(self, reg, target):
        """Register address of `target` (keystone has no `adr`).  The label is
        resolved once every label has a pc."""
        self.lines.append(("ADR", reg, target))
        self.pc += 8

    def label(self, name):
        assert name not in self.labels, "duplicate label %s" % name
        self.labels[name] = self.pc
        self.lines.append(name + ":")

    def emit(self, name, blob):
        self.label(name)
        self.lines.append(".byte " + ",".join("0x%02x" % x for x in blob))
        self.pc += len(blob)

    def cstr(self, name, s):
        self.emit(name, s.encode() + b"\x00")

    def align(self, n=8):
        while self.pc % n:
            self.lines.append(".byte 0x00")
            self.pc += 1


def build_panel(p):
    """Assemble the panel.  `p` keys:

    code_base, got_msgsend, got_getclass, got_dlsym, scratch,
    sel (dict name -> vm), title, message, label_private, label_official,
    mode_key, runmode (optional)
    """
    code_base = p["code_base"]
    scratch = p["scratch"]
    sel = p["sel"]
    got_msg = p["got_msgsend"]
    got_cls = p["got_getclass"]
    got_dlsym = p["got_dlsym"]
    title = p.get("title", TITLE)
    msg = p.get("message", MSG)
    label_private = p.get("label_private", LABEL_PRIVATE)
    label_official = p.get("label_official", LABEL_OFFICIAL)
    mode_key = p.get("mode_key", MODE_KEY)
    runmode = p.get("runmode", RUNMODE)

    a = Asm(code_base)

    def ldsel(name):
        """adrp/ldr a SEL from its __objc_selrefs slot into x9."""
        key = resolve_sel(sel, name)
        if key is None:
            raise SystemExit("selector %r not present in __objc_selrefs" % name)
        addr = sel[key]
        page = addr & ~0xFFF
        off = addr & 0xFFF
        assert off % 8 == 0
        return ["adrp x9, 0x%x" % page, "ldr x9, [x9, #0x%x]" % off]

    def ldslot(addr, reg):
        page = addr & ~0xFFF
        off = addr & 0xFFF
        assert off % 8 == 0 and off <= 0xFF8, "slot %#x not addressable in one page" % addr
        return ["adrp x9, 0x%x" % page, "ldr %s, [x9, #0x%x]" % (reg, off)]

    scratch_low = scratch & 0xFFF

    def load_scratch(reg="x22"):
        """Point `reg` at the scratch block itself, not at its page base.

        The scratch block is only 16-byte aligned, so the low 12 bits have to
        be added back; otherwise every state slot lands up to 0xFFF bytes
        before the reserved gap and writes over live __DATA.
        """
        out = ["adrp %s, 0x%x" % (reg, scratch & ~0xFFF)]
        if scratch_low:
            out.append("add %s, %s, #0x%x" % (reg, reg, scratch_low))
        return out

    def load_double(dreg, src):
        """Load a double from ("slot", off) in scratch or ("const", label)."""
        kind, val = src
        if kind == "const":
            a.adr("x9", val)
            a("ldr d%d, [x9]" % dreg)
        else:
            a("ldr d%d, [x22, #0x%x]" % (dreg, val))

    def init_frame(xsrc, ysrc, wsrc, hsrc):
        """Put CGRect{x,y,w,h} into d0-d3 for initWithFrame:/setFrame:."""
        load_double(0, xsrc)
        load_double(1, ysrc)
        load_double(2, wsrc)
        load_double(3, hsrc)

    def add_to_vc_view(reg):
        """[self.vc.view addSubview:reg]; leaves the view in x0."""
        a("ldr x0, [x22, #0x%x]" % S_VC)
        a.many(ldsel("view"))
        a("mov x1, x9")
        a("blr x19")
        a("cbz x0, .Lp_bail")
        a("mov x2, %s" % reg)
        a.many(ldsel("addSubview"))
        a("mov x1, x9")
        a("blr x19")

    # ======================= the hook ====================================
    a.label("hook_start")
    a("sub sp, sp, #0x70")
    a("stp x0, x1, [sp, #0x00]")
    a("stp x2, x3, [sp, #0x10]")
    a("stp x4, x5, [sp, #0x20]")
    a("stp x6, x7, [sp, #0x30]")
    a("stp x8, x30, [sp, #0x40]")
    a("stp x19, x20, [sp, #0x50]")
    a("bl apply_mode")
    a("bl panel")
    a("ldp x19, x20, [sp, #0x50]")
    a("ldp x8, x30, [sp, #0x40]")
    a("ldp x6, x7, [sp, #0x30]")
    a("ldp x4, x5, [sp, #0x20]")
    a("ldp x2, x3, [sp, #0x10]")
    a("ldp x0, x1, [sp, #0x00]")
    a("add sp, sp, #0x70")
    orig = p["orig_start"]
    a("adrp x16, 0x%x" % (orig & ~0xFFF))
    a("add x16, x16, #0x%x" % (orig & 0xFFF))
    a("br x16")                          # tail call into the original IMP

    # ======================= mode -> key slot =============================
    a.label("apply_mode")
    a("sub sp, sp, #0x40")
    a("stp x19, x20, [sp, #0x00]")
    a("stp x21, x22, [sp, #0x10]")
    a("stp x23, x24, [sp, #0x20]")
    a("stp x25, x30, [sp, #0x30]")
    a.many(ldslot(got_msg, "x19"))
    a.many(ldslot(got_cls, "x20"))
    a.many(load_scratch())
    a("mov x21, #0")
    a("mov w23, #%d" % MODE_PRIVATE)
    a("str xzr, [x22, #0x%x]" % S_KEYOBJ)
    a("str xzr, [x22, #0x%x]" % S_DEFAULTS)

    a.adr("x0", "cstr_NSUserDefaults")
    a("blr x20")
    a("cbz x0, .Lam_apply")
    a.many(ldsel("standardUserDefaults"))
    a("mov x1, x9")
    a("blr x19")
    a("mov x21, x0")
    a("cbz x21, .Lam_apply")

    a.adr("x0", "cstr_NSString")
    a("blr x20")
    a("cbz x0, .Lam_apply")
    a.adr("x2", "cstr_mode")
    a.many(ldsel("stringWithUTF8String"))
    a("mov x1, x9")
    a("blr x19")
    a("str x0, [x22, #0x%x]" % S_KEYOBJ)
    a("cbz x0, .Lam_apply")

    a("mov x2, x0")
    a("mov x0, x21")
    a.many(ldsel("integerForKey"))
    a("mov x1, x9")
    a("blr x19")
    a("cmp w0, #%d" % MODE_OFFICIAL)
    a("b.ne .Lam_apply")
    a("mov w23, #%d" % MODE_OFFICIAL)

    a.label(".Lam_apply")
    a("str x21, [x22, #0x%x]" % S_DEFAULTS)
    a("str w23, [x22, #0x%x]" % S_MODE)
    a("mov w9, #0")
    a("cmp w23, #%d" % MODE_OFFICIAL)
    a("b.ne .Lam_slot")
    a("mov w9, #1")
    a.label(".Lam_slot")
    a("str x9, [x22, #0x%x]" % S_KEY)
    a("ldp x25, x30, [sp, #0x30]")
    a("ldp x23, x24, [sp, #0x20]")
    a("ldp x21, x22, [sp, #0x10]")
    a("ldp x19, x20, [sp, #0x00]")
    a("add sp, sp, #0x40")
    a("ret")

    # ======================= panel (blocking) ============================
    a.label("panel")
    a("sub sp, sp, #0x60")
    a("stp x19, x20, [sp, #0x00]")
    a("stp x21, x22, [sp, #0x10]")
    a("stp x23, x24, [sp, #0x20]")
    a("stp x25, x26, [sp, #0x30]")
    a("stp x27, x30, [sp, #0x40]")
    a.many(load_scratch())
    a("ldrb w9, [x22, #0x%x]" % S_SHOWN)
    a("cbnz w9, .Lp_ret")
    a("mov w9, #1")
    a("strb w9, [x22, #0x%x]" % S_SHOWN)
    a("str wzr, [x22, #0x%x]" % S_CHOICE)
    a("str xzr, [x22, #0x%x]" % S_WINDOW)
    a("str xzr, [x22, #0x%x]" % S_V_TITLE)
    a("str xzr, [x22, #0x%x]" % S_V_MSG)
    a("str xzr, [x22, #0x%x]" % S_V_PRIV)
    a("str xzr, [x22, #0x%x]" % S_V_OFF)

    a.many(ldslot(got_msg, "x19"))
    a.many(ldslot(got_cls, "x20"))

    for slot, cname, text in ((S_S_TITLE, "str_title", title),
                              (S_S_MSG, "str_msg", msg),
                              (S_S_OFFICIAL, "str_official", label_official),
                              (S_S_PRIVATE, "str_private", label_private),
                              (S_RUNMODE, "cstr_runmode", runmode)):
        a.adr("x0", "cstr_NSString")
        a("blr x20")
        a("adr x2, %s" % cname)
        a.many(ldsel("stringWithUTF8String"))
        a("mov x1, x9")
        a("blr x19")
        a("str x0, [x22, #0x%x]" % slot)

    # ---- window ---------------------------------------------------------
    a("bl find_scene")
    a("cbz x0, .Lp_win_frame")
    a("mov x21, x0")
    a.adr("x0", "cstr_UIWindow")
    a("blr x20")
    a("cbz x0, .Lp_win_frame")
    a.many(ldsel("alloc"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_win_frame")
    a("mov x2, x21")
    a.many(ldsel("initWithWindowScene"))
    a("mov x1, x9")
    a("blr x19")
    a("cbnz x0, .Lp_win_ok")

    a.label(".Lp_win_frame")
    a.adr("x0", "cstr_UIWindow")
    a("blr x20")
    a("cbz x0, .Lp_bail")
    a.many(ldsel("alloc"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_bail")
    a("mov x21, x0")                                  # the new, empty window
    # initWithFrame: needs the rect in d0-d3, and msgSend may clobber all of
    # d0-d7, so the size is measured *after* the alloc and stored inline.
    a("bl panel_size")
    a("fcmp d0, #0.0")
    a("b.le .Lp_bail")
    a("fcmp d1, #0.0")
    a("b.le .Lp_bail")
    a("fmov d2, d0")
    a("fmov d3, d1")
    a("fmov d0, xzr")
    a("fmov d1, xzr")
    a("mov x0, x21")
    a.many(ldsel("initWithFrame"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_bail")

    a.label(".Lp_win_ok")
    a("mov x23, x0")
    a("str x23, [x22, #0x%x]" % S_WINDOW)

    a("mov x0, x23")
    a.adr("x9", "dbl_level")
    a("ldr d0, [x9]")
    a.many(ldsel("setWindowLevel"))
    a("mov x1, x9")
    a("blr x19")

    a.adr("x0", "cstr_UIViewController")
    a("blr x20")
    a("cbz x0, .Lp_bail")
    a.many(ldsel("alloc"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_bail")
    a.many(ldsel("init"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_bail")
    a("str x0, [x22, #0x%x]" % S_VC)

    a("ldr x0, [x22, #0x%x]" % S_WINDOW)
    a("ldr x2, [x22, #0x%x]" % S_VC)
    a.many(ldsel("setRootViewController"))
    a("mov x1, x9")
    a("blr x19")

    # Size and pin the window *before* it is shown.  `initWithWindowScene:`
    # takes its bounds from the scene's coordinate space, which is fixed at
    # scene creation (the launch orientation) and can differ from what the
    # glass shows once the interface has rotated: the panel then lays out
    # 844 pt wide on a 390 pt screen and the right-hand button runs off the
    # edge.  relayout() measures the screen and asks the scene which way round
    # the interface is, so the panel fits either way.
    a("bl relayout")

    a("ldr x0, [x22, #0x%x]" % S_WINDOW)
    a.many(ldsel("makeKeyAndVisible"))
    a("mov x1, x9")
    a("blr x19")

    a("bl pump_once")

    # ---- register the two button handlers on UIViewController ----------
    # UIButton target-action needs a SEL.  The selectors are not in the
    # binary, so sel_registerName() makes them, and class_addMethod() installs
    # the IMPs (pick_private / pick_official) — no blocks, no UIAction.
    a.many(ldslot(got_dlsym, "x25"))
    a("mov x0, #-2")                                  # RTLD_DEFAULT
    a.adr("x1", "cstr_sel_registerName")
    a("blr x25")
    a("cbz x0, .Lp_bail")
    a("mov x27, x0")

    a.adr("x0", "cstr_sel_pick_private")
    a("blr x27")
    a("cbz x0, .Lp_bail")
    a("str x0, [x22, #0x%x]" % S_SEL_P)

    a.adr("x0", "cstr_sel_pick_official")
    a("blr x27")
    a("cbz x0, .Lp_bail")
    a("str x0, [x22, #0x%x]" % S_SEL_O)

    a("mov x0, #-2")
    a.adr("x1", "cstr_class_addMethod")
    a("blr x25")
    a("cbz x0, .Lp_bail")
    a("mov x27, x0")

    a.adr("x0", "cstr_UIViewController")
    a("blr x20")
    a("cbz x0, .Lp_bail")
    a("mov x21, x0")

    a("mov x0, x21")
    a("ldr x1, [x22, #0x%x]" % S_SEL_P)
    a.adr("x2", "pick_private")
    a.adr("x3", "cstr_method_types")
    a("blr x27")

    a("mov x0, x21")
    a("ldr x1, [x22, #0x%x]" % S_SEL_O)
    a.adr("x2", "pick_official")
    a.adr("x3", "cstr_method_types")
    a("blr x27")

    # ---- one row of content: two labels above, two buttons side by side --
    def make_label(slot, view_slot, ysrc, hsrc, font_label, bold, lines):
        a.adr("x0", "cstr_UILabel")
        a("blr x20")
        a("cbz x0, .Lp_bail")
        a.many(ldsel("alloc"))
        a("mov x1, x9")
        a("blr x19")
        a("cbz x0, .Lp_bail")
        a("mov x21, x0")
        init_frame(("const", "dbl_margin"), ysrc, ("slot", S_LWD), hsrc)
        a("mov x0, x21")
        a.many(ldsel("initWithFrame"))
        a("mov x1, x9")
        a("blr x19")
        a("cbz x0, .Lp_bail")
        a("mov x21, x0")

        a("ldr x2, [x22, #0x%x]" % slot)
        a.many(ldsel("setText"))
        a("mov x1, x9")
        a("blr x19")

        a.adr("x0", "cstr_UIColor")
        a("blr x20")
        a("cbz x0, .Lp_bail")
        a.many(ldsel("whiteColor"))
        a("mov x1, x9")
        a("blr x19")
        a("cbz x0, .Lp_bail")
        a("mov x2, x0")
        a("mov x0, x21")
        a.many(ldsel("setTextColor"))
        a("mov x1, x9")
        a("blr x19")

        a.adr("x0", "cstr_UIFont")
        a("blr x20")
        a("cbz x0, .Lp_bail")
        a.adr("x9", font_label)
        a("ldr d0, [x9]")
        a.many(ldsel("boldSystemFontOfSize" if bold else "systemFontOfSize"))
        a("mov x1, x9")
        a("blr x19")
        a("cbz x0, .Lp_bail")
        a("mov x2, x0")
        a("mov x0, x21")
        a.many(ldsel("setFont"))
        a("mov x1, x9")
        a("blr x19")

        a("mov x0, x21")
        a("mov w2, #%d" % lines)
        a.many(ldsel("setNumberOfLines"))
        a("mov x1, x9")
        a("blr x19")

        a("mov x0, x21")
        a("mov w2, #1")                              # NSTextAlignmentCenter
        a.many(ldsel("setTextAlignment"))
        a("mov x1, x9")
        a("blr x19")

        a("str x21, [x22, #0x%x]" % view_slot)       # relayout re-frames it later
        add_to_vc_view("x21")

    def make_button(slot, view_slot, xsrc, sel_slot):
        a.adr("x0", "cstr_UIButton")
        a("blr x20")
        a("cbz x0, .Lp_bail")
        a("mov w2, #0")                              # UIButtonTypeCustom
        a.many(ldsel("buttonWithType"))
        a("mov x1, x9")
        a("blr x19")
        a("cbz x0, .Lp_bail")
        a("mov x23, x0")

        init_frame(xsrc, ("slot", S_LY), ("slot", S_LBW),
                   ("const", "dbl_button_h"))
        a("mov x0, x23")
        a.many(ldsel("setFrame"))
        a("mov x1, x9")
        a("blr x19")

        a("mov x0, x23")
        a("ldr x2, [x22, #0x%x]" % slot)
        a("mov w3, #0")
        a.many(ldsel("setTitle"))
        a("mov x1, x9")
        a("blr x19")

        a.adr("x0", "cstr_UIColor")
        a("blr x20")
        a("cbz x0, .Lp_bail")
        a.many(ldsel("whiteColor"))
        a("mov x1, x9")
        a("blr x19")
        a("cbz x0, .Lp_bail")
        a("mov x2, x0")
        a("mov x0, x23")
        a("mov w3, #0")
        a.many(ldsel("setTitleColor"))
        a("mov x1, x9")
        a("blr x19")

        a.adr("x0", "cstr_UIFont")
        a("blr x20")
        a("cbz x0, .Lp_bail")
        a.adr("x9", "dbl_font_btn")
        a("ldr d0, [x9]")
        a.many(ldsel("boldSystemFontOfSize"))
        a("mov x1, x9")
        a("blr x19")
        a("cbz x0, .Lp_bail")
        a("mov x2, x0")
        a("mov x0, x23")
        a.many(ldsel("setFont"))
        a("mov x1, x9")
        a("blr x19")

        # dark rounded button background
        a.adr("x0", "cstr_UIColor")
        a("blr x20")
        a("cbz x0, .Lp_bail")
        a.adr("x9", "dbl_btn_white")
        a("ldr d0, [x9]")
        a.adr("x9", "dbl_btn_alpha")
        a("ldr d1, [x9]")
        a.many(ldsel("colorWithWhite"))
        a("mov x1, x9")
        a("blr x19")
        a("cbz x0, .Lp_bail")
        a("mov x2, x0")
        a("mov x0, x23")
        a.many(ldsel("setBackgroundColor"))
        a("mov x1, x9")
        a("blr x19")

        a("mov x0, x23")
        a.many(ldsel("layer"))
        a("mov x1, x9")
        a("blr x19")
        a("cbz x0, .Lp_bail")
        a("mov x21, x0")                             # x21 = CALayer
        a.adr("x9", "dbl_corner")
        a("ldr d0, [x9]")
        a.many(ldsel("setCornerRadius"))
        a("mov x1, x9")
        a("blr x19")

        # No masksToBounds: it is a CALayer property, and sending it to the
        # button (or a label) is an unrecognized selector that kills the app
        # before the first frame.  cornerRadius alone already rounds the
        # layer's background, which is all this button needs.

        # Keep "Grasscutter (private)" on one line on narrow phones: let the
        # title label shrink instead of truncating.  Its UILabel goes in x24 so
        # it cannot clobber the layer pointer in x21.
        a("mov x0, x23")
        a.many(ldsel("titleLabel"))
        a("mov x1, x9")
        a("blr x19")
        a("cbz x0, .Lp_bail")
        a("mov x24, x0")                             # x24 = title UILabel
        a("mov x0, x24")
        a("mov w2, #1")
        a.many(ldsel("setAdjustsFontSizeToFitWidth"))
        a("mov x1, x9")
        a("blr x19")

        # [button addTarget:vc action:sel forControlEvents:TouchUpInside]
        a("mov x0, x23")
        a("ldr x2, [x22, #0x%x]" % S_VC)
        a("ldr x3, [x22, #0x%x]" % sel_slot)
        a("mov w4, #64")                             # touch up inside
        a.many(ldsel("addTarget"))
        a("mov x1, x9")
        a("blr x19")

        a("str x23, [x22, #0x%x]" % view_slot)       # relayout re-frames it later
        add_to_vc_view("x23")

    # scrim so white text is readable over the Unity splash
    a("ldr x0, [x22, #0x%x]" % S_VC)
    a.many(ldsel("view"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_bail")
    a("mov x23, x0")
    a.adr("x0", "cstr_UIColor")
    a("blr x20")
    a("cbz x0, .Lp_bail")
    a.adr("x9", "dbl_scrim_white")
    a("ldr d0, [x9]")
    a.adr("x9", "dbl_scrim_alpha")
    a("ldr d1, [x9]")
    a.many(ldsel("colorWithWhite"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_bail")
    a("mov x2, x0")
    a("mov x0, x23")
    a.many(ldsel("setBackgroundColor"))
    a("mov x1, x9")
    a("blr x19")

    make_label(S_S_TITLE, S_V_TITLE, ("slot", S_LTY), ("const", "dbl_title_h"),
               "dbl_font_title", True, 1)
    make_label(S_S_MSG, S_V_MSG, ("slot", S_LMY), ("const", "dbl_msg_h"),
               "dbl_font_msg", False, 0)
    make_button(S_S_PRIVATE, S_V_PRIV, ("const", "dbl_margin"), S_SEL_P)
    make_button(S_S_OFFICIAL, S_V_OFF, ("slot", S_LX2), S_SEL_O)

    # ---- block the main thread until a button is tapped -----------------
    a("bl now_seconds")
    a("str d0, [x22, #0x%x]" % S_T0)
    a.label(".Lp_loop")
    a("ldr w9, [x22, #0x%x]" % S_CHOICE)
    a("cbnz w9, .Lp_choice")
    a("bl now_seconds")
    a("ldr d1, [x22, #0x%x]" % S_T0)
    a("fsub d0, d0, d1")
    a.adr("x9", "dbl_cap")
    a("ldr d1, [x9]")
    a("fcmp d0, d1")
    a("b.ge .Lp_timeout")
    a("bl relayout_if_needed")
    a("bl pump_once")
    a("b .Lp_loop")

    a.label(".Lp_choice")
    a.label(".Lp_timeout")
    a.label(".Lp_bail")
    a("ldr x0, [x22, #0x%x]" % S_WINDOW)
    a("cbz x0, .Lp_ret")
    a.many(ldslot(got_msg, "x19"))
    a.many(ldsel("setHidden"))
    a("mov x1, x9")
    a("mov w2, #1")
    a("blr x19")
    a.label(".Lp_ret")
    a("ldp x27, x30, [sp, #0x40]")
    a("ldp x25, x26, [sp, #0x30]")
    a("ldp x23, x24, [sp, #0x20]")
    a("ldp x21, x22, [sp, #0x10]")
    a("ldp x19, x20, [sp, #0x00]")
    a("add sp, sp, #0x60")
    a("ret")

    # ======================= run-loop helpers ============================
    a.label("find_scene")
    a("sub sp, sp, #0x20")
    a("stp x29, x30, [sp, #0x00]")
    a("str wzr, [sp, #0x10]")
    a.label(".Lfs_loop")
    a.adr("x0", "cstr_UIApplication")
    a("blr x20")
    a("cbz x0, .Lfs_none")
    a.many(ldsel("sharedApplication"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lfs_ret")
    a.many(ldsel("connectedScenes"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lfs_ret")
    a.many(ldsel("anyObject"))
    a("mov x1, x9")
    a("blr x19")
    a("cbnz x0, .Lfs_ret")
    a("ldr w9, [sp, #0x10]")
    a("cmp w9, #20")
    a("b.ge .Lfs_none")
    a("add w9, w9, #1")
    a("str w9, [sp, #0x10]")
    a("bl pump_once")
    a("b .Lfs_loop")
    a.label(".Lfs_none")
    a("mov x0, #0")
    a.label(".Lfs_ret")
    a("ldp x29, x30, [sp, #0x00]")
    a("add sp, sp, #0x20")
    a("ret")

    a.label("pump_once")
    a("sub sp, sp, #0x20")
    a("stp x29, x30, [sp, #0x00]")
    a.adr("x0", "cstr_NSDate")
    a("blr x20")
    a("cbz x0, .Lpu_ret")
    a.adr("x9", "dbl_tick")
    a("ldr d0, [x9]")
    a.many(ldsel("dateWithTimeIntervalSinceNow"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lpu_ret")
    a("str x0, [sp, #0x10]")
    a.adr("x0", "cstr_NSRunLoop")
    a("blr x20")
    a("cbz x0, .Lpu_ret")
    a.many(ldsel("currentRunLoop"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lpu_ret")
    a("ldr x2, [x22, #0x%x]" % S_RUNMODE)
    a("cbz x2, .Lpu_ret")
    a("ldr x3, [sp, #0x10]")
    a.many(ldsel("runMode:beforeDate:"))
    a("mov x1, x9")
    a("blr x19")
    a.label(".Lpu_ret")
    a("ldp x29, x30, [sp, #0x00]")
    a("add sp, sp, #0x20")
    a("ret")

    # ======================= panel geometry ===============================
    # panel_size: d0 = width, d1 = height of the space the panel is shown in.
    #
    # The screen gives the two side lengths; the window's scene says which way
    # round the interface is.  -window.bounds alone is not enough: a window made
    # with initWithWindowScene: keeps the coordinate space it was created in, so
    # during a rotation it can report 844x390 while the glass shows 390x844, and
    # the panel then overflows to the right.
    a.label("panel_size")
    a("sub sp, sp, #0x20")
    a("stp x29, x30, [sp, #0x00]")
    a.adr("x0", "cstr_UIScreen")
    a("blr x20")
    a("cbz x0, .Lps_win")
    a.many(ldsel("mainScreen"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lps_win")
    a.many(ldsel("bounds"))                           # CGRect -> d0-d3
    a("mov x1, x9")
    a("blr x19")
    a("fmin d4, d2, d3")                              # short side
    a("fmax d5, d2, d3")                              # long side
    a("mov w9, #1")                                   # 1 = landscape
    a("str w9, [sp, #0x10]")
    a("ldr x0, [x22, #0x%x]" % S_WINDOW)
    a("cbz x0, .Lps_have")
    a.many(ldsel("windowScene"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lps_have")
    a.many(ldsel("interfaceOrientation"))
    a("mov x1, x9")
    a("blr x19")
    a("cmp w0, #2")                                   # 1/2 portrait, 3/4 landscape
    a("b.hi .Lps_have")
    a("str wzr, [sp, #0x10]")
    a.label(".Lps_have")
    a("ldr w9, [sp, #0x10]")
    a("cbnz w9, .Lps_land")
    a("fmov d0, d4")
    a("fmov d1, d5")
    a("b .Lps_ret")
    a.label(".Lps_land")
    a("fmov d0, d5")
    a("fmov d1, d4")
    a("b .Lps_ret")
    a.label(".Lps_win")                               # no screen: use the window
    a("ldr x0, [x22, #0x%x]" % S_WINDOW)
    a("cbz x0, .Lps_zero")
    a.many(ldsel("bounds"))
    a("mov x1, x9")
    a("blr x19")
    a("fmov d0, d2")
    a("fmov d1, d3")
    a("b .Lps_ret")
    a.label(".Lps_zero")                              # nothing known: caller bails
    a("fmov d0, xzr")
    a("fmov d1, xzr")
    a.label(".Lps_ret")
    a("ldp x29, x30, [sp, #0x00]")
    a("add sp, sp, #0x20")
    a("ret")

    nref = [0]

    def reframe(view_slot, xsrc, ysrc, wsrc, hsrc):
        """setFrame: on a subview if it has been created already."""
        nref[0] += 1
        skip = ".Lrl_v%d" % nref[0]
        a("ldr x0, [x22, #0x%x]" % view_slot)
        a("cbz x0, %s" % skip)
        init_frame(xsrc, ysrc, wsrc, hsrc)
        a.many(ldsel("setFrame"))
        a("mov x1, x9")
        a("blr x19")
        a.label(skip)

    # relayout: pin the window to the measured size, recompute every layout
    # scalar and move the subviews that already exist.  Called once before the
    # views are built (they are skipped) and again whenever the size changes.
    a.label("relayout")
    a("sub sp, sp, #0x10")
    a("stp x29, x30, [sp, #0x00]")
    a("bl panel_size")
    a("fcmp d0, #0.0")
    a("b.le .Lrl_ret")
    a("fcmp d1, #0.0")
    a("b.le .Lrl_ret")
    a("str d0, [x22, #0x%x]" % S_LW)
    a("str d1, [x22, #0x%x]" % S_LH)

    a("ldr x0, [x22, #0x%x]" % S_WINDOW)
    a("cbz x0, .Lrl_math")
    a("fmov d2, d0")
    a("fmov d3, d1")
    a("fmov d0, xzr")
    a("fmov d1, xzr")
    a.many(ldsel("setFrame"))
    a("mov x1, x9")
    a("blr x19")

    a.label(".Lrl_math")
    a("ldr d0, [x22, #0x%x]" % S_LW)                  # width
    a("ldr d1, [x22, #0x%x]" % S_LH)                  # height

    # button width = (W - (2*margin + gap)) / 2
    a("mov w9, #%d" % int(2 * MARGIN + GAP))
    a("scvtf d2, w9")
    a("fsub d3, d0, d2")
    a("mov w9, #2")
    a("scvtf d2, w9")
    a("fdiv d3, d3, d2")
    a("str d3, [x22, #0x%x]" % S_LBW)

    # right button x = margin + button width + gap = button width + 36
    a("mov w9, #%d" % int(MARGIN + GAP))
    a("scvtf d2, w9")
    a("fadd d4, d3, d2")
    a("str d4, [x22, #0x%x]" % S_LX2)

    # button row y = H / 2 + 20
    a("mov w9, #2")
    a("scvtf d2, w9")
    a("fdiv d5, d1, d2")
    a("mov w9, #%d" % int(BUTTON_ROW_DY))
    a("scvtf d2, w9")
    a("fadd d5, d5, d2")
    a("str d5, [x22, #0x%x]" % S_LY)

    # title y = row y - 92, message y = row y - 52
    a("mov w9, #%d" % int(TITLE_DY))
    a("scvtf d2, w9")
    a("fsub d6, d5, d2")
    a("str d6, [x22, #0x%x]" % S_LTY)
    a("mov w9, #%d" % int(MSG_DY))
    a("scvtf d2, w9")
    a("fsub d7, d5, d2")
    a("str d7, [x22, #0x%x]" % S_LMY)

    # label width = W - 48
    a("mov w9, #%d" % int(2 * MARGIN))
    a("scvtf d2, w9")
    a("ldr d0, [x22, #0x%x]" % S_LW)
    a("fsub d0, d0, d2")
    a("str d0, [x22, #0x%x]" % S_LWD)

    reframe(S_V_TITLE, ("const", "dbl_margin"), ("slot", S_LTY),
            ("slot", S_LWD), ("const", "dbl_title_h"))
    reframe(S_V_MSG, ("const", "dbl_margin"), ("slot", S_LMY),
            ("slot", S_LWD), ("const", "dbl_msg_h"))
    reframe(S_V_PRIV, ("const", "dbl_margin"), ("slot", S_LY),
            ("slot", S_LBW), ("const", "dbl_button_h"))
    reframe(S_V_OFF, ("slot", S_LX2), ("slot", S_LY),
            ("slot", S_LBW), ("const", "dbl_button_h"))

    a.label(".Lrl_ret")
    a("ldp x29, x30, [sp, #0x00]")
    a("add sp, sp, #0x10")
    a("ret")

    # relayout_if_needed: one cheap size probe per tick, so a rotation while
    # the panel is up is followed instead of leaving the row half off-screen.
    a.label("relayout_if_needed")
    a("sub sp, sp, #0x10")
    a("stp x29, x30, [sp, #0x00]")
    a("bl panel_size")
    a.adr("x9", "dbl_eps")
    a("ldr d6, [x9]")
    a("ldr d2, [x22, #0x%x]" % S_LW)
    a("fsub d4, d0, d2")
    a("fabs d4, d4")
    a("fcmp d4, d6")
    a("b.gt .Lri_do")
    a("ldr d2, [x22, #0x%x]" % S_LH)
    a("fsub d4, d1, d2")
    a("fabs d4, d4")
    a("fcmp d4, d6")
    a("b.le .Lri_ret")
    a.label(".Lri_do")
    a("bl relayout")
    a.label(".Lri_ret")
    a("ldp x29, x30, [sp, #0x00]")
    a("add sp, sp, #0x10")
    a("ret")

    a.label("now_seconds")
    a("sub sp, sp, #0x10")
    a("stp x29, x30, [sp, #0x00]")
    a.adr("x0", "cstr_NSDate")
    a("blr x20")
    a("cbz x0, .Lns_zero")
    a.many(ldsel("date"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lns_zero")
    a.many(ldsel("timeIntervalSinceReferenceDate"))
    a("mov x1, x9")
    a("blr x19")
    a("b .Lns_ret")
    a.label(".Lns_zero")
    a("fmov d0, xzr")
    a.label(".Lns_ret")
    a("ldp x29, x30, [sp, #0x00]")
    a("add sp, sp, #0x10")
    a("ret")

    # ======================= button handlers (ObjC methods) ==============
    # Installed with class_addMethod as -[UIViewController rsaPatchPick*:].
    a.label("pick_private")
    a("mov w0, #%d" % MODE_PRIVATE)
    a("b choose")
    a.label("pick_official")
    a("mov w0, #%d" % MODE_OFFICIAL)
    a("b choose")

    a.label("choose")
    a("sub sp, sp, #0x40")
    a("stp x19, x20, [sp, #0x00]")
    a("stp x21, x22, [sp, #0x10]")
    a("stp x23, x24, [sp, #0x20]")
    a("stp x29, x30, [sp, #0x30]")
    a.many(load_scratch())
    a("str w0, [x22, #0x%x]" % S_CHOICE)
    a("ldr w9, [x22, #0x%x]" % S_MODE)
    a("cmp w0, w9")
    a("b.eq .Lc_ret")
    a("mov w23, w0")
    a("ldr x21, [x22, #0x%x]" % S_DEFAULTS)
    a("cbz x21, .Lc_ret")
    a("ldr x24, [x22, #0x%x]" % S_KEYOBJ)
    a("cbz x24, .Lc_ret")
    a.many(ldslot(got_msg, "x19"))
    a("mov x0, x21")
    a("mov x2, x23")
    a("mov x3, x24")
    a.many(ldsel("setIntegerForKey"))
    a("mov x1, x9")
    a("blr x19")
    a("mov x0, x21")
    a.many(ldsel("synchronize"))
    a("mov x1, x9")
    a("blr x19")

    a.many(ldslot(got_dlsym, "x20"))
    a("mov x0, #-2")                     # RTLD_DEFAULT
    a.adr("x1", "cstr_exit")
    a("blr x20")
    a("cbz x0, .Lc_ret")
    a("mov x19, x0")
    a("mov w0, #0")
    a("blr x19")
    a.label(".Lc_ret")
    a("ldp x29, x30, [sp, #0x30]")
    a("ldp x23, x24, [sp, #0x20]")
    a("ldp x21, x22, [sp, #0x10]")
    a("ldp x19, x20, [sp, #0x00]")
    a("add sp, sp, #0x40")
    a("ret")

    # ======================= data =========================================
    a.align(8)
    a.label("end_code")
    a.cstr("cstr_NSUserDefaults", "NSUserDefaults")
    a.cstr("cstr_NSString", "NSString")
    a.cstr("cstr_UIWindow", "UIWindow")
    a.cstr("cstr_UIViewController", "UIViewController")
    a.cstr("cstr_UIScreen", "UIScreen")
    a.cstr("cstr_UILabel", "UILabel")
    a.cstr("cstr_UIButton", "UIButton")
    a.cstr("cstr_UIColor", "UIColor")
    a.cstr("cstr_UIFont", "UIFont")
    a.cstr("cstr_NSDate", "NSDate")
    a.cstr("cstr_NSRunLoop", "NSRunLoop")
    a.cstr("cstr_UIApplication", "UIApplication")
    a.cstr("cstr_sel_registerName", "sel_registerName")
    a.cstr("cstr_class_addMethod", "class_addMethod")
    a.cstr("cstr_sel_pick_private", SEL_PICK_PRIVATE)
    a.cstr("cstr_sel_pick_official", SEL_PICK_OFFICIAL)
    a.cstr("cstr_method_types", METHOD_TYPES)
    a.cstr("cstr_mode", mode_key)
    a.cstr("cstr_runmode", runmode)
    a.cstr("cstr_exit", "exit")
    a.cstr("str_title", title)
    a.cstr("str_msg", msg)
    a.cstr("str_official", label_official)
    a.cstr("str_private", label_private)
    a.align(8)
    a.emit("dbl_level", struct.pack("<d", WINDOW_LEVEL))
    a.emit("dbl_tick", struct.pack("<d", TICK))
    a.emit("dbl_cap", struct.pack("<d", PANEL_CAP))
    a.emit("dbl_eps", struct.pack("<d", LAYOUT_EPS))
    a.emit("dbl_margin", struct.pack("<d", MARGIN))
    a.emit("dbl_button_h", struct.pack("<d", BUTTON_H))
    a.emit("dbl_title_h", struct.pack("<d", TITLE_H))
    a.emit("dbl_msg_h", struct.pack("<d", MSG_H))
    a.emit("dbl_font_title", struct.pack("<d", 20.0))
    a.emit("dbl_font_msg", struct.pack("<d", 15.0))
    a.emit("dbl_font_btn", struct.pack("<d", 15.0))
    a.emit("dbl_btn_white", struct.pack("<d", 0.18))
    a.emit("dbl_btn_alpha", struct.pack("<d", 1.0))
    a.emit("dbl_corner", struct.pack("<d", 10.0))
    a.emit("dbl_scrim_white", struct.pack("<d", 0.0))
    a.emit("dbl_scrim_alpha", struct.pack("<d", 0.72))

    # resolve deferred `adr` pseudo-instructions now that all labels are known
    real = []
    for ln in a.lines:
        if isinstance(ln, tuple):
            _, reg, label = ln
            if label not in a.labels:
                raise SystemExit("panel: unknown label %r" % label)
            target = a.labels[label]
            real.append("adrp %s, 0x%x" % (reg, target & ~0xFFF))
            real.append("add %s, %s, #0x%x" % (reg, reg, target & 0xFFF))
        else:
            real.append(ln)
    src = "\n".join(real)
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    enc, cnt = ks.asm(src, code_base)
    if enc is None:
        raise SystemExit("panel: keystone failed")
    blob = bytes(enc)
    if a.labels["hook_start"] != code_base:
        raise SystemExit("panel: hook_start is not at the code base")
    return {"blob": blob, "asm": src, "labels": a.labels, "size": len(blob),
            "code_base": code_base, "end": a.pc}
