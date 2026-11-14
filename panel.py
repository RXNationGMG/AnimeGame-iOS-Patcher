#!/usr/bin/env python3
"""Position-dependent AArch64 server panel for the RSA-key patcher.

Everything version specific (code base, GOT slots, selector refs, scratch
page) is passed in through `p`, so the same generator works for any Genshin
version whose method list, selrefs and bindings were found by `gipatch.py`.

Panel semantics
---------------
* runs from the `startUnity:` hook, i.e. before `UnityInitApplication`, so it
  is the first thing the user sees and cannot be covered by Unity;
* blocks the main thread in 0.1 s run-loop slices until a button is tapped
  (60 s failsafe -> hide and continue);
* tapping the already-active choice hides the panel and boots normally;
* tapping the other choice persists `rsapatch.mode`, synchronises the
  defaults and `exit(0)`s, so the next launch applies that key in
  `apply_mode` before Unity builds any of the RSA key strings.
"""
import struct

try:
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
except ImportError:                                     # older/odd builds
    from keystone.keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

S_KEY = 0x000        # u64 0 = replacement key, 1 = shipped key
S_SHOWN = 0x008      # u8  panel already presented in this process
S_CHOICE = 0x00C     # u32 0 = none yet, else the mode the user picked
S_BLOCK_P = 0x020    # 32-byte global block (private/Grasscutter)
S_BLOCK_O = 0x040    # 32-byte global block (official)
S_WINDOW = 0x060
S_VC = 0x068
S_ALERT = 0x070
S_S_TITLE = 0x078
S_S_MSG = 0x080
S_S_OFFICIAL = 0x088
S_S_PRIVATE = 0x090
S_DEFAULTS = 0x098
S_KEYOBJ = 0x0A0
S_MODE = 0x0A8
S_RUNMODE = 0x0B0
S_FRAME = 0x0C0
S_T0 = 0x0E0

MODE_PRIVATE = 1
MODE_OFFICIAL = 2

WINDOW_LEVEL = 2001.0    # UIWindowLevelAlert + 1
TICK = 0.1
PANEL_CAP = 60.0

TITLE = "RSA Patch Selection"
MSG = "Choose your RSA Patch. Switching requires you to restart the app."
LABEL_OFFICIAL = "HoYoverse (official)"
LABEL_PRIVATE = "Grasscutter (private)"
MODE_KEY = "rsapatch.mode"
RUNMODE = "kCFRunLoopDefaultMode"

# Friendly short names used by the payload -> real selector text in the binary.
# `__objc_selrefs` stores the exact selector string, so both spellings are
# accepted: a short name resolves through this table, anything else is used
# verbatim.
SEL_ALIASES = {
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
    "addAction": "addAction:",
    "dateWithTimeIntervalSinceNow": "dateWithTimeIntervalSinceNow:",
}


def resolve_sel(sel, name):
    """Map a payload selector name to the key used by `selrefs`."""
    if name in sel:
        return name
    alias = SEL_ALIASES.get(name)
    if alias and alias in sel:
        return alias
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

    code_base, got_msgsend, got_getclass, got_dlsym, got_globalblock, scratch,
    sel (dict name -> vm), title, message, label_private, label_official,
    mode_key, runmode (optional)
    """
    code_base = p["code_base"]
    scratch = p["scratch"]
    sel = p["sel"]
    got_msg = p["got_msgsend"]
    got_cls = p["got_getclass"]
    got_dlsym = p["got_dlsym"]
    got_block = p["got_globalblock"]
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
    a("adrp x22, 0x%x" % (scratch & ~0xFFF))
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
    a("adrp x22, 0x%x" % (scratch & ~0xFFF))
    a("ldrb w9, [x22, #0x%x]" % S_SHOWN)
    a("cbnz w9, .Lp_ret")
    a("mov w9, #1")
    a("strb w9, [x22, #0x%x]" % S_SHOWN)
    a("str wzr, [x22, #0x%x]" % S_CHOICE)
    a("str xzr, [x22, #0x%x]" % S_WINDOW)

    a.many(ldslot(got_msg, "x19"))
    a.many(ldslot(got_cls, "x20"))
    a.many(ldslot(got_block, "x23"))

    for base in (S_BLOCK_P, S_BLOCK_O):
        a("str x23, [x22, #0x%x]" % (base + 0))
        a("mov w9, #0x1000")
        a("lsl w9, w9, #16")
        a("str w9, [x22, #0x%x]" % (base + 8))
        a("str wzr, [x22, #0x%x]" % (base + 12))
        a("adr x9, blk_private" if base == S_BLOCK_P else "adr x9, blk_official")
        a("str x9, [x22, #0x%x]" % (base + 16))
        a.adr("x9", "blk_desc")
        a("str x9, [x22, #0x%x]" % (base + 24))

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
    a.adr("x0", "cstr_UIScreen")
    a("blr x20")
    a("cbz x0, .Lp_bail")
    a.many(ldsel("mainScreen"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_bail")
    a.many(ldsel("bounds"))
    a("mov x1, x9")
    a("blr x19")
    a("str d0, [x22, #0x%x]" % (S_FRAME + 0))
    a("str d1, [x22, #0x%x]" % (S_FRAME + 8))
    a("str d2, [x22, #0x%x]" % (S_FRAME + 16))
    a("str d3, [x22, #0x%x]" % (S_FRAME + 24))

    a.adr("x0", "cstr_UIWindow")
    a("blr x20")
    a("cbz x0, .Lp_bail")
    a.many(ldsel("alloc"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_bail")
    a("ldr d0, [x22, #0x%x]" % (S_FRAME + 0))
    a("ldr d1, [x22, #0x%x]" % (S_FRAME + 8))
    a("ldr d2, [x22, #0x%x]" % (S_FRAME + 16))
    a("ldr d3, [x22, #0x%x]" % (S_FRAME + 24))
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
    a("ldr x0, [x22, #0x%x]" % S_WINDOW)
    a.many(ldsel("makeKeyAndVisible"))
    a("mov x1, x9")
    a("blr x19")

    a("bl pump_once")

    a.adr("x0", "cstr_UIAlertController")
    a("blr x20")
    a("cbz x0, .Lp_bail")
    a("ldr x2, [x22, #0x%x]" % S_S_TITLE)
    a("ldr x3, [x22, #0x%x]" % S_S_MSG)
    a("mov w4, #1")
    a.many(ldsel("alert"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_bail")
    a("mov x25, x0")
    a("str x25, [x22, #0x%x]" % S_ALERT)

    # private / Grasscutter action
    a.adr("x0", "cstr_UIAlertAction")
    a("blr x20")
    a("cbz x0, .Lp_bail")
    a("ldr x2, [x22, #0x%x]" % S_S_PRIVATE)
    a("mov w3, #0")
    a("add x4, x22, #0x%x" % S_BLOCK_P)
    a.many(ldsel("action"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_bail")
    a("mov x24, x0")
    a("mov x0, x25")
    a("mov x2, x24")
    a.many(ldsel("addAction"))
    a("mov x1, x9")
    a("blr x19")

    # official action
    a.adr("x0", "cstr_UIAlertAction")
    a("blr x20")
    a("cbz x0, .Lp_bail")
    a("ldr x2, [x22, #0x%x]" % S_S_OFFICIAL)
    a("mov w3, #0")
    a("add x4, x22, #0x%x" % S_BLOCK_O)
    a.many(ldsel("action"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lp_bail")
    a("mov x26, x0")
    a("ldr x0, [x22, #0x%x]" % S_ALERT)
    a("mov x2, x26")
    a.many(ldsel("addAction"))
    a("mov x1, x9")
    a("blr x19")

    a("ldr x0, [x22, #0x%x]" % S_VC)
    a("ldr x2, [x22, #0x%x]" % S_ALERT)
    a("mov w3, #0")
    a("mov x4, #0")
    a.many(ldsel("present"))
    a("mov x1, x9")
    a("blr x19")

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

    # ======================= alert action handlers ========================
    a.label("blk_private")
    a("mov w0, #%d" % MODE_PRIVATE)
    a("b choose")
    a.label("blk_official")
    a("mov w0, #%d" % MODE_OFFICIAL)
    a("b choose")

    a.label("choose")
    a("sub sp, sp, #0x40")
    a("stp x19, x20, [sp, #0x00]")
    a("stp x21, x22, [sp, #0x10]")
    a("stp x23, x24, [sp, #0x20]")
    a("stp x29, x30, [sp, #0x30]")
    a("adrp x22, 0x%x" % (scratch & ~0xFFF))
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
    a.cstr("cstr_UIAlertController", "UIAlertController")
    a.cstr("cstr_UIAlertAction", "UIAlertAction")
    a.cstr("cstr_NSDate", "NSDate")
    a.cstr("cstr_NSRunLoop", "NSRunLoop")
    a.cstr("cstr_UIApplication", "UIApplication")
    a.cstr("cstr_mode", mode_key)
    a.cstr("cstr_runmode", runmode)
    a.cstr("cstr_exit", "exit")
    a.cstr("str_title", title)
    a.cstr("str_msg", msg)
    a.cstr("str_official", label_official)
    a.cstr("str_private", label_private)
    a.align(8)
    a.emit("blk_desc", struct.pack("<QQ", 0, 32))
    a.emit("dbl_level", struct.pack("<d", WINDOW_LEVEL))
    a.emit("dbl_tick", struct.pack("<d", TICK))
    a.emit("dbl_cap", struct.pack("<d", PANEL_CAP))

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
