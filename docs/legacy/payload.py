#!/usr/bin/env python3
"""Build the server-select panel as position-dependent AArch64 code (v7).

Layout (all inside the main executable, no new segments, no prot changes):
  code         __TEXT header padding   0x1000031C0  (R+X, 3648 B free)
  official key __TEXT __eh_frame gap   0x1139F34A8  (R+X, readable)
  scratch      __DATA zero-fill tail   0x11604F000  (RW, 4 KB)

One IMP is hooked (the method-list entry lives in writable __DATA):

  -[UnityAppController startUnity:]  -> hook_start   (IMP field 0x1152C58C0)

`startUnity:` is not called directly from didFinishLaunching.  The controller
schedules it with

    [self performSelector:@selector(startUnity:) withObject:app afterDelay:0.0]

(two call sites in the binary, both pass d0 = 0.0 and a 3rd object argument),
so it runs on the *next main-run-loop turn, after didFinishLaunching has
returned*.  At that point UIApplication's run loop is live and touch delivery
works, which is what makes a blocking panel possible here: nothing of Unity
exists yet, so nothing can cover it, and the run loop can be pumped without
starving the app of events.

hook_start does, in this order:

  1. apply_mode      read `keyswitch.mode` from NSUserDefaults and point the
                     key slot at the official blob (2) or at 0 = baked-in
                     Yuuki key (anything else).  This is the only place the
                     slot is ever written, and it runs before
                     UnityInitApplication, so all seven RSA-key build sites
                     see the same key.
  2. panel           build a UIWindow at UIWindowLevelAlert + 1 (2001.0) with
                     a plain UIViewController root, present a two-button
                     alert on it, and block the main thread in a run-loop
                     pump (0.1 s slices, 60 s wall-clock failsafe).
                       * tap the server that is already active -> window is
                         hidden, the pump stops, startup continues normally
                         with the key that was applied in step 1;
                       * tap the other server -> write the mode, flush
                         NSUserDefaults, exit(0).  The next launch applies
                         that key in step 1 before Unity exists.
  3. original        tail-call the original startUnity: IMP.

Why the key cannot be switched in place: the seven key build sites run inside
UnityInitApplication, i.e. after this hook returns.  Writing the slot from a
later hook (showGameUI, the v5/v6 approach) left the engine holding a mix of
old and new keys, which the server rejected with 4214.
"""
import json
import struct

from keystone.keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

CODE_BASE = 0x1000031C0
CODE_LIMIT = 0x100004000

# __DATA_CONST,__got slots: exact addresses of the non-lazy bind entries in
# LC_DYLD_INFO_ONLY (verified with walk_bind), spread over two pages.
GOT_MSGSEND = 0x1139F9B70       # _objc_msgSend
GOT_GETCLASS = 0x1139F9B48      # _objc_getClass
GOT_DLSYM = 0x1139F8C40         # _dlsym
GOT_GLOBALBLOCK = 0x1139F8B90   # __NSConcreteGlobalBlock

for _name, _a in (("msgSend", GOT_MSGSEND), ("getClass", GOT_GETCLASS),
                  ("dlsym", GOT_DLSYM), ("globalBlock", GOT_GLOBALBLOCK)):
    assert 0x1139F8000 <= _a < 0x115170000, "%s slot %#x outside __DATA_CONST" % (_name, _a)

SCRATCH = 0x11604F000
S_KEY = 0x000          # u64 key slot, read by the 7 key build stubs
S_SHOWN = 0x008        # u8  panel already presented in this process
S_CHOICE = 0x00C       # u32 0 = none yet, else the mode the user picked
S_BLOCK_Y = 0x020      # 32-byte global block (Yuuki)
S_BLOCK_O = 0x040      # 32-byte global block (Official)
S_WINDOW = 0x060       # our UIWindow
S_VC = 0x068           # its root UIViewController
S_ALERT = 0x070        # the UIAlertController
S_S_TITLE = 0x078
S_S_MSG = 0x080
S_S_OFFICIAL = 0x088
S_S_YUUKI = 0x090
S_DEFAULTS = 0x098     # NSUserDefaults object
S_KEYOBJ = 0x0A0       # NSString "keyswitch.mode"
S_MODE = 0x0A8         # u64 mode applied at startUnity (1 yuuki, 2 official)
S_RUNMODE = 0x0B0      # NSString "kCFRunLoopDefaultMode"
S_FRAME = 0x0C0        # CGRect staged from -[UIScreen bounds]
S_T0 = 0x0E0           # double, panel start time

KEY_OFFICIAL = 0x1139F34A8
ORIG_START_UNITY = 0x10001774C

MODE_YUUKI = 1
MODE_OFFICIAL = 2

WINDOW_LEVEL = 2001.0   # UIWindowLevelAlert (2000) + 1
TICK = 0.1              # run-loop slice
PANEL_CAP = 60.0        # failsafe if nothing is ever tapped

# selector refs (__DATA,__objc_selrefs), all verified present in the binary
SEL = {
    "alloc": 0x1152744E8,
    "init": 0x11527A378,
    "initWithFrame": 0x11527AA68,
    "initWithWindowScene": 0x11527B180,
    "mainScreen": 0x11527D238,
    "connectedScenes": 0x115276500,
    "anyObject": 0x1152746C8,
    "sharedApplication": 0x115285388,
    "bounds": 0x115275350,
    "setWindowLevel": 0x115285088,
    "setRootViewController": 0x115284288,
    "makeKeyAndVisible": 0x11527D270,
    "setHidden": 0x115282BA8,
    "present": 0x11527EFC8,
    "alert": 0x115272518,
    "action": 0x115272520,
    "addAction": 0x115272528,
    "stringWithUTF8String": 0x115286118,
    "date": 0x1152770C0,
    "timeIntervalSinceReferenceDate": 0x1152866B8,
    "dateWithTimeIntervalSinceNow": 0x1152770F8,
    "currentRunLoop": 0x115276E40,
    "runMode:beforeDate:": 0x115280970,
    "standardUserDefaults": 0x115285B38,
    "integerForKey": 0x11527B3C8,
    "setIntegerForKey": 0x115282D48,
    "synchronize": 0x115286398,
}

TITLE = "Genshin server"
MSG = "Choose your server. Switching restarts the app."
OFFICIAL = "HoYoverse (official)"
YUUKI = "YuukiPS (private)"
MODE_KEY = "keyswitch.mode"
RUNMODE = "kCFRunLoopDefaultMode"


def ldsel(name):
    """adrp/ldr a SEL from its __objc_selrefs slot into x9."""
    a = SEL[name]
    page = a & ~0xFFF
    off = a & 0xFFF
    assert off % 8 == 0
    return ["adrp x9, 0x%x" % page, "ldr x9, [x9, #0x%x]" % off]


def ldslot(addr, reg):
    """adrp/ldr an absolute 8-byte slot address into reg (x9 is the scratch)."""
    page = addr & ~0xFFF
    off = addr & 0xFFF
    assert off % 8 == 0 and off <= 0xFF8, "slot %#x not addressable in one page" % addr
    return ["adrp x9, 0x%x" % page, "ldr %s, [x9, #0x%x]" % (reg, off)]


class Asm:
    """Emit instructions/data while tracking the pc, so labels are known
    without asking the assembler and every code label has a real address."""

    def __init__(self):
        self.lines = []
        self.pc = CODE_BASE
        self.labels = {}

    def __call__(self, insn):
        assert ":" not in insn, insn
        self.lines.append(insn)
        self.pc += 4

    def many(self, insns):
        for i in insns:
            self(i)

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


def build():
    a = Asm()

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
    a("adrp x16, 0x%x" % (ORIG_START_UNITY & ~0xFFF))
    a("add x16, x16, #0x%x" % (ORIG_START_UNITY & 0xFFF))
    a("br x16")                          # tail call, original returns to our caller

    # ======================= mode -> key slot =============================
    # Reads NSUserDefaults once, records the applied mode and points the key
    # slot at the official blob or at 0 (= baked-in Yuuki key).
    a.label("apply_mode")
    a("sub sp, sp, #0x40")
    a("stp x19, x20, [sp, #0x00]")
    a("stp x21, x22, [sp, #0x10]")
    a("stp x23, x24, [sp, #0x20]")
    a("stp x25, x30, [sp, #0x30]")
    a.many(ldslot(GOT_MSGSEND, "x19"))
    a.many(ldslot(GOT_GETCLASS, "x20"))
    a("adrp x22, 0x%x" % SCRATCH)
    a("mov x21, #0")                     # defaults object
    a("mov w23, #%d" % MODE_YUUKI)       # assumed mode
    a("str xzr, [x22, #0x%x]" % S_KEYOBJ)
    a("str xzr, [x22, #0x%x]" % S_DEFAULTS)

    # [NSUserDefaults standardUserDefaults]
    a("adr x0, cstr_NSUserDefaults")
    a("blr x20")
    a("cbz x0, .Lam_apply")
    a.many(ldsel("standardUserDefaults"))
    a("mov x1, x9")
    a("blr x19")
    a("mov x21, x0")
    a("cbz x21, .Lam_apply")

    # key = [NSString stringWithUTF8String:"keyswitch.mode"]
    a("adr x0, cstr_NSString")
    a("blr x20")
    a("cbz x0, .Lam_apply")
    a("adr x2, cstr_mode")
    a.many(ldsel("stringWithUTF8String"))
    a("mov x1, x9")
    a("blr x19")
    a("str x0, [x22, #0x%x]" % S_KEYOBJ)
    a("cbz x0, .Lam_apply")

    # stored = [defaults integerForKey:key]
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
    a("cmp w23, #%d" % MODE_OFFICIAL)
    a("b.ne .Lam_yuuki")
    a("adrp x9, 0x%x" % (KEY_OFFICIAL & ~0xFFF))
    a("add x9, x9, #0x%x" % (KEY_OFFICIAL & 0xFFF))
    a("b .Lam_write")
    a.label(".Lam_yuuki")
    a("mov x9, #0")                      # 0 -> baked-in Yuuki key
    a.label(".Lam_write")
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
    a("adrp x22, 0x%x" % SCRATCH)
    a("ldrb w9, [x22, #0x%x]" % S_SHOWN)
    a("cbnz w9, .Lp_ret")
    a("mov w9, #1")
    a("strb w9, [x22, #0x%x]" % S_SHOWN)
    a("str wzr, [x22, #0x%x]" % S_CHOICE)
    a("str xzr, [x22, #0x%x]" % S_WINDOW)

    a.many(ldslot(GOT_MSGSEND, "x19"))
    a.many(ldslot(GOT_GETCLASS, "x20"))
    a.many(ldslot(GOT_GLOBALBLOCK, "x23"))

    # two global blocks: {isa, flags|reserved, invoke, descriptor}
    a("str x23, [x22, #0x%x]" % (S_BLOCK_Y + 0))
    a("str x23, [x22, #0x%x]" % (S_BLOCK_O + 0))
    a("mov w9, #0x1000")
    a("lsl w9, w9, #16")
    a("str w9, [x22, #0x%x]" % (S_BLOCK_Y + 8))
    a("str w9, [x22, #0x%x]" % (S_BLOCK_O + 8))
    a("str wzr, [x22, #0x%x]" % (S_BLOCK_Y + 12))
    a("str wzr, [x22, #0x%x]" % (S_BLOCK_O + 12))
    a("adr x9, blk_yuuki")
    a("str x9, [x22, #0x%x]" % (S_BLOCK_Y + 16))
    a("adr x9, blk_official")
    a("str x9, [x22, #0x%x]" % (S_BLOCK_O + 16))
    a("adr x9, blk_desc")
    a("str x9, [x22, #0x%x]" % (S_BLOCK_Y + 24))
    a("str x9, [x22, #0x%x]" % (S_BLOCK_O + 24))

    # NSStrings
    for slot, cname, text in ((S_S_TITLE, "str_title", TITLE),
                              (S_S_MSG, "str_msg", MSG),
                              (S_S_OFFICIAL, "str_official", OFFICIAL),
                              (S_S_YUUKI, "str_yuuki", YUUKI),
                              (S_RUNMODE, "cstr_runmode", RUNMODE)):
        a("adr x0, cstr_NSString")
        a("blr x20")
        a("adr x2, %s" % cname)
        a.many(ldsel("stringWithUTF8String"))
        a("mov x1, x9")
        a("blr x19")
        a("str x0, [x22, #0x%x]" % slot)

    # ---- window -----------------------------------------------------------
    # iOS 13+ scene apps only display windows that belong to a scene, so try
    # [[UIWindow alloc] initWithWindowScene:[connectedScenes anyObject]] and
    # fall back to initWithFrame: for a legacy (non-scene) app.
    a("bl find_scene")
    a("cbz x0, .Lp_win_frame")
    a("mov x21, x0")
    a("adr x0, cstr_UIWindow")
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

    # frame = [[UIScreen mainScreen] bounds]   (CGRect in d0..d3)
    a.label(".Lp_win_frame")
    a("adr x0, cstr_UIScreen")
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

    # window = [[UIWindow alloc] initWithFrame:frame]
    a("adr x0, cstr_UIWindow")
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

    # [window setWindowLevel:UIWindowLevelAlert + 1]
    a("mov x0, x23")
    a("adr x9, dbl_level")
    a("ldr d0, [x9]")
    a.many(ldsel("setWindowLevel"))
    a("mov x1, x9")
    a("blr x19")

    # vc = [[UIViewController alloc] init]
    a("adr x0, cstr_UIViewController")
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

    # [window setRootViewController:vc]; [window makeKeyAndVisible]
    a("ldr x0, [x22, #0x%x]" % S_WINDOW)
    a("ldr x2, [x22, #0x%x]" % S_VC)
    a.many(ldsel("setRootViewController"))
    a("mov x1, x9")
    a("blr x19")
    a("ldr x0, [x22, #0x%x]" % S_WINDOW)
    a.many(ldsel("makeKeyAndVisible"))
    a("mov x1, x9")
    a("blr x19")

    # one run-loop turn: the window becomes key, the root VC appears and its
    # layer tree is committed, so the alert can be presented on it
    a("bl pump_once")

    # alert = [UIAlertController alertControllerWithTitle:message:preferredStyle:]
    a("adr x0, cstr_UIAlertController")
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

    # Yuuki action (global block -> blk_yuuki)
    a("adr x0, cstr_UIAlertAction")
    a("blr x20")
    a("cbz x0, .Lp_bail")
    a("ldr x2, [x22, #0x%x]" % S_S_YUUKI)
    a("mov w3, #0")
    a("add x4, x22, #0x%x" % S_BLOCK_Y)
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

    # Official action (global block -> blk_official)
    a("adr x0, cstr_UIAlertAction")
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

    # [vc presentViewController:alert animated:NO completion:nil]
    a("ldr x0, [x22, #0x%x]" % S_VC)
    a("ldr x2, [x22, #0x%x]" % S_ALERT)
    a("mov w3, #0")
    a("mov x4, #0")
    a.many(ldsel("present"))
    a("mov x1, x9")
    a("blr x19")

    # ---- block the main thread until a button is tapped (60 s failsafe) --
    a("bl now_seconds")
    a("str d0, [x22, #0x%x]" % S_T0)
    a.label(".Lp_loop")
    a("ldr w9, [x22, #0x%x]" % S_CHOICE)
    a("cbnz w9, .Lp_choice")
    a("bl now_seconds")
    a("ldr d1, [x22, #0x%x]" % S_T0)
    a("fsub d0, d0, d1")
    a("adr x9, dbl_cap")
    a("ldr d1, [x9]")
    a("fcmp d0, d1")
    a("b.ge .Lp_timeout")
    a("bl pump_once")
    a("b .Lp_loop")

    # ---- teardown -------------------------------------------------------
    a.label(".Lp_choice")
    a.label(".Lp_timeout")
    a.label(".Lp_bail")
    a("ldr x0, [x22, #0x%x]" % S_WINDOW)
    a("cbz x0, .Lp_ret")
    a.many(ldslot(GOT_MSGSEND, "x19"))
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
    # x0 = a connected UIWindowScene, or 0.  A scene app's windows are only
    # displayed when they belong to a scene, and the scene is connected
    # through the run loop, so pump for up to 2 s while waiting for it.
    a.label("find_scene")
    a("sub sp, sp, #0x20")
    a("stp x29, x30, [sp, #0x00]")
    a("str wzr, [sp, #0x10]")
    a.label(".Lfs_loop")
    a("adr x0, cstr_UIApplication")
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

    # one 0.1 s slice of kCFRunLoopDefaultMode.  Clobbers x0..x9, d0..d1.
    a.label("pump_once")
    a("sub sp, sp, #0x20")
    a("stp x29, x30, [sp, #0x00]")
    a("adr x0, cstr_NSDate")
    a("blr x20")
    a("cbz x0, .Lpu_ret")
    a("adr x9, dbl_tick")
    a("ldr d0, [x9]")
    a.many(ldsel("dateWithTimeIntervalSinceNow"))
    a("mov x1, x9")
    a("blr x19")
    a("cbz x0, .Lpu_ret")
    a("str x0, [sp, #0x10]")
    a("adr x0, cstr_NSRunLoop")
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

    # d0 = [[NSDate date] timeIntervalSinceReferenceDate]
    a.label("now_seconds")
    a("sub sp, sp, #0x10")
    a("stp x29, x30, [sp, #0x00]")
    a("adr x0, cstr_NSDate")
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
    a.label("blk_yuuki")
    a("mov w0, #%d" % MODE_YUUKI)
    a("b choose")
    a.label("blk_official")
    a("mov w0, #%d" % MODE_OFFICIAL)
    a("b choose")

    # w0 = requested mode.  Records the choice so the pump stops.  Same mode
    # as the one already applied -> just return (the panel hides the window
    # once the handler has unwound).  Different mode -> persist, flush,
    # exit(0) so the next launch applies it before Unity initialises.
    a.label("choose")
    a("sub sp, sp, #0x40")
    a("stp x19, x20, [sp, #0x00]")
    a("stp x21, x22, [sp, #0x10]")
    a("stp x23, x24, [sp, #0x20]")
    a("stp x29, x30, [sp, #0x30]")
    a("adrp x22, 0x%x" % SCRATCH)
    a("str w0, [x22, #0x%x]" % S_CHOICE)
    a("ldr w9, [x22, #0x%x]" % S_MODE)
    a("cmp w0, w9")
    a("b.eq .Lc_ret")
    a("mov w23, w0")                     # requested mode
    a("ldr x21, [x22, #0x%x]" % S_DEFAULTS)
    a("cbz x21, .Lc_ret")                # cannot persist -> never exit/loop
    a("ldr x24, [x22, #0x%x]" % S_KEYOBJ)
    a("cbz x24, .Lc_ret")
    a.many(ldslot(GOT_MSGSEND, "x19"))
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

    # exit(0) -- not linked, so resolve it through dlsym at runtime
    a.many(ldslot(GOT_DLSYM, "x20"))
    a("mov x0, #-2")                     # RTLD_DEFAULT
    a("adr x1, cstr_exit")
    a("blr x20")
    a("cbz x0, .Lc_ret")
    a("mov x19, x0")
    a("mov w0, #0")
    a("blr x19")                         # never returns
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
    a.cstr("cstr_mode", MODE_KEY)
    a.cstr("cstr_runmode", RUNMODE)
    a.cstr("cstr_exit", "exit")
    a.cstr("str_title", TITLE)
    a.cstr("str_msg", MSG)
    a.cstr("str_official", OFFICIAL)
    a.cstr("str_yuuki", YUUKI)
    a.align(8)
    a.emit("blk_desc", struct.pack("<QQ", 0, 32))
    a.emit("dbl_level", struct.pack("<d", WINDOW_LEVEL))
    a.emit("dbl_tick", struct.pack("<d", TICK))
    a.emit("dbl_cap", struct.pack("<d", PANEL_CAP))

    src = "\n".join(a.lines)
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    enc, cnt = ks.asm(src, CODE_BASE)
    return bytes(enc), src, cnt, a.labels


def main():
    blob, src, cnt, labels = build()
    print("assembled %d instructions, %d bytes" % (cnt, len(blob)))
    print("code %#x .. %#x  limit %#x  free left %d"
          % (CODE_BASE, CODE_BASE + len(blob), CODE_LIMIT,
             CODE_LIMIT - CODE_BASE - len(blob)))
    if CODE_BASE + len(blob) > CODE_LIMIT:
        raise SystemExit("PAYLOAD TOO BIG")
    assert labels["hook_start"] == CODE_BASE
    info = {"code_base": CODE_BASE, "code_end": labels["end_code"],
            "labels": labels, "size": len(blob)}
    open("payload.bin", "wb").write(blob)
    open("payload.s", "w").write(src)
    open("payload.json", "w").write(json.dumps(info, indent=2))
    for k in ("hook_start", "apply_mode", "panel", "pump_once", "now_seconds",
              "choose", "blk_yuuki", "blk_official", "end_code"):
        print("  %-12s %#x" % (k, labels[k]))
    print("wrote payload.bin, payload.s, payload.json")


if __name__ == "__main__":
    main()
