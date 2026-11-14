#!/usr/bin/env python3
"""Execute the v7 payload under Unicorn with a mocked UIKit/ObjC runtime.

What is being proved here, for the real payload bytes:

  * the static address audit passes against main_signed.bin
  * a custom UIWindow is built from the app's connected UIWindowScene
    (initWithWindowScene:, because iOS 13 scene apps never display a window
    made with initWithFrame:), falling back to initWithFrame:[UIScreen bounds]
    for a legacy app, given windowLevel 2001.0, a plain UIViewController root
    and makeKeyAndVisible
  * a scene that connects late is picked up by pumping the run loop
  * the alert is presented on that window's controller, non-animated, with two
    actions whose handlers are global blocks pointing into the payload
  * the main thread is blocked in a run-loop pump (kCFRunLoopDefaultMode,
    NSDate +0.1 s slices) and a tap is dispatched *inside* that pump, exactly
    like UIKit does - the handler runs before runMode:beforeDate: returns
  * tap the active server -> no write, no exit, window hidden, startUnity: runs
  * tap the other server  -> one write, synchronize, exit(0); startUnity: is
    never reached, because the process is gone before it can be
  * a relaunch then applies the stored mode *before* the original startUnity:
  * an untouched panel times out after 60 s of run-loop time, is dismissed,
    and startup continues with the key that was already applied
  * no UIScreen and no scene / no NSUserDefaults -> silent degradation, never
    a crash and never an exit (no restart loop)
"""
import json
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_ALL
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_X30,
    UC_ARM64_REG_D0, UC_ARM64_REG_D1, UC_ARM64_REG_D2, UC_ARM64_REG_D3,
)

ORIG_START = 0x10001774C
SENTINEL = 0x200000000
# real __DATA_CONST __got slots (two pages), verified in the bind table
GOT_PAGE = 0x1139F8000
GOT_MSGSEND = 0x1139F9B70
GOT_GETCLASS = 0x1139F9B48
GOT_DLSYM = 0x1139F8C40
GOT_GLOBALBLOCK = 0x1139F8B90
SCRATCH = 0x11604F000
SELREGION = 0x115260000
FAKE = 0x300000000
HEAP = 0x400000000
STACK = 0x500000000
KEY_OFFICIAL = 0x1139F34A8
KEY_STRING = 0x115286118            # stringWithUTF8String:

SEL_SLOTS = {
    "alloc": 0x1152744E8,
    "init": 0x11527A378,
    "initWithFrame:": 0x11527AA68,
    "initWithWindowScene:": 0x11527B180,
    "mainScreen": 0x11527D238,
    "connectedScenes": 0x115276500,
    "anyObject": 0x1152746C8,
    "sharedApplication": 0x115285388,
    "bounds": 0x115275350,
    "setWindowLevel:": 0x115285088,
    "setRootViewController:": 0x115284288,
    "makeKeyAndVisible": 0x11527D270,
    "setHidden:": 0x115282BA8,
    "presentViewController:animated:completion:": 0x11527EFC8,
    "alertControllerWithTitle:message:preferredStyle:": 0x115272518,
    "actionWithTitle:style:handler:": 0x115272520,
    "addAction:": 0x115272528,
    "stringWithUTF8String:": KEY_STRING,
    "date": 0x1152770C0,
    "timeIntervalSinceReferenceDate": 0x1152866B8,
    "dateWithTimeIntervalSinceNow:": 0x1152770F8,
    "currentRunLoop": 0x115276E40,
    "runMode:beforeDate:": 0x115280970,
    "standardUserDefaults": 0x115285B38,
    "integerForKey:": 0x11527B3C8,
    "setInteger:forKey:": 0x115282D48,
    "synchronize": 0x115286398,
}

W = 390.0
H = 844.0
LEVEL = 2001.0
TICK = 0.1
CAP = 60.0


def dbits(v):
    return struct.unpack("<Q", struct.pack("<d", v))[0]


class Sim:
    def __init__(self, payload, meta, store=None, taps=None, clock_step=5.0,
                 screen=True, defaults=True, scene=True, scene_delay=0):
        self.meta = meta
        self.store = dict(store or {})
        self.taps = list(taps or [])
        self.clock_step = clock_step
        self.has_screen = screen
        self.has_defaults = defaults
        self.has_scene = scene
        self.scene_delay = scene_delay
        self.scene_used = None
        self.frame_used = None
        self.window_scene = None
        self.build_pumps = None

        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u = self.uc
        u.mem_map(0x100000000, 0x4000, UC_PROT_ALL)
        u.mem_map(0x100017000, 0x1000, UC_PROT_ALL)
        u.mem_map(SENTINEL, 0x1000, UC_PROT_ALL)
        u.mem_map(GOT_PAGE, 0x2000, UC_PROT_ALL)
        u.mem_map(SELREGION, 0x40000, UC_PROT_ALL)
        u.mem_map(SCRATCH, 0x1000, UC_PROT_ALL)
        u.mem_map(FAKE, 0x10000, UC_PROT_ALL)
        u.mem_map(HEAP, 0x100000, UC_PROT_ALL)
        u.mem_map(STACK, 0x20000, UC_PROT_ALL)

        u.mem_write(0x1000031C0, payload)
        u.mem_write(ORIG_START, b"\xc0\x03\x5f\xd6")   # ret
        u.hook_add(UC_HOOK_CODE, self._hook_orig_start, begin=ORIG_START, end=ORIG_START)

        self.calls = []
        self.objects = {}
        self.classes = {}
        self.heap_next = HEAP
        self.blocks = []
        self.presented = []
        self.hidden = []
        self.key_window = None
        self.level = None
        self.frame = None
        self.init_frame = None
        self.root_vc = None
        self.pump_modes = []
        self.pumps = 0
        self.ticks = []
        self.exited = []
        self.writes = []
        self.slot_at_orig_start = None
        self.orig_start_calls = 0
        self.clock = 1000.0
        self.dashed = None
        self.unhandled = []
        self.animations = []

        self.strbase = FAKE + 0x8000
        self.strnext = self.strbase

        def putstr(s):
            b = s.encode() + b"\x00"
            a = self.strnext
            u.mem_write(a, b)
            self.strnext += (len(b) + 7) & ~7
            return a

        self.putstr = putstr
        for name, slot in SEL_SLOTS.items():
            u.mem_write(slot, struct.pack("<Q", putstr(name)))

        self.fn_msg = FAKE + 0x1000
        self.fn_getclass = FAKE + 0x1100
        self.fn_isa = FAKE + 0x1200
        self.fn_dlsym = FAKE + 0x1300
        self.fn_exit = FAKE + 0x1500
        u.mem_write(GOT_MSGSEND, struct.pack("<Q", self.fn_msg))
        u.mem_write(GOT_GETCLASS, struct.pack("<Q", self.fn_getclass))
        u.mem_write(GOT_GLOBALBLOCK, struct.pack("<Q", self.fn_isa))
        u.mem_write(GOT_DLSYM, struct.pack("<Q", self.fn_dlsym))
        for a in (self.fn_msg, self.fn_getclass, self.fn_isa, self.fn_dlsym,
                  self.fn_exit):
            u.mem_write(a, b"\xc0\x03\x5f\xd6")

        u.hook_add(UC_HOOK_CODE, self._hook_msg, begin=self.fn_msg, end=self.fn_msg)
        u.hook_add(UC_HOOK_CODE, self._hook_getclass, begin=self.fn_getclass,
                   end=self.fn_getclass)
        u.hook_add(UC_HOOK_CODE, self._hook_dlsym, begin=self.fn_dlsym,
                   end=self.fn_dlsym)
        u.hook_add(UC_HOOK_CODE, self._hook_exit, begin=self.fn_exit,
                   end=self.fn_exit)

    # ---------------- helpers ----------------
    def rd(self, a, n=8):
        return self.uc.mem_read(a, n)

    def u64(self, a):
        return struct.unpack("<Q", self.rd(a, 8))[0]

    def cstr(self, a):
        out = b""
        while True:
            b = self.uc.mem_read(a, 1)
            if b[0] == 0:
                return out.decode()
            out += b
            a += 1

    def new_obj(self, cls, **kw):
        p = self.heap_next
        self.heap_next += 0x100
        self.objects[p] = {"cls": cls, **kw}
        return p

    def new_class(self, name):
        p = self.classes.get(name)
        if p is None:
            p = self.new_obj(name, is_class=True)
            self.classes[name] = p
        return p

    def _ret(self, val=None):
        u = self.uc
        if val is not None:
            u.reg_write(UC_ARM64_REG_X0, val)
        u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_X30))

    def _ret_d(self, d0=0.0, d1=0.0, d2=0.0, d3=0.0):
        u = self.uc
        u.reg_write(UC_ARM64_REG_D0, dbits(d0))
        u.reg_write(UC_ARM64_REG_D1, dbits(d1))
        u.reg_write(UC_ARM64_REG_D2, dbits(d2))
        u.reg_write(UC_ARM64_REG_D3, dbits(d3))
        u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_X30))

    def _rd_d(self, reg):
        return struct.unpack("<d", struct.pack("<Q", self.uc.reg_read(reg)))[0]

    def text_of(self, p):
        return self.objects.get(p, {}).get("text")

    # ---------------- fake runtime ----------------
    def _hook_orig_start(self, uc, addr, size, user):
        self.orig_start_calls += 1
        self.slot_at_orig_start = self.u64(SCRATCH)
        self.calls.append(("orig", "startUnity slot=%#x" % self.slot_at_orig_start))
        self._ret(0)

    def _hook_dlsym(self, uc, addr, size, user):
        name = self.cstr(uc.reg_read(UC_ARM64_REG_X1))
        self.calls.append(("dlsym", name))
        self._ret(self.fn_exit if name == "exit" else 0)

    def _hook_exit(self, uc, addr, size, user):
        self.exited.append(uc.reg_read(UC_ARM64_REG_X0))
        uc.emu_stop()

    def _hook_getclass(self, uc, addr, size, user):
        name = self.cstr(uc.reg_read(UC_ARM64_REG_X0))
        self._ret(self.new_class(name))

    def _hook_msg(self, uc, addr, size, user):
        recv = uc.reg_read(UC_ARM64_REG_X0)
        sel = self.cstr(uc.reg_read(UC_ARM64_REG_X1))
        a2 = uc.reg_read(UC_ARM64_REG_X2)
        a3 = uc.reg_read(UC_ARM64_REG_X3)
        a4 = uc.reg_read(UC_ARM64_REG_X4)
        info = self.objects.get(recv)
        self.calls.append(("msg", (info or {}).get("cls", "?"), sel))

        if info and info.get("is_class"):
            cls = info["cls"]
            if sel == "stringWithUTF8String:":
                return self._ret(self.new_obj("NSString", text=self.cstr(a2)))
            if sel == "standardUserDefaults":
                if not self.has_defaults:
                    return self._ret(0)
                d = self.new_obj("NSUserDefaults")
                self.defaults = d
                return self._ret(d)
            if sel == "mainScreen":
                if not self.has_screen:
                    return self._ret(0)
                self.screen = self.new_obj("UIScreen")
                return self._ret(self.screen)
            if sel == "sharedApplication":
                self.app = self.new_obj("UIApplication")
                return self._ret(self.app)
            if sel == "date":
                return self._ret(self.new_obj("NSDate"))
            if sel == "dateWithTimeIntervalSinceNow:":
                self.ticks.append(self._rd_d(UC_ARM64_REG_D0))
                return self._ret(self.new_obj("NSDate"))
            if sel == "currentRunLoop":
                return self._ret(self.new_obj("NSRunLoop"))
            if sel == "alloc":
                return self._ret(self.new_obj(cls))
            if sel == "alertControllerWithTitle:message:preferredStyle:":
                o = self.new_obj("UIAlertController",
                                 title=self.text_of(a2), msg=self.text_of(a3),
                                 style=a4, actions=[])
                self.alert = o
                return self._ret(o)
            if sel == "actionWithTitle:style:handler:":
                t = self.text_of(a2)
                o = self.new_obj("UIAlertAction", title=t, style=a3, handler=a4)
                isa, flags, resv, invoke, desc = struct.unpack(
                    "<QiiQQ", self.rd(a4, 32))
                self.blocks.append({"title": t, "isa": isa, "flags": flags,
                                    "invoke": invoke, "desc": desc, "addr": a4})
                return self._ret(o)
            self.unhandled.append(("class", cls, sel))
            return self._ret(0)

        cls = (info or {}).get("cls")
        if sel == "connectedScenes":
            if not self.has_scene:
                return self._ret(self.new_obj("NSSet", empty=True))
            return self._ret(self.new_obj("NSSet", empty=False))
        if sel == "anyObject":
            if not info.get("empty") and self.pumps >= self.scene_delay:
                self.scene = self.new_obj("UIWindowScene")
                return self._ret(self.scene)
            return self._ret(0)
        if sel == "initWithWindowScene:":
            self.window_scene = a2
            self.build_pumps = self.pumps
            self.scene_used = True
            return self._ret(recv)
        if sel == "initWithFrame:":
            self.frame_used = True
            self.build_pumps = self.pumps
            self.init_frame = (self._rd_d(UC_ARM64_REG_D0), self._rd_d(UC_ARM64_REG_D1),
                              self._rd_d(UC_ARM64_REG_D2), self._rd_d(UC_ARM64_REG_D3))
            return self._ret(recv)
        if sel == "init":
            return self._ret(recv)
        if sel == "bounds":
            self.frame = (0.0, 0.0, W, H)
            return self._ret_d(0.0, 0.0, W, H)
        if sel == "setWindowLevel:":
            self.level = self._rd_d(UC_ARM64_REG_D0)
            return self._ret(0)
        if sel == "setRootViewController:":
            self.root_vc = a2
            return self._ret(0)
        if sel == "makeKeyAndVisible":
            self.key_window = recv
            return self._ret(0)
        if sel == "setHidden:":
            self.hidden.append(bool(a2))
            return self._ret(0)
        if sel == "presentViewController:animated:completion:":
            self.presented.append(a2)
            self.animations.append(a3)
            return self._ret(0)
        if sel == "addAction:":
            info.setdefault("actions", []).append(a2)
            return self._ret(0)
        if sel == "integerForKey:":
            key = self.text_of(a2)
            v = self.store.get(key, 0)
            self.calls.append(("read", key, v))
            return self._ret(v)
        if sel == "setInteger:forKey:":
            key = self.text_of(a3)
            self.store[key] = a2
            self.writes.append((key, a2))
            return self._ret(0)
        if sel == "synchronize":
            self.calls.append(("synchronize",))
            return self._ret(0)
        if sel == "timeIntervalSinceReferenceDate":
            self.clock += self.clock_step
            return self._ret_d(self.clock)
        if sel == "dateWithTimeIntervalSinceNow:":
            self.ticks.append(self._rd_d(UC_ARM64_REG_D0))
            return self._ret(self.new_obj("NSDate"))
        if sel == "runMode:beforeDate:":
            self.pumps += 1
            self.pump_modes.append(self.text_of(a2))
            if self.taps and self.blocks:
                title = self.taps.pop(0)
                blk = next(b for b in self.blocks if b["title"] == title)
                # dispatch the handler the way UIKit does: inside the run loop
                uc.reg_write(UC_ARM64_REG_X0, blk["addr"])
                uc.reg_write(UC_ARM64_REG_PC, blk["invoke"])
                return
            return self._ret(1)
        self.unhandled.append((cls, sel))
        return self._ret(0)

    # ---------------- drivers ----------------
    def _run(self, entry):
        u = self.uc
        u.reg_write(UC_ARM64_REG_SP, STACK + 0x10000)
        u.reg_write(UC_ARM64_REG_X0, 0x12345678)     # self
        u.reg_write(UC_ARM64_REG_X1, 0xABCD)         # _cmd
        u.reg_write(UC_ARM64_REG_X30, SENTINEL)
        u.emu_start(entry, SENTINEL, count=4000000)
        return self

    def run_start(self):
        return self._run(self.meta["labels"]["hook_start"])

    # ---------------- observations ----------------
    @property
    def slot(self):
        return self.u64(SCRATCH)

    @property
    def mode(self):
        return self.u64(SCRATCH + 0xA8)

    @property
    def choice(self):
        return self.u64(SCRATCH + 0x0C) & 0xFFFFFFFF

    @property
    def sp_ok(self):
        return self.uc.reg_read(UC_ARM64_REG_SP) == STACK + 0x10000

    @property
    def stopped_pc(self):
        return self.uc.reg_read(UC_ARM64_REG_PC)


YUUKI = "YuukiPS (private)"
OFFICIAL = "HoYoverse (official)"


def report(s, label):
    print("\n=== %s ===" % label)
    print("  stopped pc        : %#x" % s.stopped_pc)
    print("  orig startUnity   : %d" % s.orig_start_calls)
    print("  slot at startUnity: %s"
          % ("-" if s.slot_at_orig_start is None else hex(s.slot_at_orig_start)))
    print("  key slot now      : %#x   applied mode %d" % (s.slot, s.mode))
    print("  sp restored       : %s" % s.sp_ok)
    print("  window level      : %s   frame %s" % (s.level, s.frame))
    print("  window via scene  : %s (scene %s)   via frame: %s (frame arg %s)"
          % (s.scene_used, hex(s.window_scene) if s.window_scene else None,
             s.frame_used, s.init_frame))
    print("  pumps before build: %s" % s.build_pumps)
    print("  key window        : %s   root vc set: %s"
          % (s.key_window is not None, s.root_vc is not None))
    print("  alerts presented  : %d  animated=%s"
          % (len(s.presented), s.animations))
    print("  actions           : %s" % [b["title"] for b in s.blocks])
    print("  pumps             : %d  modes %s"
          % (s.pumps, sorted(set(m for m in s.pump_modes if m))))
    print("  ticks             : %s" % sorted(set(s.ticks)))
    print("  window hidden     : %s" % s.hidden)
    print("  defaults writes   : %s" % (s.writes or "none"))
    print("  exits             : %s" % (s.exited or "none"))
    print("  unhandled         : %s" % (s.unhandled or "none"))


def main():
    payload = open("payload.bin", "rb").read()
    meta = json.load(open("payload.json"))
    ok = True

    def bad(msg):
        nonlocal ok
        print("  !! " + msg)
        ok = False

    print("static address audit against main_signed.bin ...")
    import audit_payload
    errs = audit_payload.audit(payload, code_end=meta["code_end"], verbose=False)
    print("  %d problem(s)" % len(errs))
    for e in errs:
        print("  !! " + e)
    ok = ok and not errs

    # ---- 1. first launch, tap the active server --------------------------
    s = Sim(payload, meta, taps=[YUUKI])
    s.run_start()
    report(s, "first launch (no stored mode) -> panel, tap YuukiPS (already active)")
    if s.slot_at_orig_start != 0:
        bad("Yuuki key was not in the slot when startUnity was entered")
    if s.mode != 1:
        bad("applied mode is %d, expected 1" % s.mode)
    if s.level != LEVEL:
        bad("window level %r, expected %r" % (s.level, LEVEL))
    if not s.scene_used:
        bad("window was not built with initWithWindowScene:")
    if s.frame_used:
        bad("scene app window fell back to initWithFrame:")
    if s.window_scene is None:
        bad("window has no window scene")
    if s.key_window is None or s.root_vc is None:
        bad("window was not made key/visible with a root view controller")
    if len(s.presented) != 1:
        bad("alert presented %d times, expected 1" % len(s.presented))
    if s.animations != [0]:
        bad("alert must be presented without animation, got %r" % (s.animations,))
    if [b["title"] for b in s.blocks] != [YUUKI, OFFICIAL]:
        bad("action titles wrong: %r" % [b["title"] for b in s.blocks])
    for b in s.blocks:
        if b["flags"] != 0x10000000:
            bad("block flags %#x" % b["flags"])
        if b["isa"] != s.fn_isa:
            bad("block isa %#x is not __NSConcreteGlobalBlock" % b["isa"])
        if not (0x1000031C0 <= b["invoke"] < 0x1000031C0 + len(payload)):
            bad("block invoke %#x outside payload" % b["invoke"])
        if struct.unpack("<QQ", s.rd(b["desc"], 16)) != (0, 32):
            bad("block descriptor wrong")
    if s.pumps < 1:
        bad("main thread was never blocked in the run-loop pump")
    if sorted(set(s.pump_modes)) != ["kCFRunLoopDefaultMode"]:
        bad("pump mode(s) %r" % (s.pump_modes,))
    if sorted(set(s.ticks)) != [TICK]:
        bad("pump tick %r, expected %r" % (sorted(set(s.ticks)), TICK))
    if s.writes or s.exited:
        bad("tapping the active server must not write or exit")
    if s.hidden != [True]:
        bad("the panel window was not hidden after the choice: %r" % (s.hidden,))
    if s.orig_start_calls != 1:
        bad("original startUnity called %d times, expected 1" % s.orig_start_calls)
    if not s.sp_ok:
        bad("stack not restored")

    # ---- 2. first launch, switch to official -> save + exit -------------
    s2 = Sim(payload, meta, taps=[OFFICIAL])
    s2.run_start()
    report(s2, "first launch -> tap HoYoverse: persist mode, flush, exit(0)")
    if s2.writes != [("keyswitch.mode", 2)]:
        bad("expected one write of mode 2, got %r" % (s2.writes,))
    if not any(c[0] == "synchronize" for c in s2.calls):
        bad("defaults were not flushed")
    if s2.exited != [0]:
        bad("expected exit(0), got %r" % (s2.exited,))
    if s2.orig_start_calls != 0:
        bad("Unity was started after exit(0) - the restart is broken")

    # ---- 3. relaunch: official already applied, tap official ------------
    s3 = Sim(payload, meta, store=s2.store, taps=[OFFICIAL])
    s3.run_start()
    report(s3, "relaunch (mode 2) -> official key before startUnity, tap official")
    if s3.slot_at_orig_start != KEY_OFFICIAL:
        bad("official key was not in the slot at startUnity (%s)"
            % (hex(s3.slot_at_orig_start or 0)))
    if s3.mode != 2:
        bad("applied mode %d, expected 2" % s3.mode)
    if s3.writes or s3.exited:
        bad("re-tapping the active server must not restart")
    if s3.hidden != [True] or s3.orig_start_calls != 1:
        bad("official continue path wrong (hidden=%r start=%d)"
            % (s3.hidden, s3.orig_start_calls))

    # ---- 4. switch back to Yuuki ----------------------------------------
    s4 = Sim(payload, meta, store={"keyswitch.mode": 2}, taps=[YUUKI])
    s4.run_start()
    report(s4, "switch back to YuukiPS: persist mode 1, exit(0)")
    if s4.slot != KEY_OFFICIAL:
        bad("this launch should have applied the official key")
    if s4.writes != [("keyswitch.mode", 1)] or s4.exited != [0]:
        bad("switch back did not persist + exit: %r %r" % (s4.writes, s4.exited))
    if s4.orig_start_calls != 0:
        bad("Unity started after exit(0)")
    s5 = Sim(payload, meta, store=s4.store, taps=[YUUKI])
    s5.run_start()
    report(s5, "relaunch after switching back -> Yuuki key before startUnity")
    if s5.slot_at_orig_start != 0 or s5.mode != 1:
        bad("relaunch did not apply the Yuuki key")

    # ---- 5. nobody taps: 60 s failsafe, then normal startup -------------
    s6 = Sim(payload, meta, taps=[], clock_step=5.0)
    s6.run_start()
    report(s6, "panel ignored -> 60 s failsafe, dismiss, startUnity normally")
    if s6.pumps < 5:
        bad("pump ran only %d times" % s6.pumps)
    if s6.hidden != [True]:
        bad("timed-out panel was not hidden")
    if s6.writes or s6.exited:
        bad("failsafe must not write or exit")
    if s6.orig_start_calls != 1:
        bad("startUnity did not run after the failsafe")
    if s6.slot_at_orig_start != 0:
        bad("key slot changed on the failsafe path")

    # ---- 6. no scene and no UIScreen: silent degradation ----------------
    s7 = Sim(payload, meta, screen=False, scene=False, taps=[OFFICIAL])
    s7.run_start()
    report(s7, "no scene, no UIScreen -> panel build bails, startUnity runs, no exit")
    if s7.presented:
        bad("presented an alert without a screen")
    if s7.scene_used or s7.frame_used:
        bad("built a window without a scene or a screen")
    if s7.exited or s7.writes:
        bad("must not exit when the panel could not be built")
    if s7.orig_start_calls != 1:
        bad("startUnity did not run")
    if s7.slot_at_orig_start != 0 or not s7.sp_ok:
        bad("bail path left the key slot/stack wrong")

    # ---- 7. legacy (non-scene) app: fall back to initWithFrame: ---------
    s10 = Sim(payload, meta, scene=False, screen=True, taps=[YUUKI])
    s10.run_start()
    report(s10, "no scene -> snapshot pump gives up, initWithFrame: fallback")
    if s10.scene_used:
        bad("used a scene that does not exist")
    if not s10.frame_used:
        bad("legacy app did not fall back to initWithFrame:")
    if s10.init_frame != (0.0, 0.0, W, H):
        bad("legacy window frame %r" % (s10.init_frame,))
    if s10.build_pumps != 20:
        bad("waited %r pumps for a scene, expected 20" % (s10.build_pumps,))
    if len(s10.presented) != 1 or s10.hidden != [True]:
        bad("legacy panel did not present/hide: %r %r"
            % (s10.presented, s10.hidden))
    if s10.orig_start_calls != 1:
        bad("startUnity did not run on the legacy path")

    # ---- 8. scene connects late: retry pump finds it --------------------
    s11 = Sim(payload, meta, scene_delay=4, taps=[YUUKI])
    s11.run_start()
    report(s11, "scene appears after 4 run-loop turns -> retry pump picks it up")
    if not s11.scene_used or s11.frame_used:
        bad("late scene was not used (scene=%r frame=%r)"
            % (s11.scene_used, s11.frame_used))
    if s11.build_pumps != 4:
        bad("expected 4 waits for the late scene, got %r" % (s11.build_pumps,))
    if len(s11.presented) != 1 or s11.orig_start_calls != 1:
        bad("late-scene panel did not run normally")

    # ---- 9. panel is shown only once per process ------------------------
    s8 = Sim(payload, meta, taps=[YUUKI])
    s8.run_start()
    s8.run_start()
    report(s8, "startUnity called twice in one process -> panel once")
    if len(s8.presented) != 1:
        bad("panel presented %d times in one process" % len(s8.presented))
    if s8.orig_start_calls != 2:
        bad("original startUnity should run per call, got %d"
            % s8.orig_start_calls)

    # ---- 10. NSUserDefaults unavailable: never exit (no restart loop) ---
    s9 = Sim(payload, meta, defaults=False, taps=[OFFICIAL])
    s9.run_start()
    report(s9, "no NSUserDefaults -> cannot persist -> continue, never exit")
    if s9.exited:
        bad("exited without being able to persist the choice (restart loop)")
    if s9.writes:
        bad("wrote defaults that do not exist")
    if s9.orig_start_calls != 1:
        bad("startUnity did not run after the unpersistable choice")
    if s9.slot_at_orig_start != 0 or s9.mode != 1:
        bad("mode should still be Yuuki when defaults are unavailable")

    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
