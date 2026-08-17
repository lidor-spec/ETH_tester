#!/usr/bin/env python3
"""Does the report tell the truth?

Inject a KNOWN, deliberate amount of frame loss and check what the tool
reports. If the tool flatters reality, these numbers will disagree.

Test 1: uniform 0.5% loss on one direction, unidirectional  -> must report 0.5%
Test 2: 2% loss on A->B only, while B->A is clean, bidirectional
        -> must FAIL, and must not dilute the bad direction into the average
Test 3: a single burst of consecutive drops in the middle   -> must be counted
Test 4: loss of the very LAST frames (invisible to seq gaps) -> must be counted
Test 5: live samples vs final number - is the final one the honest one?
"""
import sys, time
sys.path.insert(0, "/home/claude/ethswitch")
import eth_switch_tester as E
from eth_switch_tester import Config, Session, TestSuite, get_if_hwaddr

A, B = "veth0", "veth1"
cfg = Config(iface_a=A, iface_b=B, mac_a=get_if_hwaddr(A), mac_b=get_if_hwaddr(B),
             link_mbps=100, frame_size=512, rate_mode="pps", rate_value=2000,
             duration=5.0, loss_threshold_pct=0.10)

# ---- a saboteur that drops frames on purpose -------------------------------
class Saboteur:
    """Wraps RawSender.send and silently discards selected frames."""
    def __init__(self):
        self.mode = None
        self.n = {}
        self.dropped = {}
        self.orig = E.RawSender.send
        outer = self

        def send(self_sender, data):
            iface = str(self_sender.iface)
            i = outer.n.get(iface, 0)
            outer.n[iface] = i + 1
            if outer._should_drop(iface, i):
                outer.dropped[iface] = outer.dropped.get(iface, 0) + 1
                return                      # frame never reaches the wire
            return outer.orig(self_sender, data)

        E.RawSender.send = send

    def _should_drop(self, iface, i):
        m = self.mode
        if not m:
            return False
        kind, target, param = m
        if target and target not in iface:
            return False
        if kind == "every":
            return i % param == 0
        if kind == "window":
            return param[0] <= i < param[1]
        if kind == "tail":
            return i >= param
        return False

    def set(self, kind, target, param):
        self.mode = (kind, target, param)
        self.n.clear(); self.dropped.clear()

    def off(self):
        self.mode = None

    def restore(self):
        E.RawSender.send = self.orig


sab = Saboteur()
samples = []
def emit(kind, payload):
    if kind == "sample":
        samples.append(payload)

s = Session(cfg, emit)
s.open()
fails = []
def check(name, cond, detail):
    print(("  PASS  " if cond else "  >>FAIL<<  ") + name + " -- " + detail)
    if not cond:
        fails.append(name)

try:
    # ------------------------------------------------------------- test 1
    print("\n=== TEST 1: uniform 1-in-200 (0.5%) loss, unidirectional ===")
    sab.set("every", "veth0", 200)
    r = s.run_stream(size=512, pps=2000, duration=5.0, bidir=False, live=False)
    real = sab.dropped.get("veth0", 0)
    tx = r["tx_frames"]
    truth = real / tx * 100.0
    print(f"    deliberately dropped {real} of {tx} frames = {truth:.4f}% actual")
    print(f"    tool reports loss_pct = {r['loss_pct']:.4f}%   lost = {r['lost']}")
    check("test1 loss count exact", abs(r["lost"] - real) <= 2,
          f"reported {r['lost']} vs actual {real}")
    check("test1 loss pct accurate", abs(r["loss_pct"] - truth) < 0.05,
          f"reported {r['loss_pct']:.4f}% vs actual {truth:.4f}%")
    sab.off()

    # ------------------------------------------------------------- test 2
    print("\n=== TEST 2: 2% loss on A->B only, B->A clean, BIDIRECTIONAL ===")
    print("    (does a single bad direction get diluted by the good one?)")
    sab.set("every", "veth0", 50)
    r2 = s.run_stream(size=512, pps=2000, duration=5.0, bidir=True, live=False)
    real2 = sab.dropped.get("veth0", 0)
    a2b = r2["streams"].get("A->B", {})
    b2a = r2["streams"].get("B->A", {})
    print(f"    deliberately dropped {real2} frames, all on A->B")
    print(f"    A->B reported loss = {a2b.get('loss_pct',0):.4f}%  (lost {a2b.get('lost')})")
    print(f"    B->A reported loss = {b2a.get('loss_pct',0):.4f}%  (lost {b2a.get('lost')})")
    print(f"    AGGREGATE headline = {r2['loss_pct']:.4f}%")
    check("test2 bad direction measured", abs(a2b.get("lost", 0) - real2) <= 3,
          f"A->B lost {a2b.get('lost')} vs actual {real2}")
    check("test2 good direction clean", b2a.get("lost", 0) <= 2,
          f"B->A lost {b2a.get('lost')}")
    suite = TestSuite(s, emit)
    ok, det = suite._verdict(r2)
    print(f"    verdict -> {'PASS' if ok else 'FAIL'}: {det}")
    check("test2 verdict must FAIL", not ok,
          "a 2% failure in one direction must not pass")
    worst = max(v.get("loss_pct", 0) for v in r2["streams"].values())
    check("test2 headline not understated", abs(r2["loss_pct"] - worst) < 0.2,
          f"headline {r2['loss_pct']:.4f}% vs worst direction {worst:.4f}%"
          " (averaging the two directions hides a one-way fault)")
    sab.off()

    # ------------------------------------------------------------- test 3
    print("\n=== TEST 3: consecutive burst of 300 drops in the middle ===")
    sab.set("window", "veth0", (2000, 2300))
    r3 = s.run_stream(size=512, pps=2000, duration=5.0, bidir=False, live=False)
    real3 = sab.dropped.get("veth0", 0)
    print(f"    dropped {real3} consecutive frames; tool reports lost={r3['lost']}")
    check("test3 burst loss counted", abs(r3["lost"] - real3) <= 2,
          f"reported {r3['lost']} vs actual {real3}")
    sab.off()

    # ------------------------------------------------------------- test 4
    print("\n=== TEST 4: the LAST 150 frames dropped (no sequence gap follows) ===")
    sab.set("tail", "veth0", 0)   # placeholder, set precisely below
    # send a fixed count so we know where the tail is
    sab.set("tail", "veth0", 1850)
    r4 = s.run_stream(size=512, pps=2000, duration=0, count=2000, bidir=False, live=False)
    real4 = sab.dropped.get("veth0", 0)
    print(f"    dropped the final {real4} frames; tool reports lost={r4['lost']}"
          f"  (tx={r4['tx_frames']} rx={r4['rx_frames']})")
    check("test4 tail loss counted", abs(r4["lost"] - real4) <= 2,
          f"reported {r4['lost']} vs actual {real4} - tail loss is invisible to "
          f"sequence gaps and must come from the TX counter")
    sab.off()

    # ------------------------------------------------------------- test 5
    print("\n=== TEST 5: live samples vs final number, on a CLEAN run ===")
    samples.clear()
    r5 = s.run_stream(size=512, pps=2000, duration=5.0, bidir=False, live=True)
    live_max = max((x["loss_pct"] for x in samples), default=0.0)
    print(f"    highest loss shown live   = {live_max:.4f}%")
    print(f"    final reported loss       = {r5['lost']} frames / {r5['loss_pct']:.4f}%")
    print(f"    frames tx={r5['tx_frames']} rx={r5['rx_frames']}")
    check("test5 clean run is truly clean", r5["lost"] <= 2,
          f"final lost={r5['lost']} on an unsabotaged run")
    if live_max > 0.05 and r5["lost"] <= 2:
        print(f"    NOTE: live view peaked at {live_max:.3f}% but no frames were "
              f"actually lost -> the live spike is a mid-flight sampling artifact, "
              f"the final number is the honest one.")
finally:
    sab.restore()
    s.close()

print("\n" + "=" * 68)
print("VERDICT:", "no dishonesty found" if not fails else f"PROBLEMS: {fails}")
