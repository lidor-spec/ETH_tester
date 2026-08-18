"""Why is there no RX data? Answers it in one run.

Injects frames on adapter A and watches adapter B three ways at once:
  1. Npcap capture      - frames the tool would have counted
  2. NDIS good-frame counter on B
  3. NDIS RX ERROR counter on B  <- the discriminator

    Npcap > 0                      -> forwarding works
    Npcap 0, RX ERRORS climbing    -> frames ARRIVE but are CORRUPT (physical/clock)
    Npcap 0, RX ERRORS flat        -> nothing arrives at all (port not forwarding)

Run it once with the bad board, once with the good one, and compare.
    python setup_scripts\\probe_forwarding.py "Ethernet 3" "Ethernet 4"
"""
import subprocess
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eth_switch_tester import (  # noqa: E402
    RawSender, Receiver, StreamStats, build_template, stamp, now_ns,
    get_if_hwaddr, BROADCAST, STREAM_A2B, SCAPY_OK, SCAPY_ERR,
)

A = sys.argv[1] if len(sys.argv) > 1 else "Ethernet 3"
B = sys.argv[2] if len(sys.argv) > 2 else "Ethernet 4"
N, PPS, SIZE = 4000, 2000, 512


def ndis(name):
    ps = ("Get-NetAdapterStatistics -Name '%s' | ForEach-Object { "
          "\"{0} {1} {2} {3}\" -f ($_.ReceivedUnicastPackets + "
          "$_.ReceivedNonUnicastPackets), $_.ReceivedPacketErrors, "
          "$_.ReceivedDiscardedPackets, ($_.SentUnicastPackets + "
          "$_.SentNonUnicastPackets) }" % name)
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                         capture_output=True, text=True, timeout=25).stdout.split()
    return [int(x) for x in out[:4]] if len(out) >= 4 else [0, 0, 0, 0]


def main():
    if not SCAPY_OK:
        print("scapy unavailable:", SCAPY_ERR)
        return 1
    mac_a, mac_b = get_if_hwaddr(A), get_if_hwaddr(B)
    print(f"A (inject) : {A}  {mac_a}")
    print(f"B (listen) : {B}  {mac_b}")
    print(f"sending {N} broadcast frames of {SIZE} B at {PPS} pps\n")

    st = StreamStats("A->B")
    rx = Receiver(B, {STREAM_A2B: st}, expect_stream=STREAM_A2B)
    rx.start()
    print(f"capture backend on B: {rx.mode}")
    snd = RawSender(A)

    before_b = ndis(B)
    tpl = build_template(BROADCAST, mac_a, SIZE, STREAM_A2B)
    t0 = time.perf_counter()
    iv = 1.0 / PPS
    for i in range(N):
        while (time.perf_counter() - t0) < i * iv:
            time.sleep(0)
        stamp(tpl, i, now_ns())
        snd.send(tpl)
    el = time.perf_counter() - t0
    time.sleep(1.2)
    after_b = ndis(B)
    kdrop = rx.kernel_drops()
    rx.stop()
    snd.close()

    s = st.snapshot()
    d_ok, d_err, d_dis, _ = (after_b[i] - before_b[i] for i in range(4))
    print(f"\nsent            : {N} in {el:.2f} s ({N/el:.0f} pps)")
    print(f"Npcap captured  : {s['rx_frames']}")
    print(f"kernel drops    : {kdrop}")
    print(f"B good frames   : {d_ok}")
    print(f"B RX ERRORS     : {d_err}   <-- FCS / alignment")
    print(f"B RX discarded  : {d_dis}")

    print("\n" + "=" * 62)
    if s["rx_frames"] > N * 0.9:
        print("FORWARDING OK - this board carries frames A->B.")
    elif s["rx_frames"] > 0:
        loss = 100.0 * (1 - s["rx_frames"] / N)
        print(f"PARTIAL: {loss:.1f}% missing. Marginal link, not a dead port.")
        print("Suspect signal integrity / termination / cable.")
    elif d_err > 0 or d_dis > 0:
        print("FRAMES ARRIVE BUT ARE CORRUPT.")
        print("The PHY sees energy and the NIC discards every frame on FCS, so")
        print("Npcap never sees one. This is PHYSICAL, not configuration:")
        print("  - 25 MHz reference clock: crystal load caps, marginal solder,")
        print("    wrong part -> link still trains but every frame bit-errors")
        print("  - magnetics: wrong/absent centre-tap caps, swapped pairs")
        print("  - termination: missing 49.9R, impedance, long stubs")
        print("  - supply noise on the PHY rails / missing decoupling")
    else:
        print("NOTHING ARRIVES - and not one corrupt frame either.")
        print("The port is linked but the fabric is not forwarding to it:")
        print("  - strap resistors differ from the working board (compare them)")
        print("  - KSZ8895 port receive/transmit-enable or port isolation")
        print("  - EEPROM / register config loaded on this unit only")
        print("  - fabric-side fault: link is a PHY-level property and comes up")
        print("    even when the switch core never forwards a frame")
    print("=" * 62)
    print("\nNow swap boards and run again - the difference is the diagnosis.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
