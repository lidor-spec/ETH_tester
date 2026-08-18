"""Verify the preflight gate against the board that is actually connected."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eth_switch_tester import (  # noqa: E402
    Config, Session, PreflightError, get_if_hwaddr,
)

A = sys.argv[1] if len(sys.argv) > 1 else "Ethernet 3"
B = sys.argv[2] if len(sys.argv) > 2 else "Ethernet 4"
cfg = Config(iface_a=A, iface_b=B, mac_a=get_if_hwaddr(A), mac_b=get_if_hwaddr(B),
             link_mbps=100, frame_size=512, loss_threshold_pct=0.10)
s = Session(cfg, lambda k, p: print("   ", p) if k == "log" else None)
s.open()
try:
    print("\n--- running preflight ---")
    r = s.preflight()
    print("\nRESULT: preflight PASSED - frames cross in both directions")
    for k, v in r.items():
        print(f"   {k}: {v['rx']}/{v['tx']} arrived, "
              f"NIC FCS errors {v['nic_rx_errors']}")
    print("\n(so on this board the suite would be allowed to run)")
except PreflightError as e:
    print("\nRESULT: preflight correctly REFUSED to run")
    print("=" * 68)
    print(e)
    print()
    print(e.detail)
    print("=" * 68)
finally:
    s.close()
