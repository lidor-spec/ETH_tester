#!/usr/bin/env python3
"""Verify single-adapter reflection mode end to end.

veth0 = the 'USB adapter' running ReflectSession
veth1 = a stand-in for the router: a responder that answers ARP + ICMP echo

Also cross-checks our hand-built IP/ICMP headers against scapy's dissector,
which recomputes and validates the checksums independently.
"""
import sys, threading, time
sys.path.insert(0, "/home/claude/ethswitch")
from eth_switch_tester import (  # noqa: E402
    Config, ReflectSession, RawSender, Receiver, build_arp_request,
    parse_arp_reply, build_icmp_template, stamp_icmp, parse_icmp_reply,
    mac_str_to_bytes, mac_bytes_to_str, ip_to_bytes, bytes_to_ip, now_ns,
    get_if_hwaddr, _cksum, _IP_OFF, _ICMP_OFF,
)

A, B = "veth0", "veth1"
MAC_A, MAC_B = get_if_hwaddr(A), get_if_hwaddr(B)
IP_A, IP_B = "10.99.0.1", "10.99.0.2"

# ---------------------------------------------------------------- 1. headers
print("=== 1. header construction cross-checked against scapy ===")
from scapy.all import Ether, IP, ICMP, ARP, checksum as scapy_cksum  # noqa: E402

tpl = build_icmp_template(MAC_B, MAC_A, IP_A, IP_B, 128, 0x1234)
stamp_icmp(tpl, 42, 1234567890123)
pkt = Ether(bytes(tpl))
assert pkt.haslayer(IP) and pkt.haslayer(ICMP), pkt.summary()
ip, ic = pkt[IP], pkt[ICMP]
print(f"    scapy sees: {pkt.summary()}")
print(f"    len={len(tpl)+4} on-wire  ip.len={ip.len}  proto={ip.proto}  "
      f"src={ip.src} dst={ip.dst}  icmp.type={ic.type} id={ic.id} seq={ic.seq}")
assert ip.src == IP_A and ip.dst == IP_B, (ip.src, ip.dst)
assert ip.len == len(tpl) - 14, (ip.len, len(tpl))
assert ic.type == 8 and ic.id == 0x1234 and ic.seq == 42, (ic.type, ic.id, ic.seq)
# scapy recomputes checksums when we delete + rebuild; compare to ours
raw_before = bytes(tpl)
del pkt[IP].chksum, pkt[ICMP].chksum
raw_after = bytes(Ether(raw_before[:14]) / pkt[IP])
assert raw_after[24:26] == raw_before[24:26], "IP checksum mismatch vs scapy"
assert raw_after[36:38] == raw_before[36:38], "ICMP checksum mismatch vs scapy"
print("    IP + ICMP checksums match scapy's independent computation  OK")

arp = build_arp_request(MAC_A, IP_A, IP_B)
ap = Ether(arp)
assert ap.haslayer(ARP) and ap[ARP].op == 1 and ap[ARP].pdst == IP_B, ap.summary()
assert ap.dst == "ff:ff:ff:ff:ff:ff", ap.dst
print(f"    ARP request: {ap.summary()}  OK")

# round-trip our own parser through a synthetic reply
reply = bytearray(tpl)
reply[0:6], reply[6:12] = mac_str_to_bytes(MAC_A), mac_str_to_bytes(MAC_B)
reply[_IP_OFF+12:_IP_OFF+16] = ip_to_bytes(IP_B)
reply[_IP_OFF+16:_IP_OFF+20] = ip_to_bytes(IP_A)
reply[_ICMP_OFF] = 0
got = parse_icmp_reply(bytes(reply))
assert got == (0, 42, 1234567890123), got
print(f"    parse_icmp_reply -> {got}  OK")

# ------------------------------------------------------------- 2. responder
print("\n=== 2. responder on veth1 (stands in for your router) ===")
stop = threading.Event()
served = {"arp": 0, "icmp": 0}
snd_b = RawSender(B)


def responder(data, rx_ns):
    # ARP request for IP_B -> send reply
    if len(data) >= 42 and data[12] == 0x08 and data[13] == 0x06:
        import struct
        if struct.unpack_from("!H", data, 20)[0] == 1 and bytes_to_ip(data[38:42]) == IP_B:
            r = bytearray(60)
            r[0:6] = data[6:12]
            r[6:12] = mac_str_to_bytes(MAC_B)
            struct.pack_into("!H", r, 12, 0x0806)
            struct.pack_into("!HHBBH", r, 14, 1, 0x0800, 6, 4, 2)
            r[22:28] = mac_str_to_bytes(MAC_B)
            r[28:32] = ip_to_bytes(IP_B)
            r[32:38] = data[22:28]
            r[38:42] = data[28:32]
            snd_b.send(bytes(r))
            served["arp"] += 1
        return
    # ICMP echo request -> echo reply (swap MACs/IPs, type 8->0, fix cksum)
    if len(data) >= 42 and data[12] == 0x08 and data[13] == 0x00 and data[23] == 1:
        if data[34] != 8:
            return
        r = bytearray(data)
        r[0:6], r[6:12] = data[6:12], data[0:6]
        r[26:30], r[30:34] = data[30:34], data[26:30]
        r[34] = 0
        import struct
        struct.pack_into("!H", r, 36, 0)
        struct.pack_into("!H", r, 36, _cksum(r, 34, len(r) - 34))
        snd_b.send(bytes(r))
        served["icmp"] += 1


rx_b = Receiver(B, {}, raw_hook=responder, bpf_override="arp or icmp")
rx_b.start()
print(f"    responder listening on {B} ({rx_b.mode}), MAC {MAC_B}")

# ------------------------------------------------------------- 3. the mode
print("\n=== 3. ReflectSession on veth0 (your one adapter) ===")
cfg = Config(link_mbps=100, loss_threshold_pct=1.0)
rs = ReflectSession(cfg, A, MAC_A, IP_A, IP_B, lambda k, p: (
    print("   LOG:", p) if k == "log" else None))
rs.open()
try:
    mac = rs.resolve_target(timeout=5.0)
    assert mac == MAC_B, (mac, MAC_B)
    print(f"    ARP resolved target -> {mac}  OK")

    for size, pps, dur in ((64, 500, 3.0), (512, 1000, 3.0), (1400, 500, 2.0)):
        r = rs.run(size=size, pps=pps, duration=dur, live=False)
        print(f"    {size:5d}B @{pps:5d}pps  tx={r['tx_frames']:5d} rx={r['rx_frames']:5d} "
              f"loss={r['loss_pct']:6.3f}%  RTT avg={r['rtt_avg_us']:8.1f}us "
              f"min={r['lat_min_us']:7.1f} p99={r['p99']:8.1f} jit={r['jitter']:6.1f} "
              f"switch~{r['switch_us_estimate']:.1f}us hostdrop={r['host_capture_drops']}")
        assert r["tx_frames"] > pps * dur * 0.9, r["tx_frames"]
        assert r["rx_frames"] > r["tx_frames"] * 0.9, (r["rx_frames"], r["tx_frames"])
        assert r["loss_pct"] < 5.0, r["loss_pct"]
        assert r["rtt_avg_us"] > 0
finally:
    stop.set()
    rs.close()
    rx_b.stop()
    snd_b.close()

print(f"\n    responder served {served['arp']} ARP + {served['icmp']} ICMP")
assert served["icmp"] > 1000, served
print("\nREFLECTION MODE VERIFIED END TO END")
