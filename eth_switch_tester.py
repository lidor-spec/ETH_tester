#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 ETH SWITCH TESTER  v1.0
=============================================================================
 Layer-2 Ethernet switch validation tool with a live GUI dashboard.

 Designed for testing an UNMANAGED L2 switch from a Windows PC using
 two USB-to-Ethernet adapters (one into switch port X = TX, one into
 switch port Y = RX).

 It does NOT use TCP/IP. It injects raw Ethernet frames with a private
 EtherType (0x88B5, IEEE "local experimental 1"), each carrying a
 sequence number and a high-resolution transmit timestamp. That means:

   * Packet loss is measured exactly (sequence gaps), not inferred.
   * Latency uses the Npcap kernel capture timestamp on RX.
   * The OS TCP/IP stack, Nagle, window scaling etc. cannot distort results.
   * Out-of-order and duplicate frames are detected.

 REQUIREMENTS
   Windows 10/11, Python 3.9+
   Npcap   -> https://npcap.com  (install with "WinPcap API-compatible mode")
   pip install scapy
   RUN AS ADMINISTRATOR (raw injection requires it)

 Author: generated for Skypulse-tec switch bring-up
=============================================================================
"""

from __future__ import annotations

import csv
import html
import json
import os
import queue
import random
import re
import statistics
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# Scapy import (guarded so the file can be inspected without scapy present)
# --------------------------------------------------------------------------
SCAPY_OK = True
SCAPY_ERR = ""
try:
    # Ask scapy to use libpcap/Npcap BEFORE it initialises its architecture
    # layer. That unlocks kernel-side BPF filtering and raw (non-dissected)
    # packet reads, which is what keeps the receiver from dropping frames.
    from scapy.config import conf as scapy_conf  # type: ignore
    scapy_conf.use_pcap = True
    from scapy.all import AsyncSniffer, Raw, get_if_hwaddr, sendp  # type: ignore
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore
    except Exception:  # not on Windows
        get_windows_if_list = None  # type: ignore
except Exception as _e:  # pragma: no cover
    SCAPY_OK = False
    SCAPY_ERR = str(_e)
    get_windows_if_list = None  # type: ignore


# ==========================================================================
# 1. CONSTANTS / CLOCK / HELPERS
# ==========================================================================

ETHERTYPE = 0x88B5              # IEEE Std 802 local experimental EtherType 1
MAGIC = b"SWTS"                 # payload magic
HDR_FMT = "!4sBBBBIQ"           # magic, ver, stream, flags, rsv, seq, tx_ns
HDR_LEN = struct.calcsize(HDR_FMT)          # 20
ETH_HDR_LEN = 14
MIN_FRAME = 64                  # on-wire incl. 4-byte FCS
MAX_FRAME = 1518
FCS_LEN = 4
IFG_PREAMBLE = 20               # 12B inter-frame gap + 8B preamble/SFD
VERSION = 1

BROADCAST = "ff:ff:ff:ff:ff:ff"
SNAPLEN = 128                   # capture only the header we actually parse

# Let the capture thread get the GIL back quickly from the transmit loop.
try:
    sys.setswitchinterval(0.0008)
except Exception:
    pass

# high-resolution wall clock: epoch base + monotonic delta
_T0_WALL = time.time_ns()
_T0_PERF = time.perf_counter_ns()


def now_ns() -> int:
    """Epoch nanoseconds with monotonic (sub-microsecond) resolution."""
    return _T0_WALL + (time.perf_counter_ns() - _T0_PERF)


def mac_str_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.replace("-", ":").split(":"))


def mac_bytes_to_str(b: bytes) -> str:
    return ":".join("%02x" % x for x in b)


def random_local_mac() -> str:
    """Locally-administered, unicast, almost certainly never seen by the DUT."""
    o = [0x02, random.randrange(256), random.randrange(256),
         random.randrange(256), random.randrange(256), random.randrange(256)]
    return ":".join("%02x" % x for x in o)


def line_rate_pps(frame_size: int, link_mbps: int) -> float:
    """Theoretical max frames/s for a given on-wire frame size (incl. FCS)."""
    return (link_mbps * 1_000_000.0) / ((frame_size + IFG_PREAMBLE) * 8.0)


def mbps(byte_count: int, seconds: float, frame_count: int = 0) -> float:
    """Wire-rate Mbps. Adds IFG+preamble+FCS overhead if frame_count given."""
    if seconds <= 0:
        return 0.0
    total = byte_count + frame_count * (FCS_LEN + IFG_PREAMBLE)
    return (total * 8.0) / seconds / 1_000_000.0


def human_pps(v: float) -> str:
    if v >= 1_000_000:
        return f"{v/1e6:.2f} M"
    if v >= 1000:
        return f"{v/1e3:.1f} k"
    return f"{v:.0f}"


# ==========================================================================
# 2. FRAME BUILD / PARSE
# ==========================================================================

def build_template(dst: str, src: str, size: int, stream_id: int,
                   pattern: bytes = b"") -> bytearray:
    """
    Build a frame template. `size` is on-wire size INCLUDING the 4-byte FCS
    that the NIC appends, so we emit (size - 4) bytes.
    """
    size = max(MIN_FRAME, min(int(size), 9018))     # allow jumbo up to 9018
    emit = size - FCS_LEN
    buf = bytearray(emit)
    buf[0:6] = mac_str_to_bytes(dst)
    buf[6:12] = mac_str_to_bytes(src)
    struct.pack_into("!H", buf, 12, ETHERTYPE)
    struct.pack_into(HDR_FMT, buf, ETH_HDR_LEN, MAGIC, VERSION, stream_id, 0, 0, 0, 0)
    # deterministic payload fill (helps spot bit errors / stuck bits)
    fill_start = ETH_HDR_LEN + HDR_LEN
    if fill_start < emit:
        if pattern:
            p = (pattern * ((emit - fill_start) // len(pattern) + 1))[: emit - fill_start]
        else:
            p = bytes((i * 7 + 0x5A) & 0xFF for i in range(emit - fill_start))
        buf[fill_start:] = p
    return buf


def build_vlan_template(dst: str, src: str, size: int, stream_id: int,
                        vid: int, pcp: int = 0) -> bytearray:
    """
    Same test frame but 802.1Q-tagged. The KSZ8895 has VLAN support, and a tag
    shifts every subsequent field by 4 bytes - a classic place for a switch to
    mis-parse, mis-forward or strip incorrectly.
    """
    inner = build_template(dst, src, max(MIN_FRAME, size - 4), stream_id)
    buf = bytearray(inner[:12])
    buf += struct.pack("!HH", 0x8100, ((pcp & 7) << 13) | (vid & 0x0FFF))
    buf += inner[12:]
    return buf


SEQ_OFF = ETH_HDR_LEN + 4 + 1 + 1 + 1 + 1     # offset of seq field
TS_OFF = SEQ_OFF + 4                          # offset of tx_ns field


def stamp(buf: bytearray, seq: int, tx_ns: int) -> None:
    """
    Write the sequence number and transmit timestamp.

    An 802.1Q tag shifts every field after the MACs by 4 bytes, so the offsets
    must be computed, not assumed - writing at the untagged offsets in a tagged
    frame silently corrupts the payload and destroys the measurement.
    """
    if buf[12] == 0x81 and buf[13] == 0x00:
        struct.pack_into("!I", buf, SEQ_OFF + 4, seq & 0xFFFFFFFF)
        struct.pack_into("!Q", buf, TS_OFF + 4, tx_ns)
    else:
        struct.pack_into("!I", buf, SEQ_OFF, seq & 0xFFFFFFFF)
        struct.pack_into("!Q", buf, TS_OFF, tx_ns)


def payload_ok(data: bytes) -> bool:
    """
    Verify the deterministic filler written by build_template.

    A switch that mangles a frame (bad SERDES, marginal PHY, buffer aliasing)
    can still deliver it with a valid length and sequence number. Counting only
    arrivals would call that a pass, so we spot-check the payload bytes.
    Capture snaplen limits how much of the frame we see, which is fine - a
    corrupting path shows up in the first bytes too.
    """
    start = ETH_HDR_LEN + HDR_LEN
    if len(data) > 13 and data[12] == 0x81 and data[13] == 0x00:
        start += 4
    n = len(data)
    if n <= start:
        return True
    k = 0
    i = start
    while i < n:
        if data[i] != ((k * 7 + 0x5A) & 0xFF):
            return False
        k += 1
        i += 1
    return True


def expected_pay_byte(k: int) -> int:
    """The k-th filler byte build_template() writes. Ground truth for RX."""
    return (k * 7 + 0x5A) & 0xFF


def payload_bit_errors(data: bytes) -> Tuple[int, int, List[int], int]:
    """
    Compare the received payload against what was transmitted, bit by bit.

    There is no analogue sampling here - we cannot see the MLT-3 line levels.
    What we CAN do is prove the digital result: every bit that entered the
    switch came out the other side with the same value. Returns
    (bits_compared, bit_errors, per-bit-position error counts, first_bad_byte).
    """
    start = ETH_HDR_LEN + HDR_LEN
    if len(data) > 13 and data[12] == 0x81 and data[13] == 0x00:
        start += 4
    n = len(data)
    if n <= start:
        return 0, 0, [0] * 8, -1
    bits = 0
    errs = 0
    by_pos = [0] * 8
    first_bad = -1
    for i in range(start, n):
        exp = expected_pay_byte(i - start)
        got = data[i]
        bits += 8
        if got != exp:
            x = got ^ exp
            if first_bad < 0:
                first_bad = i - start
            for b in range(8):
                if x & (1 << b):
                    errs += 1
                    by_pos[b] += 1
    return bits, errs, by_pos, first_bad


class BitTap:
    """
    Ring buffer of recently received frames, kept for the timing/bit view.

    Deliberately small and lock-protected: the capture thread must never block
    on the GUI, and we only need enough frames to draw a diagram.
    """

    def __init__(self, maxlen: int = 400):
        self.lock = threading.Lock()
        self.maxlen = maxlen
        self.frames: List[Dict] = []
        self.bits_compared = 0
        self.bit_errors = 0
        self.by_pos = [0] * 8
        self.enabled = False

    def reset(self) -> None:
        with self.lock:
            self.frames = []
            self.bits_compared = 0
            self.bit_errors = 0
            self.by_pos = [0] * 8

    def add(self, seq: int, tx_ns: int, rx_ns: int, data: bytes) -> None:
        b, e, pos, first_bad = payload_bit_errors(data)
        with self.lock:
            self.bits_compared += b
            self.bit_errors += e
            for i in range(8):
                self.by_pos[i] += pos[i]
            self.frames.append({"seq": seq, "tx_ns": tx_ns, "rx_ns": rx_ns,
                                "lat_ns": rx_ns - tx_ns, "data": data,
                                "bit_errors": e, "first_bad": first_bad})
            if len(self.frames) > self.maxlen:
                del self.frames[0:len(self.frames) - self.maxlen]

    def snapshot(self) -> Dict:
        with self.lock:
            return {"frames": list(self.frames), "bits": self.bits_compared,
                    "errors": self.bit_errors, "by_pos": list(self.by_pos)}


def parse(data: bytes) -> Optional[Tuple[int, int, int]]:
    """Return (stream_id, seq, tx_ns) if this is one of our frames."""
    if len(data) < ETH_HDR_LEN + HDR_LEN:
        return None
    off = ETH_HDR_LEN
    if data[12] == 0x81 and data[13] == 0x00:      # 802.1Q tag present
        if len(data) < off + 4 + HDR_LEN:
            return None
        if data[16] != 0x88 or data[17] != 0xB5:
            return None
        off += 4
    elif data[12] != 0x88 or data[13] != 0xB5:
        return None
    if data[off:off + 4] != MAGIC:
        return None
    stream_id = data[off + 5]
    seq = struct.unpack_from("!I", data, off + 8)[0]
    tx_ns = struct.unpack_from("!Q", data, off + 12)[0]
    return stream_id, seq, tx_ns


# ==========================================================================
# 3. STATISTICS
# ==========================================================================

class StreamStats:
    """
    Thread-safe RFC-2544-style counters for one unidirectional stream.
    Loss is derived from sequence numbers, not from a received-set, so
    memory stays constant at any packet count.
    """

    MAX_LAT_SAMPLES = 400_000

    def __init__(self, label: str = ""):
        self.label = label
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.tx_frames = 0
            self.tx_bytes = 0
            self.rx_frames = 0
            self.rx_bytes = 0
            self.rx_foreign = 0        # frames on the wire that aren't ours
            self.highest_seq = -1
            self.reorder = 0
            self.dup_suspect = 0
            self.lat_ns: List[int] = []
            self.lat_seen = 0
            self.lat_sum = 0
            self.lat_min = None
            self.lat_max = None
            self.lat_last = 0
            self.prev_lat = None
            self.jitter_ns = 0.0
            self.first_rx_ns = None
            self.last_rx_ns = None
            self.tx_start_ns = None
            self.tx_end_ns = None
            self.errors = 0
            self.bad_payload = 0
            self.payload_checked = 0

    # ---- TX side -------------------------------------------------------
    def note_tx_begin(self) -> None:
        """Called immediately before the first frame leaves."""
        with self.lock:
            if self.tx_start_ns is None:
                self.tx_start_ns = now_ns()

    def note_tx_end(self) -> None:
        """Called immediately after the last frame leaves."""
        with self.lock:
            self.tx_end_ns = now_ns()

    def on_tx(self, n: int, nbytes: int) -> None:
        with self.lock:
            self.tx_frames += n
            self.tx_bytes += nbytes

    # ---- RX side -------------------------------------------------------
    def note_payload(self, ok: bool) -> None:
        with self.lock:
            self.payload_checked += 1
            if not ok:
                self.bad_payload += 1

    def on_rx(self, seq: int, tx_ns: int, rx_ns: int, nbytes: int) -> None:
        with self.lock:
            self.rx_frames += 1
            self.rx_bytes += nbytes
            if self.first_rx_ns is None:
                self.first_rx_ns = rx_ns
            self.last_rx_ns = rx_ns
            if seq > self.highest_seq:
                self.highest_seq = seq
            elif seq == self.highest_seq:
                self.dup_suspect += 1
            else:
                self.reorder += 1
            lat = rx_ns - tx_ns
            if -1_000_000_000 < lat < 10_000_000_000:
                self.lat_last = lat
                self.lat_sum += lat
                if self.lat_min is None or lat < self.lat_min:
                    self.lat_min = lat
                if self.lat_max is None or lat > self.lat_max:
                    self.lat_max = lat
                # Reservoir sampling: a plain cap would fill up early in a long
                # run and bias p50/p95/p99 towards the first seconds, hiding
                # degradation that appears later. This keeps the sample
                # uniformly spread over the whole run.
                self.lat_seen += 1
                if len(self.lat_ns) < self.MAX_LAT_SAMPLES:
                    self.lat_ns.append(lat)
                else:
                    j = random.randrange(self.lat_seen)
                    if j < self.MAX_LAT_SAMPLES:
                        self.lat_ns[j] = lat
                # RFC 3550 interarrival jitter estimate
                if self.prev_lat is not None:
                    d = abs(lat - self.prev_lat)
                    self.jitter_ns += (d - self.jitter_ns) / 16.0
                self.prev_lat = lat

    # ---- snapshot ------------------------------------------------------
    def snapshot(self) -> Dict:
        with self.lock:
            good = self.rx_frames - self.dup_suspect
            # CONFIRMED loss: only gaps below the highest sequence we have
            # actually seen. A frame still in flight has not been lost, and
            # counting it as lost is what manufactured phantom spikes in the
            # live view. This is the honest number to display DURING a run.
            seen_span = self.highest_seq + 1 if self.highest_seq >= 0 else 0
            lost_confirmed = max(0, seen_span - good)
            # TOTAL loss: also covers frames dropped at the very END of a run,
            # which leave no following gap and are only visible by comparing
            # against the transmit counter. Correct only AFTER the drain wait.
            expected = max(seen_span, self.tx_frames)
            lost = max(0, expected - good)
            loss_pct = (lost / expected * 100.0) if expected else 0.0
            loss_pct_confirmed = ((lost_confirmed / seen_span * 100.0)
                                  if seen_span else 0.0)
            n = len(self.lat_ns)
            avg = (self.lat_sum / max(1, self.rx_frames)) if self.rx_frames else 0
            return dict(
                label=self.label,
                tx_frames=self.tx_frames, tx_bytes=self.tx_bytes,
                rx_frames=self.rx_frames, rx_bytes=self.rx_bytes,
                rx_foreign=self.rx_foreign,
                expected=expected, lost=lost, loss_pct=loss_pct,
                lost_confirmed=lost_confirmed, loss_pct_confirmed=loss_pct_confirmed,
                in_flight=max(0, self.tx_frames - seen_span),
                reorder=self.reorder, dup=self.dup_suspect,
                lat_min_us=(self.lat_min / 1000.0) if self.lat_min is not None else 0.0,
                lat_max_us=(self.lat_max / 1000.0) if self.lat_max is not None else 0.0,
                lat_avg_us=avg / 1000.0,
                jitter_us=self.jitter_ns / 1000.0,
                lat_samples=n,
                bad_payload=self.bad_payload,
                payload_checked=self.payload_checked,
            )

    def percentiles(self) -> Dict[str, float]:
        with self.lock:
            s = sorted(self.lat_ns)
        if not s:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "jitter": 0.0}

        def pct(p):
            i = min(len(s) - 1, max(0, int(round(p / 100.0 * (len(s) - 1)))))
            return s[i] / 1000.0
        return {"p50": pct(50), "p95": pct(95), "p99": pct(99),
                "jitter": self.jitter_ns / 1000.0}


# ==========================================================================
# 4. RAW SOCKETS: SENDER + RECEIVER
# ==========================================================================

class RawSender:
    """Fast L2 injector. Prefers the underlying pcap handle over scapy layers."""

    def __init__(self, iface):
        if not SCAPY_OK:
            raise RuntimeError("scapy not available: " + SCAPY_ERR)
        self.iface = iface
        self.sock = scapy_conf.L2socket(iface=iface)
        self._out = getattr(self.sock, "outs", None)
        self._mode = None  # 'pcap' | 'scapy' | 'sendp'

    def send(self, data: bytes) -> None:
        if self._mode is None:
            self._probe(data)
        if self._mode == "pcap":
            self._out.send(data)
        elif self._mode == "scapy":
            self.sock.send(Raw(load=data))
        else:
            sendp(Raw(load=data), iface=self.iface, verbose=0)

    def _probe(self, data: bytes) -> None:
        if self._out is not None:
            try:
                self._out.send(data)
                self._mode = "pcap"
                return
            except Exception:
                pass
        try:
            self.sock.send(Raw(load=data))
            self._mode = "scapy"
            return
        except Exception:
            pass
        self._mode = "sendp"
        sendp(Raw(load=data), iface=self.iface, verbose=0)

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass


_OPEN_PCAP_CACHE: List = []


def _get_open_pcap():
    """
    Return scapy's raw libpcap/Npcap wrapper, or None.

    On Windows with Npcap this is always present. On Linux scapy only defines
    it when conf.use_pcap is set, so we opt in and reload once.
    """
    if _OPEN_PCAP_CACHE:
        return _OPEN_PCAP_CACHE[0]
    if not SCAPY_OK:
        return None
    fn = None
    try:
        import importlib
        import scapy.arch.libpcap as _lp  # type: ignore
        fn = getattr(_lp, "open_pcap", None)
        if fn is None:
            prev = getattr(scapy_conf, "use_pcap", False)
            try:
                scapy_conf.use_pcap = True
                _lp = importlib.reload(_lp)
                fn = getattr(_lp, "open_pcap", None)
            finally:
                scapy_conf.use_pcap = prev
    except Exception:
        fn = None
    _OPEN_PCAP_CACHE.append(fn)
    return fn


class Receiver:
    """
    Packet capture for one port.

    Two back-ends, tried in order:
      1. Direct libpcap/Npcap handle  -> raw bytes, NO scapy dissection,
         kernel-side BPF filter, and pcap_stats() so host-side drops are
         reported separately from real switch loss. This is the fast path.
      2. scapy AsyncSniffer          -> fallback, dissects every frame in
         Python and will itself drop frames above ~20-40 kpps.
    """

    def __init__(self, iface, stats_by_stream: Dict[int, StreamStats],
                 raw_hook: Optional[Callable[[bytes, float], None]] = None,
                 expect_stream: Optional[int] = None,
                 parse_fn: Optional[Callable] = None,
                 bpf_override: Optional[str] = None):
        if not SCAPY_OK:
            raise RuntimeError("scapy not available: " + SCAPY_ERR)
        self.iface = iface
        self.stats_by_stream = stats_by_stream
        self.raw_hook = raw_hook
        # A capture handle on the TX adapter also sees our own outbound
        # frames. Narrowing the kernel filter to the stream we expect to
        # RECEIVE stops that echo from flooding the capture buffer.
        self.expect_stream = expect_stream
        # Reflection mode swaps in an ICMP parser and its own kernel filter.
        self.parse_fn = parse_fn or parse
        self.bpf_override = bpf_override
        self.check_payload = parse_fn is None
        self.bit_tap: Optional[BitTap] = None
        self.sniffer = None
        self.pcap = None
        self._thread = None
        self._stop = threading.Event()
        self.mode = "none"
        self.filtered = False
        self.foreign = 0
        self.total = 0
        self.kernel_drop_base = 0

    def _bpf(self) -> str:
        """Kernel filter: our EtherType, and (if known) only the stream we
        should be receiving on this port. Byte 19 of the frame is stream_id."""
        if self.bpf_override:
            return self.bpf_override
        # "ether proto" alone misses 802.1Q-tagged frames, so match both the
        # untagged EtherType and the tagged one (vlan shifts fields by 4).
        base = "ether proto 0x88b5 or (vlan and ether proto 0x88b5)"
        if self.expect_stream is not None:
            return (f"(ether proto 0x88b5 and ether[19] = {self.expect_stream}) "
                    f"or (vlan and ether proto 0x88b5 and ether[23] = "
                    f"{self.expect_stream})")
        return base

    # ---- shared frame handler -------------------------------------------
    def _handle(self, data: bytes, rx_ns: int, wire_len: int = 0) -> None:
        self.total += 1
        if self.raw_hook is not None:
            try:
                self.raw_hook(data, rx_ns)
            except Exception:
                pass
        p = self.parse_fn(data)
        if p is None:
            self.foreign += 1
            return
        stream_id, seq, tx_ns = p
        st = self.stats_by_stream.get(stream_id)
        if st is not None:
            st.on_rx(seq, tx_ns, rx_ns, (wire_len or len(data)) + FCS_LEN)
            # spot-check 1 frame in 64 for corruption (cheap at any rate)
            if self.check_payload and (self.total & 0x3F) == 0:
                st.note_payload(payload_ok(data))
                tap = self.bit_tap
                if tap is not None and tap.enabled:
                    tap.add(seq, tx_ns, rx_ns, data)

    # ---- back-end 1: raw libpcap ----------------------------------------
    def _start_pcap(self, bpf_all: bool) -> bool:
        open_pcap = _get_open_pcap()
        if open_pcap is None:
            return False
        try:
            # Small snaplen: we only need the header, and copying 128 B per
            # frame instead of 1518 B keeps the reader ahead of the wire.
            p = open_pcap(self.iface, SNAPLEN, True, 1)
        except Exception:
            return False
        # Enlarge the kernel capture buffer (Npcap/WinPcap extension) and ask
        # the driver to hand packets over promptly.
        try:
            from scapy.libs.winpcapy import pcap_setbuff, pcap_setmintocopy  # type: ignore
            try:
                pcap_setbuff(p.pcap, 32 * 1024 * 1024)
            except Exception:
                pass
            try:
                pcap_setmintocopy(p.pcap, 16 * 1024)
            except Exception:
                pass
        except Exception:
            pass
        if not bpf_all:
            for flt in (self._bpf(), "ether proto 0x88b5"):
                try:
                    p.setfilter(flt)
                    self.filtered = True
                    break
                except Exception:
                    continue
        self.pcap = p
        self.kernel_drop_base = self.kernel_drops()
        self._stop.clear()
        self._thread = threading.Thread(target=self._pcap_loop, daemon=True)
        self._thread.start()
        self.mode = "pcap+bpf" if self.filtered else "pcap"
        time.sleep(0.25)
        return True

    def _pcap_loop(self) -> None:
        """
        Tight capture loop.

        scapy's own _PcapWrapper.next() converts the packet with
        bytes(bytearray(ptr[:n])), which is a per-byte ctypes conversion and
        far too slow to keep up. We call pcap_next_ex directly and use
        ctypes.string_at(), which is a single memcpy.
        """
        p = self.pcap
        stop = self._stop
        try:
            from ctypes import POINTER, byref, c_ubyte, string_at
            from scapy.libs.winpcapy import pcap_next_ex, pcap_pkthdr  # type: ignore
        except Exception:
            # last resort: scapy's slow wrapper
            nxt = p.next
            while not stop.is_set():
                try:
                    ts, data = nxt()
                except Exception:
                    break
                if data is not None:
                    self._handle(data, int(ts * 1e9))
            return

        hdr = POINTER(pcap_pkthdr)()
        buf = POINTER(c_ubyte)()
        handle = self._handle
        pcap = p.pcap
        stopped = stop.is_set
        while not stopped():
            try:
                rc = pcap_next_ex(pcap, byref(hdr), byref(buf))
            except Exception:
                break
            if rc != 1:
                if rc < 0:          # -1 error, -2 end of savefile
                    break
                continue            # 0 = read timeout, just loop
            h = hdr.contents
            caplen = h.caplen
            data = string_at(buf, caplen)
            ts = h.ts
            handle(data, ts.tv_sec * 1_000_000_000 + ts.tv_usec * 1000,
                   wire_len=h.len)

    def kernel_drops(self) -> int:
        """Frames the capture driver itself had to discard (host-side loss)."""
        if self.pcap is None:
            return 0
        try:
            from ctypes import byref  # noqa
            from scapy.libs.winpcapy import pcap_stat, pcap_stats  # type: ignore
            st = pcap_stat()
            if pcap_stats(self.pcap.pcap, byref(st)) == 0:
                return int(st.ps_drop) + int(st.ps_ifdrop)
        except Exception:
            pass
        return 0

    # ---- back-end 2: scapy AsyncSniffer ---------------------------------
    def _cb(self, pkt):
        try:
            data = bytes(pkt.original)
        except Exception:
            try:
                data = bytes(pkt)
            except Exception:
                return
        rx_ns = int(getattr(pkt, "time", 0) * 1e9) or now_ns()
        self._handle(data, rx_ns)

    def _try_start(self, flt: Optional[str]):
        """
        Start a sniffer and confirm it is actually alive. AsyncSniffer.start()
        returns immediately and swallows errors into the capture thread, so a
        bad/unsupported BPF filter would otherwise leave us silently deaf.
        """
        kw = {"iface": self.iface, "prn": self._cb, "store": False,
              "promisc": True}
        if flt:
            kw["filter"] = flt
        try:
            sn = AsyncSniffer(**kw)
            sn.start()
        except Exception:
            return None
        time.sleep(0.35)  # let the capture handle settle
        if getattr(sn, "exception", None) is not None or not getattr(sn, "running", True):
            try:
                sn.stop(join=False)
            except Exception:
                pass
            return None
        return sn

    def start(self, bpf_all: bool = False) -> None:
        self.filtered = False
        if self._start_pcap(bpf_all):
            return
        # ---- fallback ----
        if not bpf_all:
            self.sniffer = self._try_start(self._bpf())
            if self.sniffer is None:
                self.sniffer = self._try_start("ether proto 0x88b5")
            self.filtered = self.sniffer is not None
        if self.sniffer is None:
            self.sniffer = self._try_start(None)
        if self.sniffer is None:
            raise RuntimeError(
                f"could not start packet capture on '{self.iface}'. "
                "Check that Npcap is installed and that this program is "
                "running as Administrator.")
        self.mode = "scapy+bpf" if self.filtered else "scapy"

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self.pcap is not None:
            try:
                self.pcap.close()
            except Exception:
                pass
            self.pcap = None
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None
        self.mode = "none"


class Transmitter(threading.Thread):
    """
    Rate-controlled transmitter. pps<=0 means "as fast as the host allows".
    Reports the ACHIEVED rate so host limits are never mistaken for switch loss.
    """

    def __init__(self, sender: RawSender, template: bytearray, stats: StreamStats,
                 pps: float, duration: float, stop_event: threading.Event,
                 count: Optional[int] = None, start_seq: int = 0):
        super().__init__(daemon=True)
        self.sender = sender
        self.template = template
        self.stats = stats
        self.pps = pps
        self.duration = duration
        self.stop_event = stop_event
        self.count = count
        self.seq = start_seq
        self.sent = 0
        self.frame_len = len(template)
        self.exc: Optional[BaseException] = None

    def run(self) -> None:
        try:
            self._loop()
        except BaseException as e:  # noqa
            self.exc = e

    def _loop(self) -> None:
        buf = self.template
        send = self.sender.send
        t_start = time.perf_counter()
        deadline = t_start + self.duration if self.duration > 0 else float("inf")
        limit = self.count if self.count else None
        unlimited = self.pps is None or self.pps <= 0
        interval = 0.0 if unlimited else 1.0 / self.pps
        # batch so the timer overhead does not dominate at high rates
        batch = 1 if unlimited else max(1, min(64, int(self.pps / 2000) or 1))
        # report TX counters ~40x/s so the live graph is not stair-stepped
        report_every = 512 if unlimited else max(1, min(512, int(self.pps / 40)))
        pending = 0
        self.stats.note_tx_begin()

        while not self.stop_event.is_set():
            nowp = time.perf_counter()
            if nowp >= deadline:
                break
            if limit is not None and self.sent >= limit:
                break

            if unlimited:
                due = batch
            else:
                should_have = (nowp - t_start) / interval
                due = int(should_have - self.sent)
                if due <= 0:
                    # Wait for the next tick. Never busy-spin: this thread and
                    # the capture thread share one GIL, and a spinning
                    # transmitter starves the receiver into dropping frames
                    # that would then be misreported as switch loss.
                    slack = (self.sent + 1) * interval - (nowp - t_start)
                    if slack > 0.0006:
                        time.sleep(min(slack - 0.0003, 0.02))
                    else:
                        time.sleep(0)      # yield the GIL, keep sub-ms pacing
                    continue
                due = min(due, batch * 8)

            if limit is not None:
                due = min(due, limit - self.sent)

            for _ in range(due):
                stamp(buf, self.seq, now_ns())
                send(buf)
                self.seq += 1
                self.sent += 1
                pending += 1
                if pending >= report_every:
                    self.stats.on_tx(pending, pending * self.frame_len)
                    pending = 0
                    if unlimited:
                        time.sleep(0)   # let the capture thread breathe

        self.stats.note_tx_end()
        if pending:
            self.stats.on_tx(pending, pending * self.frame_len)

    def achieved_pps(self) -> float:
        s = self.stats.snapshot()
        if self.stats.tx_start_ns and self.stats.tx_end_ns:
            dur = (self.stats.tx_end_ns - self.stats.tx_start_ns) / 1e9
            if dur > 0:
                return s["tx_frames"] / dur
        return 0.0


# ==========================================================================
# 4b. SINGLE-ADAPTER REFLECTION MODE (switch uplinked to a live network)
# ==========================================================================
#
# With only one USB-Ethernet adapter you cannot watch a frame come out of a
# second port. But if another switch port is uplinked to a live network, a
# device out there will ANSWER us, and the reply comes back in on the same
# adapter. That makes one NIC enough to measure real forwarding.
#
#     PC (1 adapter) --- switch port 1 ... port 2 --- router / any host
#                    <-------- reply travels back --------
#
# We use ICMP echo because the responder echoes our payload back verbatim, so
# our own transmit timestamp returns with the reply: a true round-trip time
# with no clock-synchronisation problem at all. Every frame crosses the switch
# fabric TWICE, so the switch's own contribution is (RTT_through_switch -
# RTT_direct_cable) / 2.
#
# Honest limitation: routers and hosts rate-limit ICMP and ARP replies, so
# this mode cannot saturate a link. It proves forwarding, MAC learning,
# broadcast flooding, latency and jitter -- not line-rate throughput. The
# ramp test below explicitly detects responder throttling and refuses to
# report it as switch loss.

ETHERTYPE_IP = 0x0800
ETHERTYPE_ARP = 0x0806
MAGIC_R = b"SWRF"

# frame layout for our echo requests
_IP_OFF = ETH_HDR_LEN            # 14
_ICMP_OFF = _IP_OFF + 20         # 34
_PAY_OFF = _ICMP_OFF + 8         # 42
_R_SEQ_OFF = _PAY_OFF + 4        # 46
_R_TS_OFF = _R_SEQ_OFF + 4       # 50
REFLECT_MIN = _R_TS_OFF + 8 + FCS_LEN   # 62 -> round up to 64


def _cksum(buf, start, length) -> int:
    """Standard internet checksum over buf[start:start+length]."""
    s = 0
    end = start + length
    i = start
    while i + 1 < end:
        s += (buf[i] << 8) | buf[i + 1]
        i += 2
    if i < end:
        s += buf[i] << 8
    while s >> 16:
        s = (s >> 16) + (s & 0xFFFF)
    return (~s) & 0xFFFF


def ip_to_bytes(ip: str) -> bytes:
    parts = [int(x) for x in ip.split(".")]
    if len(parts) != 4 or any(not 0 <= p <= 255 for p in parts):
        raise ValueError(f"bad IPv4 address: {ip}")
    return bytes(parts)


def bytes_to_ip(b: bytes) -> str:
    return ".".join(str(x) for x in b)


# ---- ARP ----------------------------------------------------------------

def build_arp_request(src_mac: str, src_ip: str, target_ip: str) -> bytes:
    """Broadcast ARP request. Doubles as a broadcast-flooding test."""
    buf = bytearray(60)                      # 60 + 4 FCS = min frame
    buf[0:6] = mac_str_to_bytes(BROADCAST)
    buf[6:12] = mac_str_to_bytes(src_mac)
    struct.pack_into("!H", buf, 12, ETHERTYPE_ARP)
    struct.pack_into("!HHBBH", buf, 14, 1, ETHERTYPE_IP, 6, 4, 1)
    buf[22:28] = mac_str_to_bytes(src_mac)
    buf[28:32] = ip_to_bytes(src_ip)
    buf[32:38] = b"\x00" * 6
    buf[38:42] = ip_to_bytes(target_ip)
    return bytes(buf)


def parse_arp_reply(data: bytes, want_ip: str) -> Optional[str]:
    """Return the sender MAC of an ARP reply for want_ip."""
    if len(data) < 42:
        return None
    if struct.unpack_from("!H", data, 12)[0] != ETHERTYPE_ARP:
        return None
    if struct.unpack_from("!H", data, 20)[0] != 2:       # oper = reply
        return None
    if bytes_to_ip(data[28:32]) != want_ip:
        return None
    return mac_bytes_to_str(data[22:28])


# ---- ICMP echo ----------------------------------------------------------

def build_icmp_template(dst_mac: str, src_mac: str, src_ip: str, dst_ip: str,
                        size: int, ident: int) -> bytearray:
    size = max(REFLECT_MIN, min(int(size), 1518))
    emit = size - FCS_LEN
    buf = bytearray(emit)
    buf[0:6] = mac_str_to_bytes(dst_mac)
    buf[6:12] = mac_str_to_bytes(src_mac)
    struct.pack_into("!H", buf, 12, ETHERTYPE_IP)
    ip_len = emit - ETH_HDR_LEN
    buf[_IP_OFF] = 0x45                      # v4, ihl 5
    buf[_IP_OFF + 1] = 0
    struct.pack_into("!H", buf, _IP_OFF + 2, ip_len)
    struct.pack_into("!H", buf, _IP_OFF + 4, ident & 0xFFFF)
    struct.pack_into("!H", buf, _IP_OFF + 6, 0)
    buf[_IP_OFF + 8] = 64                    # TTL
    buf[_IP_OFF + 9] = 1                     # ICMP
    buf[_IP_OFF + 12:_IP_OFF + 16] = ip_to_bytes(src_ip)
    buf[_IP_OFF + 16:_IP_OFF + 20] = ip_to_bytes(dst_ip)
    struct.pack_into("!H", buf, _IP_OFF + 10, 0)
    struct.pack_into("!H", buf, _IP_OFF + 10, _cksum(buf, _IP_OFF, 20))
    buf[_ICMP_OFF] = 8                       # echo request
    buf[_ICMP_OFF + 1] = 0
    struct.pack_into("!H", buf, _ICMP_OFF + 4, ident & 0xFFFF)
    buf[_PAY_OFF:_PAY_OFF + 4] = MAGIC_R
    for i in range(_R_TS_OFF + 8, emit):     # deterministic filler
        buf[i] = (i * 7 + 0x5A) & 0xFF
    return buf


def stamp_icmp(buf: bytearray, seq: int, tx_ns: int) -> None:
    """Patch sequence + timestamp and refresh the ICMP checksum."""
    struct.pack_into("!H", buf, _ICMP_OFF + 6, seq & 0xFFFF)
    struct.pack_into("!I", buf, _R_SEQ_OFF, seq & 0xFFFFFFFF)
    struct.pack_into("!Q", buf, _R_TS_OFF, tx_ns)
    struct.pack_into("!H", buf, _ICMP_OFF + 2, 0)
    struct.pack_into("!H", buf, _ICMP_OFF + 2,
                     _cksum(buf, _ICMP_OFF, len(buf) - _ICMP_OFF))


def parse_icmp_reply(data: bytes) -> Optional[Tuple[int, int, int]]:
    """(stream_id=0, seq, tx_ns) from an echo reply carrying our payload."""
    if len(data) < _R_TS_OFF + 8:
        return None
    if data[12] != 0x08 or data[13] != 0x00:
        return None
    if (data[_IP_OFF] >> 4) != 4 or data[_IP_OFF + 9] != 1:
        return None
    ihl = (data[_IP_OFF] & 0x0F) * 4
    icmp = _IP_OFF + ihl
    if len(data) < icmp + 8 + 16 or data[icmp] != 0:     # type 0 = echo reply
        return None
    pay = icmp + 8
    if data[pay:pay + 4] != MAGIC_R:
        return None
    seq = struct.unpack_from("!I", data, pay + 4)[0]
    tx_ns = struct.unpack_from("!Q", data, pay + 8)[0]
    return 0, seq, tx_ns


class ReflectSession:
    """One-adapter test driver: inject echo requests, catch the replies."""

    def __init__(self, cfg: "Config", iface: str, mac: str, src_ip: str,
                 target_ip: str, emit: Callable[[str, object], None]):
        self.cfg = cfg
        self.iface = iface
        self.mac = mac
        self.src_ip = src_ip
        self.target_ip = target_ip
        self.target_mac: Optional[str] = None
        self.emit = emit
        self.stats = StreamStats("reflect")
        self.sender: Optional[RawSender] = None
        self.rx: Optional[Receiver] = None
        self.arp_rx: Optional[Receiver] = None
        self.stop_event = threading.Event()
        self.ident = random.randrange(1, 0xFFFF)
        self._drop_base = 0

    # ---- lifecycle ---------------------------------------------------
    def open(self) -> None:
        self.emit("log", f"Opening {self.iface} for send+receive (one adapter)")
        self.sender = RawSender(self.iface)
        self.rx = Receiver(self.iface, {0: self.stats},
                           parse_fn=parse_icmp_reply,
                           bpf_override="icmp and icmp[0] = 0")
        self.rx.start()
        self.emit("log", f"Capture running ({self.rx.mode}).")

    def close(self) -> None:
        for r in (self.rx, self.arp_rx):
            if r:
                r.stop()
        if self.sender:
            self.sender.close()
        self.rx = self.arp_rx = self.sender = None

    def settle(self, wait: float = 0.3) -> None:
        self.stats.reset()
        time.sleep(wait)
        self.stats.reset()

    # ---- ARP: proves broadcast flooding + gives us the target MAC ----
    def resolve_target(self, timeout: float = 4.0) -> Optional[str]:
        got: List[str] = []

        def hook(data: bytes, rx_ns: int):
            m = parse_arp_reply(data, self.target_ip)
            if m and not got:
                got.append(m)

        arp_rx = Receiver(self.iface, {}, raw_hook=hook,
                          bpf_override="arp")
        arp_rx.start()
        try:
            req = build_arp_request(self.mac, self.src_ip, self.target_ip)
            t0 = time.perf_counter()
            n = 0
            while time.perf_counter() - t0 < timeout and not got:
                if n % 8 == 0:
                    self.sender.send(req)
                n += 1
                time.sleep(0.12)
        finally:
            arp_rx.stop()
        if got:
            self.target_mac = got[0]
            rtt = time.perf_counter() - t0
            self.emit("log", f"ARP reply from {self.target_ip} = {self.target_mac} "
                             f"(after {rtt*1000:.0f} ms) - broadcast is being "
                             f"flooded and unicast comes back")
        return self.target_mac

    # ---- measurement window -----------------------------------------
    def run(self, size: int, pps: float, duration: float,
            phase: str = "reflect", live: bool = True) -> Dict:
        if not self.target_mac:
            raise RuntimeError("target MAC unknown - run resolve_target() first")
        self.settle()
        tpl = build_icmp_template(self.target_mac, self.mac, self.src_ip,
                                  self.target_ip, size, self.ident)
        self._drop_base = self.rx.kernel_drops() if self.rx else 0
        self.stop_event.clear()
        st = self.stats
        st.note_tx_begin()
        t0 = time.perf_counter()
        deadline = t0 + duration
        interval = (1.0 / pps) if pps and pps > 0 else 0.0
        sent = 0
        pending = 0
        report_every = max(1, min(256, int((pps or 1000) / 40)))
        last_emit = t0
        prev = (0, 0, 0, 0)
        send = self.sender.send
        while not self.stop_event.is_set():
            nowp = time.perf_counter()
            if nowp >= deadline:
                break
            if interval:
                due = int((nowp - t0) / interval) - sent
                if due <= 0:
                    slack = (sent + 1) * interval - (nowp - t0)
                    time.sleep(min(slack - 0.0003, 0.02) if slack > 0.0006 else 0)
                    continue
                due = min(due, 64)
            else:
                due = 32
            for _ in range(due):
                stamp_icmp(tpl, sent, now_ns())
                send(tpl)
                sent += 1
                pending += 1
                if pending >= report_every:
                    st.on_tx(pending, pending * len(tpl))
                    pending = 0
            if live and nowp - last_emit >= 0.25:
                self._emit_sample(prev, last_emit, phase)
                prev = (st.tx_frames, st.rx_frames, st.tx_bytes, st.rx_bytes)
                last_emit = nowp
        st.note_tx_end()
        if pending:
            st.on_tx(pending, pending * len(tpl))
        time.sleep(0.8)          # let the last replies arrive
        if live:
            self._emit_sample(prev, last_emit, phase)
        return self._collect(time.perf_counter() - t0, size, pps)

    def _emit_sample(self, prev, prev_t: float, phase: str) -> None:
        s = self.stats.snapshot()
        dt = max(1e-6, time.perf_counter() - prev_t)
        agg = {
            "t": time.perf_counter(), "phase": phase,
            "tx_pps": (s["tx_frames"] - prev[0]) / dt,
            "rx_pps": (s["rx_frames"] - prev[1]) / dt,
            "tx_mbps": mbps(s["tx_bytes"] - prev[2], dt, s["tx_frames"] - prev[0]),
            "rx_mbps": mbps(s["rx_bytes"] - prev[3], dt, s["rx_frames"] - prev[1]),
            "loss_pct": s["loss_pct"], "lat_avg_us": s["lat_avg_us"],
            "lat_max_us": s["lat_max_us"], "jitter_us": s["jitter_us"],
            "streams": {"reflect": s},
        }
        self.emit("sample", agg)

    def _collect(self, elapsed: float, size: int, req_pps: float) -> Dict:
        st = self.stats
        s = st.snapshot()
        s.update(st.percentiles())
        off = self.cfg.latency_offset_us
        for k in ("lat_min_us", "lat_max_us", "lat_avg_us", "p50", "p95", "p99"):
            s[k] = max(0.0, s[k] - off)
        dur = 0.0
        if st.tx_start_ns and st.tx_end_ns and st.tx_end_ns > st.tx_start_ns:
            dur = (st.tx_end_ns - st.tx_start_ns) / 1e9
            if s["tx_frames"] > 1:
                dur += dur / (s["tx_frames"] - 1)
        if dur < 1e-4:
            dur = elapsed
        out = dict(s)
        out.update(
            frame_size=size, req_pps=req_pps, window_s=dur, elapsed=elapsed,
            tx_pps=s["tx_frames"] / dur if dur else 0,
            rx_pps=s["rx_frames"] / dur if dur else 0,
            tx_mbps=mbps(s["tx_bytes"], dur, s["tx_frames"]),
            rx_mbps=mbps(s["rx_bytes"], dur, s["rx_frames"]),
            host_capture_drops=max(0, (self.rx.kernel_drops() if self.rx else 0)
                                   - self._drop_base),
            streams={"reflect": s},
        )
        out["rtt_avg_us"] = out["lat_avg_us"]
        out["switch_us_estimate"] = out["lat_avg_us"] / 2.0
        return out


# ==========================================================================
# 5. TEST SESSION / ENGINE
# ==========================================================================

STREAM_A2B = 1      # port A -> switch -> port B
STREAM_B2A = 2      # port B -> switch -> port A


@dataclass
class Config:
    iface_a: str = ""
    iface_b: str = ""
    mac_a: str = ""
    mac_b: str = ""
    link_mbps: int = 100
    frame_size: int = 512
    rate_mode: str = "pps"        # 'pps' | 'percent' | 'mbps' | 'max'
    rate_value: float = 20000.0
    duration: float = 10.0
    bidirectional: bool = False
    sweep_sizes: List[int] = field(default_factory=lambda: [64, 128, 256, 512, 1024, 1280, 1518])
    ramp_percents: List[int] = field(default_factory=lambda: [10, 25, 50, 75, 100])
    burst_sizes: List[int] = field(default_factory=lambda: [100, 1000, 10000, 50000])
    loss_threshold_pct: float = 0.10      # pass/fail
    latency_offset_us: float = 0.0        # subtracted (direct-cable calibration)


@dataclass
class TestResult:
    name: str
    ok: bool
    detail: str
    metrics: Dict = field(default_factory=dict)
    rows: List[Dict] = field(default_factory=list)
    ts: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


class Session:
    """Owns the sockets/sniffers for the lifetime of a test run."""

    def __init__(self, cfg: Config, emit: Callable[[str, object], None]):
        self.cfg = cfg
        self.emit = emit
        self.stats: Dict[int, StreamStats] = {
            STREAM_A2B: StreamStats("A->B"),
            STREAM_B2A: StreamStats("B->A"),
        }
        self.sender_a: Optional[RawSender] = None
        self.sender_b: Optional[RawSender] = None
        self.rx_a: Optional[Receiver] = None
        self.rx_b: Optional[Receiver] = None
        self.console_hook: Optional[Callable[[bytes, float], None]] = None
        self.stop_event = threading.Event()
        self.capture_mode = "none"
        self.bit_tap = BitTap()
        self._drop_base = 0
        self._timeline: List[Dict] = []
        self._t0 = 0.0

    # ---- lifecycle -----------------------------------------------------
    def open(self, capture_all: bool = False) -> None:
        c = self.cfg
        self.emit("log", f"Opening TX socket on A: {c.iface_a}")
        self.sender_a = RawSender(c.iface_a)
        self.emit("log", f"Opening TX socket on B: {c.iface_b}")
        self.sender_b = RawSender(c.iface_b)
        self.emit("log", "Starting capture on both ports...")
        # RX on B receives stream A2B; RX on A receives stream B2A
        self.rx_b = Receiver(c.iface_b, {STREAM_A2B: self.stats[STREAM_A2B]},
                             raw_hook=self._hook,
                             expect_stream=None if capture_all else STREAM_A2B)
        self.rx_a = Receiver(c.iface_a, {STREAM_B2A: self.stats[STREAM_B2A]},
                             raw_hook=self._hook,
                             expect_stream=None if capture_all else STREAM_B2A)
        self.rx_b.bit_tap = self.bit_tap
        self.rx_a.bit_tap = self.bit_tap
        self.rx_b.start(bpf_all=capture_all)
        self.rx_a.start(bpf_all=capture_all)
        self.capture_mode = f"A:{self.rx_a.mode} B:{self.rx_b.mode}"
        self.emit("log", f"Capture running ({self.capture_mode}).")
        if not capture_all and not (self.rx_a.filtered and self.rx_b.filtered):
            self.emit("log", "WARNING: kernel BPF filter unavailable - every frame "
                             "on the wire is parsed in Python. At high rates the "
                             "PC, not the switch, may drop frames.")

    def _hook(self, data: bytes, rx_ns: int) -> None:
        if self.console_hook:
            self.console_hook(data, rx_ns)

    def close(self) -> None:
        for r in (self.rx_a, self.rx_b):
            if r:
                r.stop()
        for s in (self.sender_a, self.sender_b):
            if s:
                s.close()
        self.rx_a = self.rx_b = self.sender_a = self.sender_b = None

    def reset_stats(self) -> None:
        for s in self.stats.values():
            s.reset()

    def settle(self, wait: float = 0.3) -> None:
        """
        Clear counters, let any frames still in flight (or still sitting in the
        capture buffer) from the PREVIOUS measurement arrive, then clear again.

        Without this, a straggler carrying a high sequence number from the last
        run raises `expected` for the new run and fabricates enormous loss.
        """
        self.reset_stats()
        time.sleep(wait)
        self.reset_stats()

    # ---- core primitive -------------------------------------------------
    def run_stream(self, *, size: int, pps: float, duration: float,
                   bidir: bool, dst_override_a: Optional[str] = None,
                   dst_override_b: Optional[str] = None,
                   count: Optional[int] = None,
                   phase: str = "", live: bool = True) -> Dict:
        """
        Fire one measurement window. Returns a merged result dict.
        `pps<=0` -> maximum host rate.
        """
        c = self.cfg
        self.settle()
        dst_a = dst_override_a or c.mac_b
        dst_b = dst_override_b or c.mac_a

        tpl_a = build_template(dst_a, c.mac_a, size, STREAM_A2B)
        txs: List[Transmitter] = []
        self.stop_event.clear()
        txs.append(Transmitter(self.sender_a, tpl_a, self.stats[STREAM_A2B],
                               pps, duration, self.stop_event, count=count))
        if bidir:
            tpl_b = build_template(dst_b, c.mac_b, size, STREAM_B2A)
            txs.append(Transmitter(self.sender_b, tpl_b, self.stats[STREAM_B2A],
                                   pps, duration, self.stop_event, count=count))

        self._drop_base = self._host_drops_raw()
        self._timeline = []
        t0 = time.perf_counter()
        self._t0 = t0
        for t in txs:
            t.start()

        prev = {k: (0, 0, 0, 0) for k in self.stats}
        prev_t = t0
        while any(t.is_alive() for t in txs):
            time.sleep(0.25)
            if live:
                self._emit_sample(prev, prev_t, phase)
                prev_t = time.perf_counter()
            if self.stop_event.is_set():
                break
        for t in txs:
            t.join(timeout=3.0)

        # drain: let in-flight frames arrive
        time.sleep(0.6)
        if live:
            self._emit_sample(prev, prev_t, phase)

        elapsed = time.perf_counter() - t0
        res = self._collect(elapsed, size, bidir, pps, txs)
        res["phase"] = phase
        return res

    def _worst_window(self, win_s: float = 1.0) -> Dict:
        """
        Find the worst short window in the run.

        This exists because a run-average is a genuinely misleading summary of
        bursty loss: 300 frames dropped inside one second of a 15 s run at
        2000 pps averages to 1%, which can sit under a threshold and be
        reported as a pass, even though for that second the link lost 15% of
        everything. We report both.
        """
        tl = self._timeline
        empty = {"worst_1s_loss_pct": 0.0, "worst_1s_at_s": 0.0,
                 "worst_1s_lost": 0, "worst_1s_host_drops": 0,
                 "burstiness": 0.0}
        if len(tl) < 2:
            return empty
        worst = dict(empty)
        j = 0
        for i in range(1, len(tl)):
            while j < i - 1 and tl[i]["t"] - tl[j + 1]["t"] >= win_s:
                j += 1
            span = tl[i]["t"] - tl[j]["t"]
            if span <= 0:
                continue
            d_tx = tl[i]["tx"] - tl[j]["tx"]
            d_lost = tl[i]["lost"] - tl[j]["lost"]
            if d_tx <= 0 or d_lost <= 0:
                continue
            pct = d_lost / d_tx * 100.0
            if pct > worst["worst_1s_loss_pct"]:
                worst = {
                    "worst_1s_loss_pct": pct,
                    "worst_1s_at_s": round(tl[j]["t"], 2),
                    "worst_1s_lost": d_lost,
                    "worst_1s_host_drops": tl[i]["host_drops"] - tl[j]["host_drops"],
                    "burstiness": 0.0,
                }
        return worst

    def _host_drops_raw(self) -> int:
        n = 0
        for r in (self.rx_a, self.rx_b):
            if r is not None:
                n += r.kernel_drops()
        return n

    def _emit_sample(self, prev: Dict, prev_t: float, phase: str) -> None:
        nowp = time.perf_counter()
        dt = max(1e-6, nowp - prev_t)
        agg = {"t": nowp, "phase": phase, "streams": {}}
        tot_tx_pps = tot_rx_pps = tot_tx_mbps = tot_rx_mbps = 0.0
        worst_loss = 0.0
        lat_avg = lat_max = jitter = 0.0
        for sid, st in self.stats.items():
            s = st.snapshot()
            ptx, prx, ptxb, prxb = prev[sid]
            d_tx = s["tx_frames"] - ptx
            d_rx = s["rx_frames"] - prx
            d_txb = s["tx_bytes"] - ptxb
            d_rxb = s["rx_bytes"] - prxb
            prev[sid] = (s["tx_frames"], s["rx_frames"], s["tx_bytes"], s["rx_bytes"])
            if d_tx == 0 and d_rx == 0 and s["tx_frames"] == 0:
                continue
            tx_pps = d_tx / dt
            rx_pps = d_rx / dt
            tot_tx_pps += tx_pps
            tot_rx_pps += rx_pps
            tot_tx_mbps += mbps(d_txb, dt, d_tx)
            tot_rx_mbps += mbps(d_rxb, dt, d_rx)
            worst_loss = max(worst_loss, s["loss_pct_confirmed"])
            lat_avg = max(lat_avg, s["lat_avg_us"])
            lat_max = max(lat_max, s["lat_max_us"])
            jitter = max(jitter, s["jitter_us"])
            agg["streams"][st.label] = dict(s, tx_pps=tx_pps, rx_pps=rx_pps)
        hd = max(0, self._host_drops_raw() - self._drop_base)
        agg.update(tx_pps=tot_tx_pps, rx_pps=tot_rx_pps,
                   tx_mbps=tot_tx_mbps, rx_mbps=tot_rx_mbps,
                   loss_pct=worst_loss, lat_avg_us=lat_avg, lat_max_us=lat_max,
                   jitter_us=jitter, host_drops=hd)
        # Timeline of cumulative counters. A 15 s average can hide a 200 ms
        # burst of loss completely, so we keep the shape of the run and report
        # the worst short window separately.
        tot_tx = sum(v["tx_frames"] for v in agg["streams"].values())
        tot_rx = sum(v["rx_frames"] for v in agg["streams"].values())
        # CONFIRMED loss only. Using the total here (which compares against the
        # batched TX counter) records frames that are merely still in flight as
        # lost, and _worst_window then reports a phantom burst that fails the
        # test even when the final loss is exactly zero.
        tot_lost = sum(v["lost_confirmed"] for v in agg["streams"].values())
        self._timeline.append({
            "t": round(nowp - getattr(self, "_t0", nowp), 3),
            "tx": tot_tx, "rx": tot_rx, "lost": tot_lost, "host_drops": hd,
            "lat_avg_us": lat_avg, "lat_max_us": lat_max,
        })
        self.emit("sample", agg)

    def _collect(self, elapsed: float, size: int, bidir: bool,
                 req_pps: float, txs: List[Transmitter]) -> Dict:
        out = {"elapsed": elapsed, "frame_size": size, "bidir": bidir,
               "req_pps": req_pps, "streams": {}}
        tx_total = rx_total = lost_total = exp_total = 0
        tx_bytes = rx_bytes = 0
        win = 0.0
        lat_avg = []
        lat_max = 0.0
        lat_min = None
        jit = 0.0
        for sid, st in self.stats.items():
            s = st.snapshot()
            if s["tx_frames"] == 0:
                continue
            s.update(st.percentiles())
            off = self.cfg.latency_offset_us
            for k in ("lat_min_us", "lat_max_us", "lat_avg_us", "p50", "p95", "p99"):
                s[k] = max(0.0, s[k] - off)
            # Rates must use the TRANSMIT window, not the wall-clock of the
            # whole call (which includes the post-run drain wait).
            dur = 0.0
            if st.tx_start_ns and st.tx_end_ns and st.tx_end_ns > st.tx_start_ns:
                dur = (st.tx_end_ns - st.tx_start_ns) / 1e9
                # the window ends at the last SEND, so add one frame time back
                if s["tx_frames"] > 1:
                    dur += dur / (s["tx_frames"] - 1)
            if dur < 1e-4:          # degenerate / single frame
                dur = elapsed
            s["duration_s"] = dur
            s["tx_pps"] = s["tx_frames"] / dur if dur else 0
            s["rx_pps"] = s["rx_frames"] / dur if dur else 0
            s["tx_mbps"] = mbps(s["tx_bytes"], dur, s["tx_frames"])
            s["rx_mbps"] = mbps(s["rx_bytes"], dur, s["rx_frames"])
            win = max(win, dur)
            out["streams"][s["label"]] = s
            tx_total += s["tx_frames"]
            rx_total += s["rx_frames"]
            lost_total += s["lost"]
            exp_total += s["expected"]
            tx_bytes += s["tx_bytes"]
            rx_bytes += s["rx_bytes"]
            lat_avg.append(s["lat_avg_us"])
            lat_max = max(lat_max, s["lat_max_us"])
            lat_min = s["lat_min_us"] if lat_min is None else min(lat_min, s["lat_min_us"])
            jit = max(jit, s["jitter"])
        win = win or elapsed
        # A one-way fault must NOT be diluted by the healthy direction. The
        # aggregate is kept for the charts, but pass/fail uses the worst stream.
        worst = max((v["loss_pct"] for v in out["streams"].values()), default=0.0)
        worst_lbl = max(out["streams"].items(),
                        key=lambda kv: kv[1]["loss_pct"], default=("", {}))[0]
        out.update(
            tx_frames=tx_total, rx_frames=rx_total,
            lost=lost_total, expected=exp_total, window_s=win,
            loss_pct=(lost_total / exp_total * 100.0) if exp_total else 0.0,
            loss_pct_worst=worst, worst_direction=worst_lbl,
            tx_pps=tx_total / win if win else 0,
            rx_pps=rx_total / win if win else 0,
            tx_mbps=mbps(tx_bytes, win, tx_total),
            rx_mbps=mbps(rx_bytes, win, rx_total),
            lat_avg_us=(sum(lat_avg) / len(lat_avg)) if lat_avg else 0.0,
            lat_max_us=lat_max, lat_min_us=lat_min or 0.0, jitter_us=jit,
        )
        out.update(self._worst_window(win_s=1.0))
        out["timeline"] = list(self._timeline)
        # Frames the PC's own capture driver threw away. These are provably NOT
        # the switch's fault, so they are SUBTRACTED from the figure the switch
        # is judged on. Reporting them as switch loss meant this tool invented
        # hardware faults that did not exist.
        hd = max(0, self._host_drops_raw() - self._drop_base)
        out["host_capture_drops"] = hd
        dut_lost = max(0, lost_total - hd)
        out["dut_lost"] = dut_lost
        out["dut_loss_pct"] = (dut_lost / exp_total * 100.0) if exp_total else 0.0
        # and the same correction per direction, proportionally
        for lbl, st_d in out["streams"].items():
            share = (st_d["lost"] / lost_total) if lost_total else 0.0
            st_d["host_drops_est"] = round(hd * share, 1)
            st_d["dut_lost"] = max(0, st_d["lost"] - hd * share)
            st_d["dut_loss_pct"] = ((st_d["dut_lost"] / st_d["expected"] * 100.0)
                                    if st_d["expected"] else 0.0)
        out["dut_loss_pct_worst"] = max(
            (v["dut_loss_pct"] for v in out["streams"].values()), default=0.0)
        out["measurement_degraded"] = bool(hd and exp_total and hd / exp_total > 0.001)
        out["capture_mode"] = self.capture_mode
        # host-limited detection
        if req_pps and req_pps > 0:
            per_stream_req = req_pps * (2 if bidir else 1)
            out["rate_accuracy_pct"] = (out["tx_pps"] / per_stream_req * 100.0) if per_stream_req else 100.0
            out["tx_limited"] = out["rate_accuracy_pct"] < 95.0
        else:
            out["rate_accuracy_pct"] = 100.0
            out["tx_limited"] = False
        return out


# --------------------------------------------------------------------------
# The individual tests
# --------------------------------------------------------------------------

class TestSuite:
    def __init__(self, session: Session, emit: Callable[[str, object], None]):
        self.s = session
        self.cfg = session.cfg
        self.emit = emit

    # helper -------------------------------------------------------------
    def _pps_for(self, size: int) -> float:
        c = self.cfg
        if c.rate_mode == "max":
            return 0.0
        if c.rate_mode == "pps":
            return c.rate_value
        if c.rate_mode == "percent":
            return line_rate_pps(size, c.link_mbps) * (c.rate_value / 100.0)
        if c.rate_mode == "mbps":
            return (c.rate_value * 1e6) / ((size + IFG_PREAMBLE) * 8.0)
        return c.rate_value

    def _verdict(self, res: Dict, thr: Optional[float] = None) -> Tuple[bool, str]:
        """
        Pass/fail on evidence the SWITCH did something wrong.

        Hard rule: this tool must never fail the device under test for a
        limitation of the PC measuring it. Frames discarded by our own capture
        driver are subtracted before judging, and a degraded measurement is
        reported as reduced confidence - not as a hardware fault.
        """
        thr = self.cfg.loss_threshold_pct if thr is None else thr
        if res["rx_frames"] == 0:
            return False, "NO FRAMES RECEIVED - check cabling / port / link LEDs"

        # corruption is always the DUT or the cabling, never our capture buffer
        bad = sum(v.get("bad_payload", 0) for v in res.get("streams", {}).values())
        chk = sum(v.get("payload_checked", 0) for v in res.get("streams", {}).values())
        if bad:
            return False, (f"FRAME CORRUPTION: {bad} of {chk} spot-checked frames came "
                           f"back with a mangled payload. Frames arrive but their "
                           f"contents are wrong - suspect the PHY, SERDES, termination "
                           f"or cabling, not the forwarding logic.")

        hd = res.get("host_capture_drops", 0)
        # worst direction, with our own drops removed
        dut = max(res.get("dut_loss_pct_worst", 0.0), res.get("dut_loss_pct", 0.0))
        raw = max(res.get("loss_pct_worst", 0.0), res.get("loss_pct", 0.0))
        wd = res.get("worst_direction") or ""
        where = f" on {wd}" if wd and len(res.get("streams", {})) > 1 else ""

        note = ""
        if hd:
            note = (f"  [{hd} frame(s) were discarded by this PC's capture driver "
                    f"and are excluded; raw figure was {raw:.4f}%]")

        if dut > thr:
            if res.get("tx_limited"):
                note += (f"  [host reached only "
                         f"{res.get('rate_accuracy_pct', 0):.0f}% of the requested "
                         f"rate, so the offered load was lower than asked - the "
                         f"loss itself is still real]")
            return False, f"loss {dut:.4f}%{where} > {thr}% threshold{note}"

        # A short burst can average away over a long run - but only flag it if
        # the burst is attributable to the switch rather than to our capture.
        burst = res.get("worst_1s_loss_pct", 0.0)
        burst_hd = res.get("worst_1s_host_drops", 0)
        burst_lost = res.get("worst_1s_lost", 0)
        burst_is_dut = burst_lost > 0 and burst_hd < burst_lost * 0.5
        if burst > max(thr * 10, 1.0) and burst_is_dut:
            return False, (f"TRANSIENT LOSS BURST: the run average is only "
                           f"{dut:.4f}% (under the {thr}% threshold), but at "
                           f"t={res.get('worst_1s_at_s', 0):.1f}s a 1-second window "
                           f"lost {burst:.2f}% ({burst_lost} frames). Averaging hid "
                           f"this - it is a real drop event.{note}")

        msg = (f"loss {dut:.4f}%, avg {res['lat_avg_us']:.0f} us, "
               f"jitter {res.get('jitter_us', 0):.0f} us")
        if burst > 0.01 and burst_is_dut:
            msg += f", worst 1 s window {burst:.3f}%"
        if res.get("measurement_degraded"):
            msg += (f"  [CONFIDENCE REDUCED: this PC dropped {hd} frame(s) during "
                    f"capture. Not charged to the switch, but lower the rate for a "
                    f"cleaner measurement]")
        elif hd:
            msg += f"  [{hd} host capture drop(s) excluded]"
        return True, msg

    # 1 ------------------------------------------------------------------
    def t_link(self) -> TestResult:
        self.emit("log", "[1] Link & connectivity check (both directions, 200 frames each)")
        rows = []
        ok_all = True
        # A -> B
        r1 = self.s.run_stream(size=64, pps=500, duration=0, count=200,
                               bidir=False, phase="link A->B")
        # B -> A  (swap by using a bidir run with only B transmitting)
        c = self.cfg
        self.s.settle()
        tpl = build_template(c.mac_a, c.mac_b, 64, STREAM_B2A)
        self.s.stop_event.clear()
        tx = Transmitter(self.s.sender_b, tpl, self.s.stats[STREAM_B2A],
                         500, 0, self.s.stop_event, count=200)
        t0 = time.perf_counter()
        tx.start()
        tx.join(timeout=10)
        time.sleep(0.6)
        r2 = self.s._collect(time.perf_counter() - t0, 64, False, 500, [tx])

        for tag, r in (("A -> B", r1), ("B -> A", r2)):
            rx = r["rx_frames"]
            good = rx >= 190
            ok_all &= good
            rows.append({"direction": tag, "tx": r["tx_frames"], "rx": rx,
                         "loss_pct": round(r["loss_pct"], 3),
                         "lat_avg_us": round(r["lat_avg_us"], 1),
                         "result": "PASS" if good else "FAIL"})
        detail = ("both directions forwarding" if ok_all
                  else "one or both directions did not forward frames")
        return TestResult("1. Link / bidirectional connectivity", ok_all, detail,
                          {"a2b_rx": r1["rx_frames"], "b2a_rx": r2["rx_frames"]}, rows)

    # 2 ------------------------------------------------------------------
    def t_unknown_unicast(self) -> TestResult:
        self.emit("log", "[2] Unknown-unicast flooding (dst MAC never seen by DUT)")
        dst = random_local_mac()
        r = self.s.run_stream(size=128, pps=1000, duration=0, count=500,
                              bidir=False, dst_override_a=dst,
                              phase="unknown unicast")
        ok = r["rx_frames"] >= 450
        detail = (f"switch flooded unknown unicast to dst {dst} "
                  f"({r['rx_frames']}/500 received)") if ok else \
                 (f"only {r['rx_frames']}/500 frames flooded - a correct L2 switch "
                  f"must flood unknown unicast out all other ports")
        return TestResult("2. Unknown-unicast flooding", ok, detail,
                          {"dst": dst, "rx": r["rx_frames"]},
                          [{"dst_mac": dst, "tx": r["tx_frames"], "rx": r["rx_frames"],
                            "loss_pct": round(r["loss_pct"], 3),
                            "result": "PASS" if ok else "FAIL"}])

    # 3 ------------------------------------------------------------------
    def t_broadcast(self) -> TestResult:
        self.emit("log", "[3] Broadcast forwarding + broadcast load")
        rows = []
        ok_all = True
        for pps, n in ((1000, 1000), (10000, 20000)):
            r = self.s.run_stream(size=64, pps=pps, duration=0, count=n,
                                  bidir=False, dst_override_a=BROADCAST,
                                  phase=f"broadcast {pps}pps")
            hd = r.get("host_capture_drops", 0)
            dut = r.get("dut_loss_pct", r["loss_pct"])
            ok = dut <= 1.0 and r["rx_frames"] > 0
            ok_all &= ok
            rows.append({"rate_pps": pps, "tx": r["tx_frames"], "rx": r["rx_frames"],
                         "lost_total": r["lost"], "host_drops": hd,
                         "switch_loss_pct": round(dut, 3),
                         "lat_avg_us": round(r["lat_avg_us"], 1),
                         "result": "PASS" if ok else "FAIL"})
        hd_total = sum(x["host_drops"] for x in rows)
        detail = ("broadcast replicated to the other port" if ok_all
                  else "broadcast frames lost or not forwarded by the switch")
        if hd_total:
            detail += (f"  [{hd_total} frame(s) dropped by this PC's capture driver "
                       f"were excluded from the switch's score]")
        return TestResult("3. Broadcast forwarding", ok_all, detail, {}, rows)

    # 4 ------------------------------------------------------------------
    def t_mac_learning(self) -> TestResult:
        self.emit("log", "[4] MAC learning / aging behaviour")
        c = self.cfg
        rows = []
        # phase 1: teach the switch where MAC_A lives by sending from A
        self.s.run_stream(size=64, pps=500, duration=0, count=100, bidir=False,
                          phase="learn")
        # phase 2: now send B -> A using A's real MAC; should be unicast-forwarded
        self.s.settle()
        tpl = build_template(c.mac_a, c.mac_b, 64, STREAM_B2A)
        self.s.stop_event.clear()
        tx = Transmitter(self.s.sender_b, tpl, self.s.stats[STREAM_B2A],
                         1000, 0, self.s.stop_event, count=500)
        t0 = time.perf_counter()
        tx.start(); tx.join(timeout=10); time.sleep(0.6)
        r = self.s._collect(time.perf_counter() - t0, 64, False, 1000, [tx])
        ok1 = r["rx_frames"] >= 480
        rows.append({"step": "forward to learned MAC", "tx": r["tx_frames"],
                     "rx": r["rx_frames"], "loss_pct": round(r["loss_pct"], 3),
                     "result": "PASS" if ok1 else "FAIL"})

        # phase 3: 1000 distinct source MACs -> CAM table fill
        self.emit("log", "    filling CAM table with 1000 distinct source MACs...")
        self.s.settle()
        self.s.stop_event.clear()
        sender = self.s.sender_a
        st = self.s.stats[STREAM_A2B]
        sent = 0
        t0 = time.perf_counter()
        st.note_tx_begin()
        drop_base = self.s._host_drops_raw()
        for i in range(1000):
            src = "02:%02x:%02x:%02x:%02x:%02x" % (
                (i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF, 0x11)
            buf = build_template(c.mac_b, src, 64, STREAM_A2B)
            stamp(buf, i, now_ns())
            try:
                sender.send(bytes(buf))
                sent += 1
            except Exception:
                break
            if i % 16 == 15:
                time.sleep(0)    # keep the capture thread scheduled
        st.note_tx_end()
        st.on_tx(sent, sent * 60)
        time.sleep(0.8)
        r3 = self.s._collect(time.perf_counter() - t0, 64, False, 0, [])
        hd3 = max(0, self.s._host_drops_raw() - drop_base)
        # judge the switch on frames it lost, not frames our capture dropped
        ok2 = (sent - r3["rx_frames"] - hd3) <= sent * 0.05
        rows.append({"step": "1000 unique source MACs (CAM fill)", "tx": sent,
                     "rx": r3["rx_frames"], "host_drops": hd3,
                     "loss_pct": round(r3["loss_pct"], 3),
                     "result": "PASS" if ok2 else "FAIL"})
        ok = ok1 and ok2
        return TestResult("4. MAC learning / CAM table", ok,
                          "learning and CAM fill behaved correctly" if ok
                          else "forwarding degraded during MAC learning stress",
                          {}, rows)

    # 5 ------------------------------------------------------------------
    def t_frame_sweep(self, per_size: float = 6.0) -> TestResult:
        self.emit("log", f"[5] Frame-size sweep ({per_size:.0f}s per size)")
        rows = []
        ok_all = True
        for size in self.cfg.sweep_sizes:
            pps = self._pps_for(size)
            self.emit("log", f"    size {size} B @ {human_pps(pps) if pps else 'MAX'} pps")
            r = self.s.run_stream(size=size, pps=pps, duration=per_size,
                                  bidir=self.cfg.bidirectional,
                                  phase=f"sweep {size}B")
            ok, _ = self._verdict(r)
            ok_all &= ok
            n_dir = 2 if self.cfg.bidirectional else 1
            rows.append({
                "frame_size": size,
                "target_pps_per_dir": round(pps) if pps else "max",
                "target_pps_total": round(pps * n_dir) if pps else "max",
                "tx_pps": round(r["tx_pps"]),
                "rx_pps": round(r["rx_pps"]),
                "tx_mbps": round(r["tx_mbps"], 2),
                "rx_mbps": round(r["rx_mbps"], 2),
                "switch_loss_pct": round(r.get("dut_loss_pct", r["loss_pct"]), 4),
                "raw_loss_pct": round(r["loss_pct"], 4),
                "lat_avg_us": round(r["lat_avg_us"], 1),
                "lat_max_us": round(r["lat_max_us"], 1),
                "jitter_us": round(r["jitter_us"], 1),
                "host_drops": r.get("host_capture_drops", 0),
                "host_limited": "yes" if r.get("tx_limited") else "no",
                "result": "PASS" if ok else "FAIL",
            })
            self.emit("row", ("5. Frame-size sweep", rows[-1]))
        return TestResult("5. Frame-size sweep", ok_all,
                          "all frame sizes forwarded within loss threshold" if ok_all
                          else "loss exceeded threshold at one or more frame sizes",
                          {}, rows)

    # 6 ------------------------------------------------------------------
    def t_load_ramp(self, per_step: float = 8.0) -> TestResult:
        self.emit("log", f"[6] Load ramp at {self.cfg.frame_size} B ({per_step:.0f}s per step)")
        rows = []
        ok_all = True
        size = self.cfg.frame_size
        full = line_rate_pps(size, self.cfg.link_mbps)
        for pct in self.cfg.ramp_percents:
            pps = full * pct / 100.0
            self.emit("log", f"    {pct}% of line rate = {human_pps(pps)} pps")
            r = self.s.run_stream(size=size, pps=pps, duration=per_step,
                                  bidir=self.cfg.bidirectional,
                                  phase=f"ramp {pct}%")
            ok, _ = self._verdict(r)
            ok_all &= ok
            n_dir = 2 if self.cfg.bidirectional else 1
            rows.append({
                "target_pct": pct,
                "target_pps_per_dir": round(pps),
                "target_pps_total": round(pps * n_dir),
                "achieved_tx_pps_total": round(r["tx_pps"]),
                "rx_pps": round(r["rx_pps"]),
                "tx_mbps": round(r["tx_mbps"], 2),
                "rx_mbps": round(r["rx_mbps"], 2),
                "switch_loss_pct": round(r.get("dut_loss_pct", r["loss_pct"]), 4),
                "raw_loss_pct": round(r["loss_pct"], 4),
                "lat_avg_us": round(r["lat_avg_us"], 1),
                "lat_p99_us": round(max((s.get("p99", 0) for s in r["streams"].values()), default=0), 1),
                "host_drops": r.get("host_capture_drops", 0),
                "host_limited": "yes" if r.get("tx_limited") else "no",
                "result": "PASS" if ok else "FAIL",
            })
            self.emit("row", ("6. Load ramp", rows[-1]))
        return TestResult("6. Load ramp", ok_all,
                          "no loss up to the achieved offered load" if ok_all
                          else "loss appeared as offered load increased",
                          {}, rows)

    # 7 ------------------------------------------------------------------
    def t_burst(self) -> TestResult:
        self.emit("log", "[7] Back-to-back burst / buffer depth")
        rows = []
        ok_all = True
        size = self.cfg.frame_size
        for n in self.cfg.burst_sizes:
            self.emit("log", f"    burst of {n} frames at max host rate")
            r = self.s.run_stream(size=size, pps=0, duration=0, count=n,
                                  bidir=False, phase=f"burst {n}")
            hd = r.get("host_capture_drops", 0)
            lost = r["lost"]
            dut = r.get("dut_loss_pct", r["loss_pct"])
            ok = dut <= self.cfg.loss_threshold_pct
            ok_all &= ok
            rows.append({
                "burst_frames": n,
                "tx": r["tx_frames"], "rx": r["rx_frames"],
                "lost_total": lost,
                "host_drops": hd,
                "switch_lost": int(r.get("dut_lost", lost)),
                "switch_loss_pct": round(dut, 4),
                "burst_pps": round(r["tx_pps"]),
                "lat_max_us": round(r["lat_max_us"], 1),
                "result": "PASS" if ok else "FAIL",
            })
            self.emit("row", ("7. Burst / buffer depth", rows[-1]))
        first_fail = next((x for x in rows if x["result"] == "FAIL"), None)
        hd_total = sum(x["host_drops"] for x in rows)
        if ok_all:
            detail = "switch absorbed all bursts without dropping a frame"
        else:
            detail = (f"first switch loss at a burst of {first_fail['burst_frames']} "
                      f"frames ({first_fail['switch_lost']} dropped) - indicates the "
                      f"switch's output buffer depth")
        if hd_total:
            detail += (f"  [{hd_total} frame(s) discarded by this PC's capture driver "
                       f"were excluded from the switch's score]")
        return TestResult("7. Burst / buffer depth", ok_all, detail, {}, rows)

    # 8 ------------------------------------------------------------------
    def t_bidir_soak(self, duration: float = 20.0) -> TestResult:
        self.emit("log", f"[8] Bidirectional full-duplex soak ({duration:.0f}s)")
        size = self.cfg.frame_size
        pps = self._pps_for(size)
        r = self.s.run_stream(size=size, pps=pps, duration=duration,
                              bidir=True, phase="bidir soak")
        ok, det = self._verdict(r)
        rows = []
        for lbl, s in r["streams"].items():
            rows.append({
                "direction": lbl, "tx": s["tx_frames"], "rx": s["rx_frames"],
                "lost": s["lost"], "loss_pct": round(s["loss_pct"], 4),
                "rx_mbps": round(s["rx_mbps"], 2),
                "lat_avg_us": round(s["lat_avg_us"], 1),
                "lat_p99_us": round(s.get("p99", 0), 1),
                "jitter_us": round(s.get("jitter", 0), 1),
                "reorder": s["reorder"], "dup": s["dup"],
                "result": "PASS" if s["loss_pct"] <= self.cfg.loss_threshold_pct else "FAIL",
            })
        return TestResult("8. Bidirectional soak", ok, det, {}, rows)


    # 9 ---------------------------------------------------------------
    def t_vlan(self) -> TestResult:
        """802.1Q-tagged forwarding. A tag shifts every field by 4 bytes."""
        self.emit("log", "[9] 802.1Q VLAN-tagged frame forwarding")
        c = self.cfg
        rows = []
        ok_all = True
        for vid, pcp in ((1, 0), (100, 0), (100, 5), (4094, 7)):
            self.s.settle()
            tpl = build_vlan_template(c.mac_b, c.mac_a, 512, STREAM_A2B, vid, pcp)
            self.s.stop_event.clear()
            tx = Transmitter(self.s.sender_a, tpl, self.s.stats[STREAM_A2B],
                             1000, 0, self.s.stop_event, count=500)
            t0 = time.perf_counter()
            tx.start(); tx.join(timeout=10); time.sleep(0.7)
            r = self.s._collect(time.perf_counter() - t0, 512, False, 1000, [tx])
            ok = r["rx_frames"] >= 480
            ok_all &= ok
            rows.append({"vlan_id": vid, "priority_pcp": pcp,
                         "tx": r["tx_frames"], "rx": r["rx_frames"],
                         "loss_pct": round(r["loss_pct"], 3),
                         "lat_avg_us": round(r["lat_avg_us"], 1),
                         "result": "PASS" if ok else "FAIL"})
            self.emit("row", ("9. VLAN tagged forwarding", rows[-1]))
        detail = ("tagged frames forwarded at every tested VID/priority"
                  if ok_all else
                  "tagged frames were dropped or mangled - check the VLAN "
                  "configuration and the tag-parsing path")
        return TestResult("9. VLAN tagged forwarding", ok_all, detail, {}, rows)

    # 10 --------------------------------------------------------------
    def t_frame_limits(self) -> TestResult:
        """
        Boundary frame sizes. A correct switch forwards 64..1518 and must not
        forward runts. Sizes above 1518 depend on whether jumbo is enabled.
        """
        self.emit("log", "[10] frame size boundaries (runt / min / max / jumbo)")
        rows = []
        ok_all = True
        checks = [(64, True, "minimum legal"), (65, True, "odd size"),
                  (127, True, "odd size"), (512, True, "typical"),
                  (1518, True, "maximum legal untagged"),
                  (1522, None, "802.1Q max (informational)"),
                  (2048, None, "jumbo (informational)"),
                  (9018, None, "9k jumbo (informational)")]
        for size, expect, note in checks:
            self.s.settle()
            r = self.s.run_stream(size=size, pps=500, duration=0, count=300,
                                  bidir=False, phase=f"size {size}", live=False)
            got = r["rx_frames"]
            if expect is True:
                ok = got >= 285
                ok_all &= ok
                verdict = "PASS" if ok else "FAIL"
            else:
                verdict = "forwarded" if got >= 285 else "not forwarded"
            rows.append({"frame_size": size, "note": note,
                         "tx": r["tx_frames"], "rx": got,
                         "loss_pct": round(r["loss_pct"], 3),
                         "expected": "must forward" if expect else "optional",
                         "result": verdict})
            self.emit("row", ("10. Frame size boundaries", rows[-1]))
        jumbo = [x for x in rows if x["expected"] == "optional"
                 and x["result"] == "forwarded"]
        detail = ("all legal sizes 64-1518 forwarded"
                  if ok_all else "a legal frame size was not forwarded")
        if jumbo:
            detail += f"; oversize forwarded up to {max(x['frame_size'] for x in jumbo)} B"
        else:
            detail += "; nothing above 1518 B was forwarded (jumbo disabled)"
        return TestResult("10. Frame size boundaries", ok_all, detail, {}, rows)

    # 11 --------------------------------------------------------------
    def t_imix(self, duration: float = 20.0) -> TestResult:
        """
        RFC-2544 style IMIX: real traffic is not one frame size. Cycling sizes
        stresses the buffer allocator in a way a fixed size never does.
        """
        self.emit("log", f"[11] IMIX mixed-size soak ({duration:.0f}s)")
        c = self.cfg
        mix = [64] * 7 + [576] * 4 + [1518] * 1        # ~7:4:1 RFC 2544 IMIX
        avg = sum(mix) / len(mix)
        pps = self._pps_for(int(avg))
        self.s.settle()
        tpls = {sz: build_template(c.mac_b, c.mac_a, sz, STREAM_A2B) for sz in set(mix)}
        st = self.s.stats[STREAM_A2B]
        self.s.stop_event.clear()
        st.note_tx_begin()
        drop_base = self.s._host_drops_raw()
        interval = 1.0 / pps if pps > 0 else 0
        t0 = time.perf_counter()
        sent = 0
        send = self.s.sender_a.send
        nbytes = 0
        while time.perf_counter() - t0 < duration and not self.s.stop_event.is_set():
            if interval:
                target = (time.perf_counter() - t0) / interval
                if sent > target:
                    time.sleep(0)
                    continue
            sz = mix[sent % len(mix)]
            buf = tpls[sz]
            stamp(buf, sent, now_ns())
            send(buf)
            nbytes += len(buf)
            sent += 1
            if sent % 256 == 0:
                st.on_tx(256, 0)
        st.note_tx_end()
        st.on_tx(sent % 256, nbytes)
        time.sleep(0.8)
        r = self.s._collect(time.perf_counter() - t0, int(avg), False, pps, [])
        hd = max(0, self.s._host_drops_raw() - drop_base)
        ok = r["loss_pct"] <= c.loss_threshold_pct or hd >= r["lost"] * 0.5
        rows = [{"mix": "7x64B + 4x576B + 1x1518B", "avg_frame_B": round(avg, 1),
                 "tx": r["tx_frames"], "rx": r["rx_frames"], "lost": r["lost"],
                 "host_drops": hd, "loss_pct": round(r["loss_pct"], 4),
                 "rx_mbps": round(r["rx_mbps"], 2),
                 "lat_avg_us": round(r["lat_avg_us"], 1),
                 "lat_max_us": round(r["lat_max_us"], 1),
                 "worst_1s_loss_pct": round(r.get("worst_1s_loss_pct", 0), 3),
                 "result": "PASS" if ok else "FAIL"}]
        detail = ("mixed frame sizes handled without loss" if ok else
                  f"loss {r['loss_pct']:.4f}% under mixed-size load - buffer "
                  f"allocation may struggle with varied frame sizes")
        return TestResult("11. IMIX mixed-size soak", ok, detail, {}, rows)


FULL_SUITE = [
    ("t_link", "Link / connectivity"),
    ("t_unknown_unicast", "Unknown-unicast flooding"),
    ("t_broadcast", "Broadcast forwarding"),
    ("t_mac_learning", "MAC learning / CAM"),
    ("t_frame_sweep", "Frame-size sweep"),
    ("t_load_ramp", "Load ramp"),
    ("t_burst", "Burst / buffer depth"),
    ("t_bidir_soak", "Bidirectional soak"),
    ("t_vlan", "VLAN tagged forwarding"),
    ("t_frame_limits", "Frame size boundaries"),
    ("t_imix", "IMIX mixed-size soak"),
]


# ==========================================================================
# 6. REPORTING (self-contained HTML + CSV)
# ==========================================================================

def _svg_line_chart(series: List[Tuple[str, List[Tuple[float, float]], str]],
                    title: str, xlabel: str, ylabel: str,
                    w: int = 620, h: int = 240) -> str:
    """Tiny dependency-free SVG line chart."""
    pad_l, pad_r, pad_t, pad_b = 58, 14, 28, 34
    pw, ph = w - pad_l - pad_r, h - pad_t - pad_b
    xs = [p[0] for _, pts, _ in series for p in pts]
    ys = [p[1] for _, pts, _ in series for p in pts]
    if not xs:
        return f'<div class="muted">{html.escape(title)}: no data</div>'
    xmin, xmax = min(xs), max(xs)
    ymin, ymax = 0.0, max(ys) if max(ys) > 0 else 1.0
    ymax *= 1.15
    if xmax == xmin:
        xmax = xmin + 1

    def sx(x):
        return pad_l + (x - xmin) / (xmax - xmin) * pw

    def sy(y):
        return pad_t + ph - (y - ymin) / (ymax - ymin) * ph

    out = [f'<svg viewBox="0 0 {w} {h}" class="chart" xmlns="http://www.w3.org/2000/svg">']
    out.append(f'<text x="{w/2}" y="16" class="t">{html.escape(title)}</text>')
    for i in range(5):
        y = pad_t + ph * i / 4
        val = ymax - (ymax - ymin) * i / 4
        out.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{pad_l+pw}" y2="{y:.1f}" class="g"/>')
        out.append(f'<text x="{pad_l-6}" y="{y+4:.1f}" class="ax" text-anchor="end">{val:.4g}</text>')
    out.append(f'<text x="{pad_l+pw/2}" y="{h-6}" class="ax" text-anchor="middle">{html.escape(xlabel)}</text>')
    out.append(f'<text x="12" y="{pad_t+ph/2}" class="ax" transform="rotate(-90 12 {pad_t+ph/2})" text-anchor="middle">{html.escape(ylabel)}</text>')
    lx = pad_l + 6
    for name, pts, color in series:
        if not pts:
            continue
        d = " ".join(("M" if i == 0 else "L") + f"{sx(x):.1f},{sy(y):.1f}"
                     for i, (x, y) in enumerate(pts))
        out.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="2"/>')
        for x, y in pts:
            out.append(f'<circle cx="{sx(x):.1f}" cy="{sy(y):.1f}" r="2.5" fill="{color}"/>')
        out.append(f'<rect x="{lx}" y="{pad_t+4}" width="10" height="10" fill="{color}"/>')
        out.append(f'<text x="{lx+14}" y="{pad_t+13}" class="ax">{html.escape(name)}</text>')
        lx += 16 + 7 * len(name)
    out.append("</svg>")
    return "".join(out)


REPORT_CSS = """
:root{--bg:#0f1115;--card:#171a21;--fg:#e6e9ef;--mut:#8b93a7;--ok:#2ecc71;--bad:#ff5c5c;--acc:#4da3ff}
*{box-sizing:border-box}
body{margin:0;padding:28px;background:var(--bg);color:var(--fg);
 font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:26px 0 10px;color:var(--acc)}
.sub{color:var(--mut);margin-bottom:22px}
.card{background:var(--card);border:1px solid #232734;border-radius:10px;padding:16px;margin-bottom:16px}
.kpis{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:18px}
.kpi{background:var(--card);border:1px solid #232734;border-radius:10px;padding:12px 16px;min-width:132px}
.kpi .v{font-size:20px;font-weight:600}.kpi .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:7px 10px;text-align:right;border-bottom:1px solid #232734}
th{color:var(--mut);font-weight:600;text-transform:uppercase;font-size:10.5px;letter-spacing:.6px}
th:first-child,td:first-child{text-align:left}
.pass{color:var(--ok);font-weight:600}.fail{color:var(--bad);font-weight:600}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600}
.b-pass{background:rgba(46,204,113,.15);color:var(--ok)}.b-fail{background:rgba(255,92,92,.15);color:var(--bad)}
.muted{color:var(--mut)}
.chart{width:100%;max-width:660px;background:#12151c;border-radius:8px;margin-top:10px}
.chart .t{fill:#e6e9ef;font-size:12px;text-anchor:middle;font-weight:600}
.chart .ax{fill:#8b93a7;font-size:10px}.chart .g{stroke:#232734;stroke-width:1}
.meta{display:grid;grid-template-columns:170px 1fr;gap:4px 14px;font-size:13px}
.meta div:nth-child(odd){color:var(--mut)}
"""


def build_report(cfg: Config, results: List[TestResult], notes: str = "") -> str:
    n_pass = sum(1 for r in results if r.ok)
    n_fail = len(results) - n_pass
    overall = "PASS" if n_fail == 0 else "FAIL"

    def table(rows: List[Dict]) -> str:
        if not rows:
            return '<div class="muted">no data</div>'
        cols = list(rows[0].keys())
        h = "".join(f"<th>{html.escape(str(c).replace('_',' '))}</th>" for c in cols)
        body = []
        for r in rows:
            tds = []
            for c in cols:
                v = r.get(c, "")
                cls = ""
                if c == "result":
                    cls = ' class="pass"' if v == "PASS" else ' class="fail"'
                tds.append(f"<td{cls}>{html.escape(str(v))}</td>")
            body.append("<tr>" + "".join(tds) + "</tr>")
        return f"<table><thead><tr>{h}</tr></thead><tbody>{''.join(body)}</tbody></table>"

    def g(row, *names, default=0.0):
        """First present key wins - column names evolve, exports must not crash."""
        for n in names:
            if n in row:
                try:
                    return float(row[n])
                except (TypeError, ValueError):
                    return default
        return default

    charts = []
    for r in results:
        if r.name.startswith("5.") and r.rows:
            pts_rx = [(g(x, "frame_size"), g(x, "rx_mbps")) for x in r.rows]
            pts_tx = [(g(x, "frame_size"), g(x, "tx_mbps")) for x in r.rows]
            charts.append((r.name, _svg_line_chart(
                [("TX Mbps", pts_tx, "#4da3ff"), ("RX Mbps", pts_rx, "#2ecc71")],
                "Throughput vs frame size", "frame size (bytes)", "Mbps")
                + _svg_line_chart(
                [("avg", [(g(x, "frame_size"), g(x, "lat_avg_us")) for x in r.rows], "#ffb454"),
                 ("max", [(g(x, "frame_size"), g(x, "lat_max_us")) for x in r.rows], "#ff5c5c")],
                "Latency vs frame size", "frame size (bytes)", "microseconds")))
        if r.name.startswith("6.") and r.rows:
            charts.append((r.name, _svg_line_chart(
                [("offered", [(g(x, "target_pct"), g(x, "tx_mbps")) for x in r.rows], "#4da3ff"),
                 ("received", [(g(x, "target_pct"), g(x, "rx_mbps")) for x in r.rows], "#2ecc71")],
                "Offered vs received load", "% of line rate", "Mbps")
                + _svg_line_chart(
                [("switch loss %", [(g(x, "target_pct"), g(x, "switch_loss_pct", "loss_pct")) for x in r.rows], "#ff5c5c")],
                "Packet loss vs load", "% of line rate", "loss %")))
        if r.name.startswith("7.") and r.rows:
            charts.append((r.name, _svg_line_chart(
                [("switch loss %", [(g(x, "burst_frames"), g(x, "switch_loss_pct", "loss_pct")) for x in r.rows], "#ff5c5c")],
                "Loss vs burst size", "burst length (frames)", "loss %")))
    chart_map = {}
    for name, svg in charts:
        chart_map.setdefault(name, "")
        chart_map[name] += svg

    sections = []
    for r in results:
        badge = f'<span class="badge {"b-pass" if r.ok else "b-fail"}">{"PASS" if r.ok else "FAIL"}</span>'
        sections.append(
            f'<h2>{html.escape(r.name)} {badge}</h2>'
            f'<div class="card"><div class="muted" style="margin-bottom:10px">'
            f'{html.escape(r.detail)}</div>{table(r.rows)}'
            f'{chart_map.get(r.name,"")}</div>')

    meta = [
        ("Report generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Port A (TX)", cfg.iface_a), ("Port A MAC", cfg.mac_a),
        ("Port B (TX)", cfg.iface_b), ("Port B MAC", cfg.mac_b),
        ("Assumed link speed", f"{cfg.link_mbps} Mbps"),
        ("Default frame size", f"{cfg.frame_size} B (on-wire, incl. FCS)"),
        ("Rate mode", f"{cfg.rate_mode} = {cfg.rate_value:g}"),
        ("Loss pass threshold", f"{cfg.loss_threshold_pct} %"),
        ("Latency calibration", f"-{cfg.latency_offset_us:.1f} us (direct-cable baseline)"
            if cfg.latency_offset_us else "not calibrated"),
    ]
    meta_html = "".join(f"<div>{html.escape(k)}</div><div>{html.escape(str(v))}</div>"
                        for k, v in meta)

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>ETH Switch Test Report</title><style>{REPORT_CSS}</style></head><body>
<h1>Ethernet Switch Test Report</h1>
<div class="sub">Layer-2 raw-frame validation &mdash; EtherType 0x88B5</div>
<div class="kpis">
  <div class="kpi"><div class="l">Overall</div><div class="v {'pass' if overall=='PASS' else 'fail'}">{overall}</div></div>
  <div class="kpi"><div class="l">Tests passed</div><div class="v">{n_pass}/{len(results)}</div></div>
  <div class="kpi"><div class="l">Loss threshold</div><div class="v">{cfg.loss_threshold_pct}%</div></div>
  <div class="kpi"><div class="l">Link</div><div class="v">{cfg.link_mbps} Mbps</div></div>
</div>
<div class="card"><div class="meta">{meta_html}</div></div>
{'<div class="card"><b>Notes</b><br>' + html.escape(notes).replace(chr(10), '<br>') + '</div>' if notes else ''}
{''.join(sections)}
<div class="sub" style="margin-top:26px">Latency figures include the USB-Ethernet
adapter and host capture path in both directions. Use the direct-cable
calibration to subtract that baseline; the switch's own contribution is the
delta. Rows flagged <i>host_limited=yes</i> mean the PC could not generate the
requested rate &mdash; the loss number is still valid, the offered load is not.</div>
</body></html>"""


def write_csv(path: str, results: List[TestResult]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["test", "result", "detail"])
        for r in results:
            w.writerow([r.name, "PASS" if r.ok else "FAIL", r.detail])
        for r in results:
            if not r.rows:
                continue
            w.writerow([])
            w.writerow([r.name])
            cols = list(r.rows[0].keys())
            w.writerow(cols)
            for row in r.rows:
                w.writerow([row.get(c, "") for c in cols])


# ==========================================================================
# 7. GUI
# ==========================================================================

TK_OK = True
TK_ERR = ""
try:
    import tkinter as tk                                # noqa: E402
    from tkinter import filedialog, messagebox, ttk     # noqa: E402
except Exception as _te:                                # pragma: no cover
    # Headless environment (e.g. --selftest on a server). Provide stubs so the
    # class definitions below still parse; main() refuses to start the GUI.
    TK_OK = False
    TK_ERR = str(_te)

    class _TkStub:
        def __getattr__(self, name):
            return type(name, (object,), {"__init__": lambda self, *a, **k: None})

    tk = _TkStub()          # type: ignore
    ttk = _TkStub()         # type: ignore
    filedialog = _TkStub()  # type: ignore
    messagebox = _TkStub()  # type: ignore

BG = "#0f1115"
CARD = "#171a21"
FG = "#e6e9ef"
MUT = "#8b93a7"
ACC = "#4da3ff"
OK = "#2ecc71"
BAD = "#ff5c5c"
WARN = "#ffb454"
GRID = "#232734"


def _axis_fmt(v: float) -> str:
    a = abs(v)
    if a >= 1e6:
        return f"{v/1e6:.2f}M"
    if a >= 1e3:
        return f"{v/1e3:.1f}k"
    if a >= 10:
        return f"{v:.0f}"
    if a >= 0.01:
        return f"{v:.2f}"
    return "0" if a == 0 else f"{v:.3g}"


class LineChart(tk.Canvas):
    """Lightweight rolling line chart (no matplotlib dependency)."""

    def __init__(self, master, title: str, unit: str, series: List[Tuple[str, str]],
                 maxlen: int = 240, height: int = 150, ymin_span: float = 1.0):
        super().__init__(master, bg="#12151c", highlightthickness=1,
                         highlightbackground=GRID, height=height)
        self.title = title
        self.unit = unit
        self.series_def = series
        self.maxlen = maxlen
        self.ymin_span = ymin_span
        self.data: Dict[str, List[Optional[float]]] = {n: [] for n, _ in series}
        self.marks: List[Tuple[int, str]] = []
        self.cur_phase = ""
        self.bind("<Configure>", lambda e: self.redraw())

    def push(self, values: Dict[str, float], idle: bool = False,
             phase: str = "") -> None:
        """
        `idle=True` stores a gap instead of a zero. Drawing a line down to zero
        during the pause between test steps looks like a throughput collapse;
        it is just silence while the previous step drains.
        """
        trimmed = 0
        for name, _ in self.series_def:
            v = None if idle else float(values.get(name, 0.0))
            d = self.data[name]
            d.append(v)
            if len(d) > self.maxlen:
                trimmed = len(d) - self.maxlen
                del d[0:trimmed]
        # Remember where the phase changed so a divider can be drawn there.
        # Indices only shift when old samples are actually dropped off the
        # left edge - shifting on every push made the labels crawl away from
        # the step they belong to.
        if phase != self.cur_phase:
            self.cur_phase = phase
            n = len(self.data[self.series_def[0][0]]) if self.series_def else 0
            if n:
                self.marks.append((n - 1, phase))
        if trimmed:
            self.marks = [(i - trimmed, p) for i, p in self.marks
                          if i - trimmed >= 0]
        self.marks = self.marks[-40:]

    def clear(self) -> None:
        for k in self.data:
            self.data[k] = []
        self.marks = []
        self.cur_phase = ""
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        w = self.winfo_width() or 400
        h = self.winfo_height() or 150
        pl, pr, pt, pb = 56, 10, 20, 18
        pw, ph = max(10, w - pl - pr), max(10, h - pt - pb)
        ymax = self.ymin_span
        for d in self.data.values():
            vals = [v for v in d if v is not None]
            if vals:
                ymax = max(ymax, max(vals))
        ymax *= 1.2
        self.create_text(pl, 10, text=self.title, fill=FG, anchor="w",
                         font=("Segoe UI", 9, "bold"))
        for i in range(5):
            y = pt + ph * i / 4
            self.create_line(pl, y, pl + pw, y, fill=GRID)
            val = ymax * (1 - i / 4)
            self.create_text(pl - 6, y, text=_axis_fmt(val), fill=MUT,
                             anchor="e", font=("Segoe UI", 7))
        self.create_text(pl - 6, pt + ph + 9, text=self.unit, fill=MUT,
                         anchor="e", font=("Segoe UI", 7))
        # phase dividers, drawn behind the traces
        n_all = len(self.data[self.series_def[0][0]]) if self.series_def else 0
        if n_all >= 2:
            step0 = pw / max(1, self.maxlen - 1)
            off0 = pw - step0 * (n_all - 1)
            for idx, label in self.marks:
                if not (0 <= idx < n_all) or not label:
                    continue
                x = pl + off0 + idx * step0
                if x < pl or x > pl + pw:
                    continue
                self.create_line(x, pt, x, pt + ph, fill="#39415a", dash=(2, 3))
                row = self.marks.index((idx, label)) % 2
                self.create_text(x + 3, pt + 14 + row * 9, text=label, fill=MUT,
                                 anchor="nw", font=("Segoe UI", 7))
        lx = pl + 8
        for name, color in self.series_def:
            d = self.data[name]
            if len(d) >= 2:
                step = pw / max(1, self.maxlen - 1)
                off = pw - step * (len(d) - 1)
                seg: List[float] = []
                for i, v in enumerate(d):
                    if v is None:
                        if len(seg) >= 4:
                            self.create_line(*seg, fill=color, width=2, smooth=False)
                        seg = []
                        continue
                    seg.append(pl + off + i * step)
                    seg.append(pt + ph - (v / ymax) * ph if ymax else pt + ph)
                if len(seg) >= 4:
                    self.create_line(*seg, fill=color, width=2, smooth=False)
            live = [v for v in d if v is not None]
            cur = live[-1] if live else 0.0
            self.create_rectangle(lx, pt + 2, lx + 8, pt + 10, fill=color, outline="")
            txt = f"{name} {_axis_fmt(cur)}"
            self.create_text(lx + 12, pt + 6, text=txt, fill=MUT, anchor="w",
                             font=("Segoe UI", 8))
            lx += 24 + 6.2 * len(txt)


class BitTimingView(tk.Canvas):
    """
    Digital timing diagram of frames crossing the switch.

    There is no analogue capture here - we cannot show MLT-3 line levels or a
    real eye diagram. What this DOES show, and what actually matters for a
    forwarding test, is the digital truth on a time axis:

      Panel 1  every frame as a pulse on a TX rail and an RX rail. The
               horizontal distance between a frame's two pulses IS its
               latency, so jitter is visible as ragged connector slopes.
      Panel 2  the transmitted bit stream and the received bit stream drawn as
               NRZ waveforms, one above the other, with an XOR row beneath.
               A flat XOR row is proof the bits came through unchanged.
      Panel 3  cumulative bit-error count per bit position (0-7), which
               catches a stuck or weak data line that random spot-checks miss.
    """

    def __init__(self, master):
        super().__init__(master, bg="#0f1218", highlightthickness=1,
                         highlightbackground=GRID)
        self.snap: Dict = {"frames": [], "bits": 0, "errors": 0, "by_pos": [0] * 8}
        self.frame_idx = 0
        self.nbits = 64
        self.bind("<Configure>", lambda e: self.redraw())

    def set_data(self, snap: Dict) -> None:
        self.snap = snap
        self.frame_idx = max(0, len(snap.get("frames", [])) - 1)
        self.redraw()

    # ---- drawing helpers ------------------------------------------------
    def _wave(self, bits, x0, y_hi, y_lo, step, color, width=2):
        """NRZ square wave: horizontal run per bit, vertical edge on change."""
        pts = []
        prev = None
        x = x0
        for b in bits:
            y = y_hi if b else y_lo
            if prev is not None and y != prev:
                pts.extend([x, prev])
            pts.extend([x, y])
            x += step
            pts.extend([x, y])
            prev = y
        if len(pts) >= 4:
            self.create_line(*pts, fill=color, width=width)

    def redraw(self) -> None:
        self.delete("all")
        W = self.winfo_width() or 900
        H = self.winfo_height() or 560
        frames = self.snap.get("frames", [])
        if not frames:
            self.create_text(W / 2, H / 2, fill=MUT, font=("Segoe UI", 10),
                             text="Run a test, then press  Capture bits  to draw "
                                  "the timing diagram")
            return
        pad = 74
        # ================= panel 1: transit timing =====================
        # Latency (tens of us) is far smaller than the gap between frames
        # (hundreds of us), so a true-to-scale wall-clock axis renders the
        # transit as sub-pixel. Instead every frame is ALIGNED ON ITS OWN
        # TRANSMIT instant and the x axis is microseconds since that instant:
        # the RX pulse then sits at exactly that frame's latency, and the
        # horizontal scatter across rows IS the jitter.
        p1_top = 30
        show = frames[-40:]
        lat = [f["lat_ns"] / 1000.0 for f in show]
        lmin, lmax = min(lat), max(lat)
        lavg = sum(lat) / len(lat)
        xmax = max(1.0, lmax * 1.15)
        rows_h = 96
        self.create_text(pad, p1_top - 12, anchor="w", fill=FG,
                         font=("Segoe UI", 9, "bold"),
                         text=("1.  Frame transit  -  each row is one frame, "
                               "aligned on transmit. Distance to the green pulse "
                               "is that frame's latency."))
        gx0, gx1 = pad, W - 30

        def X(us):
            return gx0 + (us / xmax) * (gx1 - gx0)

        # microsecond grid
        ticks = 6
        for i in range(ticks + 1):
            us = xmax * i / ticks
            x = X(us)
            self.create_line(x, p1_top, x, p1_top + rows_h, fill="#20263a")
            self.create_text(x, p1_top + rows_h + 9, fill=MUT,
                             font=("Consolas", 7), text=f"{us:.0f}")
        self.create_text(gx0, p1_top + rows_h + 21, anchor="w", fill=MUT,
                         font=("Segoe UI", 7),
                         text="microseconds after transmit")
        # avg / min / max reference lines
        for us, col in ((lmin, "#39415a"), (lavg, WARN), (lmax, "#39415a")):
            x = X(us)
            self.create_line(x, p1_top, x, p1_top + rows_h, fill=col, dash=(3, 3))
        self.create_text(X(lavg), p1_top + rows_h + 9, anchor="n", fill=WARN,
                         font=("Consolas", 7), text=f"avg {lavg:.0f}")
        self.create_text(pad - 8, p1_top + 6, anchor="ne", fill=ACC,
                         font=("Segoe UI", 7, "bold"), text="TX")
        self.create_text(pad - 8, p1_top + rows_h - 6, anchor="se", fill=OK,
                         font=("Segoe UI", 7, "bold"), text="RX")
        n = len(show)
        dy = rows_h / max(1, n)
        for i, f in enumerate(show):
            y = p1_top + 3 + i * dy
            bad = f["bit_errors"] > 0
            x2 = X(f["lat_ns"] / 1000.0)
            # transit bar: length == latency
            self.create_line(gx0, y, x2, y, fill=BAD if bad else "#2f3b57",
                             width=max(1, int(dy * 0.55)))
            self.create_line(gx0, y - dy * 0.3, gx0, y + dy * 0.3, fill=ACC,
                             width=2)
            self.create_line(x2, y - dy * 0.35, x2, y + dy * 0.35,
                             fill=BAD if bad else OK, width=2)
        self.create_text(gx1, p1_top + rows_h + 21, anchor="e", fill=MUT,
                         font=("Consolas", 8),
                         text=(f"{n} frames    min {lmin:.1f}    avg {lavg:.1f}    "
                               f"max {lmax:.1f} us    jitter spread "
                               f"{lmax - lmin:.1f} us"))
        p1_h = rows_h + 34

        # ================= panel 2: bit streams ========================
        p2_top = p1_top + p1_h + 26
        f = frames[min(self.frame_idx, len(frames) - 1)]
        data = f["data"]
        start = ETH_HDR_LEN + HDR_LEN
        if len(data) > 13 and data[12] == 0x81 and data[13] == 0x00:
            start += 4
        nby = max(1, min(self.nbits // 8, len(data) - start))
        rx_bits, tx_bits = [], []
        for i in range(nby):
            got = data[start + i]
            exp = expected_pay_byte(i)
            for b in range(7, -1, -1):
                rx_bits.append((got >> b) & 1)
                tx_bits.append((exp >> b) & 1)
        xor = [a ^ b for a, b in zip(tx_bits, rx_bits)]
        step = (W - pad - 24) / max(1, len(tx_bits))
        self.create_text(pad, p2_top - 10, anchor="w", fill=FG,
                         font=("Segoe UI", 9, "bold"),
                         text=(f"2.  Bit stream, payload bytes 0-{nby-1} of frame "
                               f"seq {f['seq']}  (MSB first, NRZ)"))
        rows = [("sent", tx_bits, ACC), ("received", rx_bits, OK),
                ("XOR", xor, BAD if any(xor) else "#2b3242")]
        for r, (lbl, bits, col) in enumerate(rows):
            y_hi = p2_top + 12 + r * 40
            y_lo = y_hi + 22
            self.create_text(pad - 6, (y_hi + y_lo) / 2, anchor="e", fill=col,
                             font=("Segoe UI", 7, "bold"), text=lbl)
            self.create_line(pad, y_lo + 1, W - 24, y_lo + 1, fill="#20263a")
            self._wave(bits, pad, y_hi, y_lo, step, col,
                       2 if r < 2 else (2 if any(xor) else 1))
        # byte boundaries
        for i in range(nby + 1):
            x = pad + i * 8 * step
            self.create_line(x, p2_top + 8, x, p2_top + 12 + 2 * 40 + 22,
                             fill="#20263a", dash=(1, 4))
            if i < nby:
                self.create_text(x + 4 * step, p2_top + 12 + 2 * 40 + 34,
                                 fill=MUT, font=("Consolas", 7),
                                 text=f"0x{data[start+i]:02X}")
        ok_txt = ("all %d bits identical" % len(tx_bits)) if not any(xor) else \
                 ("%d BIT ERRORS in this frame" % sum(xor))
        self.create_text(W - 24, p2_top - 10, anchor="e",
                         fill=OK if not any(xor) else BAD,
                         font=("Segoe UI", 9, "bold"), text=ok_txt)

        # ================= panel 3: bit-position histogram =============
        p3_top = p2_top + 12 + 3 * 40 + 44
        tot = self.snap.get("bits", 0)
        errs = self.snap.get("errors", 0)
        by = self.snap.get("by_pos", [0] * 8)
        ber = (errs / tot) if tot else 0.0
        self.create_text(pad, p3_top, anchor="w", fill=FG,
                         font=("Segoe UI", 9, "bold"),
                         text="3.  Cumulative bit errors by bit position")
        self.create_text(W - 24, p3_top, anchor="e",
                         fill=OK if errs == 0 else BAD, font=("Consolas", 9),
                         text=(f"{tot:,} bits compared      {errs} errors      "
                               f"BER {'0' if errs == 0 else f'{ber:.2e}'}"))
        bw = 26
        base = p3_top + 62
        mx = max(1, max(by))
        for i in range(8):
            x = pad + i * (bw + 16)
            h = int((by[i] / mx) * 44) if by[i] else 1
            self.create_rectangle(x, base - h, x + bw, base,
                                  fill=OK if by[i] == 0 else BAD, outline="")
            self.create_text(x + bw / 2, base + 9, fill=MUT,
                             font=("Consolas", 7), text=f"b{i}")
            self.create_text(x + bw / 2, base - h - 7, fill=MUT,
                             font=("Consolas", 7), text=str(by[i]))
        self.create_text(pad + 8 * (bw + 16) + 12, base - 18, anchor="w", fill=MUT,
                         font=("Segoe UI", 8),
                         text=("every position clean - no stuck or weak data line"
                               if errs == 0 else
                               "errors concentrated in one position indicate a "
                               "stuck or weak data line"))


class KPI(tk.Frame):
    def __init__(self, master, label: str, width: int = 118):
        super().__init__(master, bg=CARD, highlightthickness=1,
                         highlightbackground=GRID)
        self.configure(width=width, height=56)
        self.pack_propagate(False)
        tk.Label(self, text=label.upper(), bg=CARD, fg=MUT,
                 font=("Segoe UI", 7, "bold")).pack(anchor="w", padx=8, pady=(6, 0))
        self.var = tk.StringVar(value="-")
        self.lbl = tk.Label(self, textvariable=self.var, bg=CARD, fg=FG,
                            font=("Segoe UI", 14, "bold"))
        self.lbl.pack(anchor="w", padx=8)

    def set(self, text: str, color: str = FG) -> None:
        self.var.set(text)
        self.lbl.configure(fg=color)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ETH Switch Tester  v1.0   -   L2 raw-frame validation")
        self.geometry("1280x850")
        self.configure(bg=BG)
        self.minsize(1080, 720)

        self.cfg = Config()
        self.session: Optional[Session] = None
        self.results: List[TestResult] = []
        self.q: "queue.Queue[Tuple[str, object]]" = queue.Queue()
        self.worker: Optional[threading.Thread] = None
        self.running = False
        self.ifaces: List[Tuple[str, str, str]] = []   # (display, scapy_name, mac)
        self.console_rows = 0
        self._last_tap: Optional[Dict] = None

        self._style()
        self._build()
        self.refresh_ifaces()
        self.after(120, self._pump)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        if not SCAPY_OK:
            self.log("scapy is not installed. Run:  pip install scapy", BAD)
            self.log("Also install Npcap from https://npcap.com", BAD)

    # ---- styling -------------------------------------------------------
    def _style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure(".", background=BG, foreground=FG, fieldbackground=CARD,
                    bordercolor=GRID, font=("Segoe UI", 9))
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=CARD, foreground=MUT,
                    padding=(16, 7), borderwidth=0)
        s.map("TNotebook.Tab", background=[("selected", BG)],
              foreground=[("selected", ACC)])
        s.configure("TCombobox", fieldbackground=CARD, background=CARD,
                    foreground=FG, arrowcolor=FG, selectbackground=CARD,
                    selectforeground=FG)
        s.map("TCombobox",
              fieldbackground=[("readonly", CARD), ("disabled", CARD)],
              foreground=[("readonly", FG), ("disabled", MUT)],
              selectbackground=[("readonly", CARD)],
              selectforeground=[("readonly", FG)])
        # the drop-down list is a classic Tk listbox, styled via the option DB
        self.option_add("*TCombobox*Listbox.background", CARD)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", ACC)
        self.option_add("*TCombobox*Listbox.selectForeground", "#0b0d12")
        s.configure("Treeview", background=CARD, fieldbackground=CARD,
                    foreground=FG, rowheight=22, borderwidth=0)
        s.configure("Treeview.Heading", background=BG, foreground=MUT,
                    relief="flat", font=("Segoe UI", 8, "bold"))
        s.map("Treeview", background=[("selected", "#26456b")])
        s.configure("H.Horizontal.TProgressbar", background=ACC, troughcolor=CARD,
                    borderwidth=0, lightcolor=ACC, darkcolor=ACC)

    def _btn(self, master, text, cmd, color=ACC, width=15):
        b = tk.Button(master, text=text, command=cmd, bg=color, fg="#0b0d12",
                      activebackground=color, relief="flat", bd=0, width=width,
                      font=("Segoe UI", 9, "bold"), cursor="hand2", pady=5)
        return b

    # ---- layout --------------------------------------------------------
    def _build(self):
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=12, pady=(10, 6))

        # --- interface row
        ifr = tk.Frame(top, bg=CARD, highlightthickness=1, highlightbackground=GRID)
        ifr.pack(fill="x")
        inner = tk.Frame(ifr, bg=CARD)
        inner.pack(fill="x", padx=10, pady=8)

        tk.Label(inner, text="PORT A (into switch)", bg=CARD, fg=MUT,
                 font=("Segoe UI", 7, "bold")).grid(row=0, column=0, sticky="w")
        self.cb_a = ttk.Combobox(inner, width=52, state="readonly")
        self.cb_a.grid(row=1, column=0, padx=(0, 10), sticky="w")

        tk.Label(inner, text="PORT B (into switch)", bg=CARD, fg=MUT,
                 font=("Segoe UI", 7, "bold")).grid(row=0, column=1, sticky="w")
        self.cb_b = ttk.Combobox(inner, width=52, state="readonly")
        self.cb_b.grid(row=1, column=1, padx=(0, 10), sticky="w")

        self._btn(inner, "Refresh", self.refresh_ifaces, "#2b3242", 9).grid(row=1, column=2, padx=3)
        self._btn(inner, "Swap", self.swap_ifaces, "#2b3242", 7).grid(row=1, column=3, padx=3)
        self.v_eth_only = tk.BooleanVar(value=True)
        tk.Checkbutton(inner, text="wired Ethernet ports only",
                       variable=self.v_eth_only, command=self._apply_iface_filter,
                       bg=CARD, fg=FG, selectcolor="#0f1218", activebackground=CARD,
                       activeforeground=FG, font=("Segoe UI", 8)).grid(
            row=1, column=4, padx=(10, 0), sticky="w")
        tk.Label(inner, text="pick the two USB-Ethernet adapters that are plugged "
                             "into the switch  -  [ETH] = wired, link status shown",
                 bg=CARD, fg=MUT, font=("Segoe UI", 7)).grid(
            row=2, column=0, columnspan=5, sticky="w", pady=(4, 0))

        # --- parameters row
        pr = tk.Frame(top, bg=CARD, highlightthickness=1, highlightbackground=GRID)
        pr.pack(fill="x", pady=(8, 0))
        p = tk.Frame(pr, bg=CARD)
        p.pack(fill="x", padx=10, pady=8)

        def lab(txt, c):
            tk.Label(p, text=txt, bg=CARD, fg=MUT,
                     font=("Segoe UI", 7, "bold")).grid(row=0, column=c, sticky="w", padx=(0, 8))

        self.v_link = tk.StringVar(value="100")
        self.v_size = tk.StringVar(value="512")
        self.v_mode = tk.StringVar(value="percent")
        self.v_rate = tk.StringVar(value="50")
        self.v_dur = tk.StringVar(value="15")
        self.v_thr = tk.StringVar(value="0.10")
        self.v_bidir = tk.BooleanVar(value=True)

        lab("LINK Mbps", 0); lab("FRAME SIZE B", 1); lab("RATE MODE", 2)
        lab("RATE VALUE", 3); lab("DURATION s", 4); lab("LOSS THR %", 5)

        ttk.Combobox(p, textvariable=self.v_link, width=8, state="readonly",
                     values=["10", "100", "1000"]).grid(row=1, column=0, sticky="w", padx=(0, 8))
        ttk.Combobox(p, textvariable=self.v_size, width=8,
                     values=["64", "128", "256", "512", "1024", "1280", "1518"]).grid(row=1, column=1, sticky="w", padx=(0, 8))
        ttk.Combobox(p, textvariable=self.v_mode, width=10, state="readonly",
                     values=["percent", "pps", "mbps", "max"]).grid(row=1, column=2, sticky="w", padx=(0, 8))
        tk.Entry(p, textvariable=self.v_rate, width=10, bg="#0f1218", fg=FG,
                 insertbackground=FG, relief="flat").grid(row=1, column=3, sticky="w", padx=(0, 8))
        tk.Entry(p, textvariable=self.v_dur, width=8, bg="#0f1218", fg=FG,
                 insertbackground=FG, relief="flat").grid(row=1, column=4, sticky="w", padx=(0, 8))
        tk.Entry(p, textvariable=self.v_thr, width=8, bg="#0f1218", fg=FG,
                 insertbackground=FG, relief="flat").grid(row=1, column=5, sticky="w", padx=(0, 14))
        tk.Checkbutton(p, text="bidirectional (full duplex)", variable=self.v_bidir,
                       bg=CARD, fg=FG, selectcolor="#0f1218", activebackground=CARD,
                       activeforeground=FG, font=("Segoe UI", 8)).grid(row=1, column=6, sticky="w")

        # --- action row
        ar = tk.Frame(top, bg=BG)
        ar.pack(fill="x", pady=(8, 0))
        self.b_quick = self._btn(ar, "Quick Check", self.run_quick, "#2ecc71", 13)
        self.b_load = self._btn(ar, "Run Load Test", self.run_load, ACC, 14)
        self.b_full = self._btn(ar, "Full Test Suite", self.run_full, "#a78bfa", 15)
        self.b_cal = self._btn(ar, "Calibrate (direct cable)", self.run_calibrate, "#2b3242", 22)
        self.b_stop = self._btn(ar, "STOP", self.stop_run, BAD, 8)
        for b in (self.b_quick, self.b_load, self.b_full, self.b_cal, self.b_stop):
            b.pack(side="left", padx=(0, 8))
        self.b_stop.configure(state="disabled")
        self._btn(ar, "Export Report", self.export_report, "#2b3242", 14).pack(side="right")

        self.pbar = ttk.Progressbar(top, style="H.Horizontal.TProgressbar", mode="determinate")
        self.pbar.pack(fill="x", pady=(8, 0))
        self.status = tk.Label(top, text="idle", bg=BG, fg=MUT, anchor="w",
                               font=("Segoe UI", 8))
        self.status.pack(fill="x")

        # --- notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=12, pady=(8, 12))
        self.tab_dash = tk.Frame(nb, bg=BG)
        self.tab_res = tk.Frame(nb, bg=BG)
        self.tab_bits = tk.Frame(nb, bg=BG)
        self.tab_con = tk.Frame(nb, bg=BG)
        self.tab_log = tk.Frame(nb, bg=BG)
        nb.add(self.tab_dash, text="  Live Dashboard  ")
        nb.add(self.tab_res, text="  Results  ")
        nb.add(self.tab_bits, text="  Bits / Timing  ")
        nb.add(self.tab_con, text="  Frame Console  ")
        nb.add(self.tab_log, text="  Log  ")
        self._build_dash()
        self._build_results()
        self._build_bits()
        self._build_console()
        self._build_log()

    # ---- dashboard -----------------------------------------------------
    def _build_dash(self):
        k = tk.Frame(self.tab_dash, bg=BG)
        k.pack(fill="x", pady=(8, 4))
        self.kpi = {}
        for key, label, wdt in [
            ("txpps", "TX pps", 110), ("rxpps", "RX pps", 110),
            ("txmbps", "TX Mbps", 110), ("rxmbps", "RX Mbps", 110),
            ("loss", "Loss %", 110), ("lost", "Frames lost", 118),
            ("lavg", "Lat avg us", 118), ("lmax", "Lat max us", 118),
            ("jit", "Jitter us", 110), ("ooo", "Reorder", 96), ("dup", "Dup", 84),
            ("hdrop", "Host drops", 112), ("bad", "Corrupt", 92),
        ]:
            w = KPI(k, label, wdt)
            w.pack(side="left", padx=(0, 8))
            self.kpi[key] = w

        cw = tk.Frame(self.tab_dash, bg=BG)
        cw.pack(fill="both", expand=True)
        self.ch_tp = LineChart(cw, "Throughput", "Mbps",
                               [("TX", ACC), ("RX", OK)], height=112)
        self.ch_pps = LineChart(cw, "Frame rate", "pps",
                                [("TX", ACC), ("RX", OK)], height=112)
        self.ch_loss = LineChart(cw, "Cumulative packet loss", "%",
                                 [("loss", BAD)], height=92, ymin_span=0.5)
        self.ch_lat = LineChart(cw, "Latency (one-way, incl. host path)", "us",
                                [("avg", WARN), ("max", BAD)], height=112)
        for c in (self.ch_tp, self.ch_pps, self.ch_loss, self.ch_lat):
            c.pack(fill="both", expand=True, pady=3)

    # ---- results -------------------------------------------------------
    def _build_results(self):
        wrap = tk.Frame(self.tab_res, bg=BG)
        wrap.pack(fill="both", expand=True, pady=8)
        cols = ("test", "result", "detail")
        self.tv = ttk.Treeview(wrap, columns=cols, show="tree headings", height=26)
        self.tv.heading("#0", text="")
        self.tv.column("#0", width=26, stretch=False)
        for c, w, a in (("test", 300, "w"), ("result", 70, "center"), ("detail", 640, "w")):
            self.tv.heading(c, text=c.upper())
            self.tv.column(c, width=w, anchor=a)
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=vs.set)
        self.tv.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tv.tag_configure("pass", foreground=OK)
        self.tv.tag_configure("fail", foreground=BAD)
        self.tv.tag_configure("row", foreground=MUT)

    # ---- bits / timing -------------------------------------------------
    def _build_bits(self):
        bar = tk.Frame(self.tab_bits, bg=CARD, highlightthickness=1,
                       highlightbackground=GRID)
        bar.pack(fill="x", pady=(8, 0))
        inner = tk.Frame(bar, bg=CARD)
        inner.pack(fill="x", padx=10, pady=7)
        self._btn(inner, "Capture bits", self.bits_capture, ACC, 13).pack(side="left")
        self._btn(inner, "< prev frame", lambda: self.bits_step(-1),
                  "#2b3242", 12).pack(side="left", padx=(8, 0))
        self._btn(inner, "next frame >", lambda: self.bits_step(1),
                  "#2b3242", 12).pack(side="left", padx=(6, 0))
        tk.Label(inner, text="bits shown", bg=CARD, fg=MUT,
                 font=("Segoe UI", 7, "bold")).pack(side="left", padx=(16, 4))
        self.v_nbits = tk.StringVar(value="64")
        cb = ttk.Combobox(inner, textvariable=self.v_nbits, width=5,
                          state="readonly", values=["32", "64", "96", "128"])
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda e: self.bits_refresh())
        self.lbl_bits = tk.Label(inner, text="", bg=CARD, fg=MUT,
                                 font=("Segoe UI", 8))
        self.lbl_bits.pack(side="left", padx=14)
        tk.Label(self.tab_bits,
                 text="Digital only - no analogue line sampling, so this is not an "
                      "eye diagram. It proves the bits that went in came out, and "
                      "when.",
                 bg=BG, fg=MUT, font=("Segoe UI", 8)).pack(anchor="w", pady=(6, 2))
        self.bitview = BitTimingView(self.tab_bits)
        self.bitview.pack(fill="both", expand=True)

    def bits_capture(self):
        s = self.session
        if s is None:
            # nothing running: show whatever the last run left behind
            if self._last_tap is None:
                messagebox.showinfo(
                    "Nothing captured yet",
                    "Start a test (Quick Check or Run Load Test), then press "
                    "Capture bits while it is running or right after it ends.")
                return
            snap = self._last_tap
        else:
            s.bit_tap.enabled = True
            snap = s.bit_tap.snapshot()
            self._last_tap = snap
        if not snap.get("frames"):
            self.log("bit capture armed - run a test and press Capture bits again",
                     WARN)
            self.lbl_bits.configure(text="armed, waiting for frames...")
            return
        self._apply_bits(snap)

    def _apply_bits(self, snap):
        self.bitview.nbits = int(self.v_nbits.get())
        self.bitview.set_data(snap)
        n = len(snap["frames"])
        self.lbl_bits.configure(
            text=(f"{n} frames captured   |   {snap['bits']:,} bits compared   |   "
                  f"{snap['errors']} bit errors"))

    def bits_step(self, d):
        v = self.bitview
        if not v.snap.get("frames"):
            return
        v.frame_idx = max(0, min(len(v.snap["frames"]) - 1, v.frame_idx + d))
        v.nbits = int(self.v_nbits.get())
        v.redraw()

    def bits_refresh(self):
        self.bitview.nbits = int(self.v_nbits.get())
        self.bitview.redraw()

    # ---- console -------------------------------------------------------
    def _build_console(self):
        f = tk.Frame(self.tab_con, bg=BG)
        f.pack(fill="both", expand=True, pady=8)
        top = tk.Frame(f, bg=CARD, highlightthickness=1, highlightbackground=GRID)
        top.pack(fill="x")
        g = tk.Frame(top, bg=CARD)
        g.pack(fill="x", padx=10, pady=8)

        tk.Label(g, text="DST MAC", bg=CARD, fg=MUT, font=("Segoe UI", 7, "bold")).grid(row=0, column=0, sticky="w")
        tk.Label(g, text="PAYLOAD (text, or 0x.. hex)", bg=CARD, fg=MUT, font=("Segoe UI", 7, "bold")).grid(row=0, column=1, sticky="w")
        tk.Label(g, text="COUNT", bg=CARD, fg=MUT, font=("Segoe UI", 7, "bold")).grid(row=0, column=2, sticky="w")
        tk.Label(g, text="FROM", bg=CARD, fg=MUT, font=("Segoe UI", 7, "bold")).grid(row=0, column=3, sticky="w")

        self.v_dst = tk.StringVar(value="ff:ff:ff:ff:ff:ff")
        self.v_pay = tk.StringVar(value="HELLO SWITCH")
        self.v_cnt = tk.StringVar(value="1")
        self.v_from = tk.StringVar(value="A")
        tk.Entry(g, textvariable=self.v_dst, width=20, bg="#0f1218", fg=FG,
                 insertbackground=FG, relief="flat").grid(row=1, column=0, padx=(0, 10), sticky="w")
        tk.Entry(g, textvariable=self.v_pay, width=52, bg="#0f1218", fg=FG,
                 insertbackground=FG, relief="flat").grid(row=1, column=1, padx=(0, 10), sticky="w")
        tk.Entry(g, textvariable=self.v_cnt, width=7, bg="#0f1218", fg=FG,
                 insertbackground=FG, relief="flat").grid(row=1, column=2, padx=(0, 10), sticky="w")
        ttk.Combobox(g, textvariable=self.v_from, width=4, state="readonly",
                     values=["A", "B"]).grid(row=1, column=3, padx=(0, 10), sticky="w")
        self._btn(g, "Send frame", self.console_send, ACC, 12).grid(row=1, column=4, padx=4)
        self._btn(g, "Sniff ALL", self.console_sniff_all, "#2b3242", 11).grid(row=1, column=5, padx=4)
        self._btn(g, "Clear", self.console_clear, "#2b3242", 8).grid(row=1, column=6, padx=4)

        tk.Label(f, text="Received frames (both ports)  -  'Sniff ALL' also shows "
                         "non-test traffic the switch forwards",
                 bg=BG, fg=MUT, font=("Segoe UI", 8)).pack(anchor="w", pady=(10, 2))
        self.con = tk.Text(f, bg="#0f1218", fg=FG, insertbackground=FG,
                           relief="flat", font=("Consolas", 9), wrap="none")
        self.con.pack(fill="both", expand=True)
        self.con.tag_configure("ours", foreground=OK)
        self.con.tag_configure("other", foreground=MUT)

    # ---- log -----------------------------------------------------------
    def _build_log(self):
        self.txt = tk.Text(self.tab_log, bg="#0f1218", fg=FG, relief="flat",
                           font=("Consolas", 9), wrap="word")
        self.txt.pack(fill="both", expand=True, pady=8)
        for tag, col in (("info", FG), ("mut", MUT), ("ok", OK),
                         ("bad", BAD), ("warn", WARN)):
            self.txt.tag_configure(tag, foreground=col)

    # ======================================================================
    # interfaces
    # ======================================================================
    # -- adapter classification -------------------------------------------
    @staticmethod
    def _kind(desc: str, phys: str = "") -> str:
        """ETH = usable wired port, WIFI / BT / VIRT = not usable for this test."""
        d = (desc or "").lower()
        p = (phys or "").lower()
        # Checked FIRST: Npcap/NDIS binding pseudo-interfaces all end in a
        # 4-digit suffix, e.g. "Realtek USB GbE #2-Npcap Packet Driver
        # (NPCAP)-0000". They cannot be opened for injection ("Interface ... not
        # found"), so they must never be offered - not even under a Wi-Fi/BT
        # label, or they would still be selectable.
        if re.search(r"-\d{4}$", desc or ""):
            return "VIRT"
        if "802.11" in p or any(k in d for k in
                                ("wi-fi", "wifi", "wireless", "802.11", "wlan")):
            return "WIFI"
        if "bluetooth" in d or "bluetooth" in p:
            return "BT"
        if any(k in d for k in ("filter", "scheduler", "lightweight", "native mac",
                                "qos packet", "wfp", "packet driver", "npcap",
                                "virtual", "vmware", "hyper-v", "virtualbox",
                                "loopback", "tap-", "tunnel", "teredo", "vpn",
                                "wan miniport", "kernel debug")):
            return "VIRT"
        return "ETH"

    def _netadapter_info(self) -> Dict[str, Dict]:
        """MAC -> {Status, LinkSpeed, PhysicalMediaType} via Get-NetAdapter."""
        if os.name != "nt":
            return {}
        try:
            flags = 0x08000000 if os.name == "nt" else 0   # CREATE_NO_WINDOW
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetAdapter | Select-Object MacAddress,Status,LinkSpeed,"
                 "InterfaceDescription,PhysicalMediaType | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=20,
                creationflags=flags).stdout
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            res = {}
            for d in data:
                mac = (d.get("MacAddress") or "").replace("-", ":").lower()
                if mac:
                    res[mac] = d
            return res
        except Exception:
            return {}

    def refresh_ifaces(self):
        self.ifaces = []
        if not SCAPY_OK:
            self.cb_a["values"] = self.cb_b["values"] = ["<scapy not installed>"]
            return
        extra = self._netadapter_info()
        try:
            raw = []
            if get_windows_if_list:
                for d in get_windows_if_list():
                    mac = (d.get("mac") or "").lower()
                    if not mac or mac == "00:00:00:00:00:00":
                        continue
                    raw.append((d.get("description") or d.get("name") or "",
                                d.get("name") or "", mac,
                                ",".join(d.get("ips", [])[:1])))
            else:
                for nm in scapy_conf.ifaces.data.values():
                    mac = (getattr(nm, "mac", "") or "").lower()
                    if not mac or mac == "00:00:00:00:00:00":
                        continue
                    raw.append((getattr(nm, "name", str(nm)),
                                getattr(nm, "name", str(nm)), mac, ""))

            # One physical NIC can appear several times: the real adapter plus
            # one entry per protocol binding. They share a MAC, so keep only the
            # best candidate per MAC - a real adapter beats a pseudo-interface.
            best: Dict[str, Tuple] = {}
            for desc, name, mac, ip in raw:
                k = self._kind(desc, extra.get(mac, {}).get("PhysicalMediaType", ""))
                # rank: real adapter (0) before pseudo (1); then shortest name
                rank = (1 if k == "VIRT" else 0, len(desc or ""))
                cur = best.get(mac)
                if cur is None or rank < cur[0]:
                    best[mac] = (rank, desc, name, mac, ip)
            raw = [(t[1], t[2], t[3], t[4]) for t in best.values()]

            seen = set()
            for desc, name, mac, ip in raw:
                info = extra.get(mac, {})
                kind = self._kind(desc, info.get("PhysicalMediaType", ""))
                status = (info.get("Status") or "").strip()
                speed = (info.get("LinkSpeed") or "").strip()
                key = (desc, mac)
                if key in seen:
                    continue
                seen.add(key)
                # Scapy enumerates adapters from the registry, so an unplugged
                # USB NIC still appears. Windows only reports adapters that are
                # actually attached, so absence there means "not plugged in".
                present = bool(info) if extra else True
                up = present and status.lower() == "up"
                tag = {"ETH": "ETH ", "WIFI": "WiFi", "BT": "BT  ", "VIRT": "virt"}[kind]
                if not present:
                    link = "  |  *** NOT PLUGGED IN ***"
                elif status:
                    link = f"  |  {status}" + (f" {speed}" if speed and up else "")
                else:
                    link = ""
                disp = f"[{tag}] {desc}  |  {mac}{link}" + (f"  |  {ip}" if ip else "")
                self.ifaces.append((disp, name, mac, kind, up, present))
        except Exception as e:
            self.log(f"interface enumeration failed: {e}", BAD)

        order = {"ETH": 0, "WIFI": 1, "BT": 2, "VIRT": 3}
        # wired first, then link-up first, then actually-present first
        self.ifaces.sort(key=lambda t: (order[t[3]], not t[4], not t[5], t[0]))
        self._apply_iface_filter()

    def _apply_iface_filter(self):
        eth_only = bool(self.v_eth_only.get())
        shown = [t for t in self.ifaces if t[3] == "ETH"] if eth_only else self.ifaces
        if eth_only and not shown:
            shown = self.ifaces
            self.log("no wired adapters found - showing everything", WARN)
        vals = [t[0] for t in shown]
        self.cb_a["values"] = vals
        self.cb_b["values"] = vals
        # auto-pick two wired, link-up ports
        up = [t[0] for t in shown if t[3] == "ETH" and t[4]]
        pick = up if len(up) >= 2 else [t[0] for t in shown if t[3] == "ETH"] or vals
        if self.cb_a.get() not in vals:
            self.cb_a.set(pick[0] if pick else "")
        if self.cb_b.get() not in vals or self.cb_b.get() == self.cb_a.get():
            nxt = next((v for v in pick if v != self.cb_a.get()), "")
            self.cb_b.set(nxt)
        n_eth = sum(1 for t in self.ifaces if t[3] == "ETH")
        n_present = sum(1 for t in self.ifaces if t[3] == "ETH" and t[5])
        n_up = sum(1 for t in self.ifaces if t[3] == "ETH" and t[4])
        self.log(f"{len(self.ifaces)} adapters: {n_eth} wired "
                 f"({n_present} plugged into the PC, {n_up} with link up to a switch), "
                 f"{sum(1 for t in self.ifaces if t[3]=='WIFI')} Wi-Fi, "
                 f"{sum(1 for t in self.ifaces if t[3]=='VIRT')} virtual", MUT)
        if n_present < 2:
            self.log("WARNING: fewer than 2 USB-Ethernet adapters are PLUGGED INTO "
                     "THE PC. Windows does not see them at all - the entries below "
                     "marked 'NOT PLUGGED IN' are leftover driver records. Connect "
                     "the adapters (check the USB hub / dock) and press Refresh.", BAD)
        elif n_up < 2:
            self.log("WARNING: adapters are connected to the PC but fewer than 2 have "
                     "link UP. Plug their cables into the switch, wait for the link "
                     "LED, then press Refresh.", WARN)

    def swap_ifaces(self):
        a, b = self.cb_a.get(), self.cb_b.get()
        self.cb_a.set(b)
        self.cb_b.set(a)

    def _resolve(self, disp: str) -> Tuple:
        for t in self.ifaces:
            if t[0] == disp:
                return t
        raise ValueError("select both adapters first")

    def _read_cfg(self) -> Config:
        c = self.cfg
        ta = self._resolve(self.cb_a.get())
        tb = self._resolve(self.cb_b.get())
        c.iface_a, c.mac_a, kind_a, up_a, present_a = ta[1], ta[2], ta[3], ta[4], ta[5]
        c.iface_b, c.mac_b, kind_b, up_b, present_b = tb[1], tb[2], tb[3], tb[4], tb[5]
        for tag, kind in (("A", kind_a), ("B", kind_b)):
            if kind == "WIFI":
                raise ValueError(
                    f"Port {tag} is a Wi-Fi adapter.\n\n"
                    "This tool injects raw Ethernet frames into a cable. A Wi-Fi "
                    "card cannot carry them to the switch, so every frame would be "
                    "reported as lost.\n\nPick the USB-Ethernet adapters instead "
                    "(they are marked [ETH]).")
            if kind in ("BT", "VIRT"):
                raise ValueError(
                    f"Port {tag} is not a physical wired port ({kind}). "
                    "Pick an adapter marked [ETH].")
        if c.iface_a == c.iface_b or c.mac_a == c.mac_b:
            raise ValueError(
                "Port A and Port B are the same physical adapter"
                f" (MAC {c.mac_a}).\n\nThe test needs two separate USB-Ethernet "
                "adapters, each cabled into a different port on the switch.")
        if not present_a or not present_b:
            miss = ", ".join(t for t, p in (("A", present_a), ("B", present_b)) if not p)
            raise ValueError(
                f"Port {miss}: that adapter is NOT PLUGGED INTO THIS PC.\n\n"
                "Windows has no such network interface right now - what you selected "
                "is a leftover driver record from the last time it was connected, "
                "which is why frames would go nowhere.\n\n"
                "Connect the USB-Ethernet adapter (check the USB hub or dock), then "
                "press Refresh.")
        if not up_a or not up_b:
            down = ", ".join(t for t, u in (("A", up_a), ("B", up_b)) if not u)
            raise ValueError(
                f"Port {down} has no link.\n\nThe adapter is connected to the PC but "
                "its cable is not linked to a switch port. Plug it in, wait for the "
                "link LED, then press Refresh.")
        c.link_mbps = int(self.v_link.get())
        c.frame_size = max(MIN_FRAME, min(9018, int(self.v_size.get())))
        c.rate_mode = self.v_mode.get()
        c.rate_value = float(self.v_rate.get() or 0)
        c.duration = float(self.v_dur.get() or 10)
        c.loss_threshold_pct = float(self.v_thr.get() or 0.1)
        c.bidirectional = bool(self.v_bidir.get())
        return c

    # ======================================================================
    # logging / events
    # ======================================================================
    def log(self, msg: str, color: str = FG) -> None:
        tag = {FG: "info", MUT: "mut", OK: "ok", BAD: "bad", WARN: "warn"}.get(color, "info")
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            self.txt.insert("end", f"[{ts}] {msg}\n", tag)
            self.txt.see("end")
        except Exception:
            print(msg)

    def emit(self, kind: str, payload: object) -> None:
        self.q.put((kind, payload))

    def _pump(self) -> None:
        redraw = False
        try:
            for _ in range(400):
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self.log(str(payload), MUT)
                elif kind == "logc":
                    m, c = payload  # type: ignore
                    self.log(m, c)
                elif kind == "sample":
                    self._on_sample(payload)  # type: ignore
                    redraw = True
                elif kind == "status":
                    self.status.configure(text=str(payload))
                elif kind == "progress":
                    self.pbar["value"] = float(payload)  # type: ignore
                elif kind == "result":
                    self._on_result(payload)  # type: ignore
                elif kind == "row":
                    self._on_row(payload)  # type: ignore
                elif kind == "console":
                    self._on_console(payload)  # type: ignore
                elif kind == "done":
                    self._on_done(str(payload))
        except queue.Empty:
            pass
        if redraw:
            for c in (self.ch_tp, self.ch_pps, self.ch_loss, self.ch_lat):
                c.redraw()
        self.after(120, self._pump)

    def _on_sample(self, s: Dict) -> None:
        k = self.kpi
        k["txpps"].set(human_pps(s["tx_pps"]))
        k["rxpps"].set(human_pps(s["rx_pps"]))
        k["txmbps"].set(f"{s['tx_mbps']:.1f}")
        k["rxmbps"].set(f"{s['rx_mbps']:.1f}", OK if s["rx_mbps"] > 0 else MUT)
        loss = s["loss_pct"]
        k["loss"].set(f"{loss:.3f}",
                      OK if loss <= self.cfg.loss_threshold_pct else
                      (WARN if loss < 1 else BAD))
        lost = (sum(v.get("lost_confirmed", v.get("lost", 0))
                    for v in s["streams"].values()) if s["streams"] else 0)
        ooo = sum(v["reorder"] for v in s["streams"].values()) if s["streams"] else 0
        dup = sum(v["dup"] for v in s["streams"].values()) if s["streams"] else 0
        k["lost"].set(f"{lost}", OK if lost == 0 else BAD)
        k["ooo"].set(f"{ooo}", OK if ooo == 0 else WARN)
        k["dup"].set(f"{dup}", OK if dup == 0 else WARN)
        # Host drops tell you instantly whether a live loss spike is your PC's
        # capture buffer or the switch. Without this the two look identical.
        hd = s.get("host_drops", 0)
        k["hdrop"].set(f"{hd}", OK if hd == 0 else WARN)
        bad = sum(v.get("bad_payload", 0) for v in s["streams"].values()) if s["streams"] else 0
        k["bad"].set(f"{bad}", OK if bad == 0 else BAD)
        off = self.cfg.latency_offset_us
        k["lavg"].set(f"{max(0.0, s['lat_avg_us']-off):.0f}")
        k["lmax"].set(f"{max(0.0, s['lat_max_us']-off):.0f}")
        jit = s.get("jitter_us", 0.0)
        k["jit"].set(f"{jit:.1f}" if jit else "-",
                     OK if jit < 200 else (WARN if jit < 1000 else BAD))
        if s.get("phase"):
            self.status.configure(text=f"running: {s['phase']}")
        # Between test steps the tool deliberately stops sending (settle +
        # drain). Recording that as 0 Mbps drew a cliff that looked like a
        # throughput collapse, so it is stored as a gap in the trace instead.
        idle = s["tx_pps"] <= 0 and s["rx_pps"] <= 0
        ph = s.get("phase", "") or ""
        self.ch_tp.push({"TX": s["tx_mbps"], "RX": s["rx_mbps"]}, idle, ph)
        self.ch_pps.push({"TX": s["tx_pps"], "RX": s["rx_pps"]}, idle, ph)
        self.ch_loss.push({"loss": loss}, idle, ph)
        self.ch_lat.push({"avg": max(0.0, s["lat_avg_us"] - off),
                          "max": max(0.0, s["lat_max_us"] - off)}, idle, ph)

    def _on_result(self, r: TestResult) -> None:
        self.results.append(r)
        node = self.tv.insert("", "end", text="",
                              values=(r.name, "PASS" if r.ok else "FAIL", r.detail),
                              tags=("pass" if r.ok else "fail",), open=False)
        for row in r.rows:
            txt = "   ".join(f"{k}={v}" for k, v in row.items())
            self.tv.insert(node, "end", text="", values=("", "", txt), tags=("row",))
        self.log(f"{r.name}: {'PASS' if r.ok else 'FAIL'} - {r.detail}",
                 OK if r.ok else BAD)

    def _on_row(self, payload) -> None:
        name, row = payload
        self.log("    " + "  ".join(f"{k}={v}" for k, v in row.items()), MUT)

    def _on_console(self, payload) -> None:
        line, ours = payload
        if self.console_rows > 2000:
            self.con.delete("1.0", "500.0")
            self.console_rows = 0
        self.con.insert("end", line + "\n", "ours" if ours else "other")
        self.con.see("end")
        self.console_rows += 1

    def _on_done(self, msg: str) -> None:
        self.running = False
        self.pbar["value"] = 100
        self.status.configure(text=msg)
        for b in (self.b_quick, self.b_load, self.b_full, self.b_cal):
            b.configure(state="normal")
        self.b_stop.configure(state="disabled")
        self.log(msg, OK if "complete" in msg.lower() else WARN)

    # ======================================================================
    # run control
    # ======================================================================
    def _start(self, fn, label: str):
        if self.running:
            messagebox.showinfo("Busy", "A test is already running.")
            return
        if not SCAPY_OK:
            messagebox.showerror(
                "Missing dependency",
                "scapy could not be imported by THIS interpreter:\n\n"
                f"  {sys.executable}\n\n"
                f"Import error:\n  {SCAPY_ERR or 'unknown'}\n\n"
                "Most likely you launched the .py file directly, which Windows "
                "runs with py.exe - and that picks the newest Python, often a "
                "Store build with no packages.\n\n"
                "Fix: start it with START-TESTER.bat, or run\n"
                '  "C:\\Program Files\\Python313\\python.exe" eth_switch_tester.py\n\n'
                "Otherwise: pip install scapy, and install Npcap from "
                "https://npcap.com")
            return
        try:
            self._read_cfg()
        except Exception as e:
            messagebox.showerror("Configuration", str(e))
            return
        self.running = True
        self.pbar["value"] = 0
        for b in (self.b_quick, self.b_load, self.b_full, self.b_cal):
            b.configure(state="disabled")
        self.b_stop.configure(state="normal")
        for c in (self.ch_tp, self.ch_pps, self.ch_loss, self.ch_lat):
            c.clear()
        self.log("=" * 74, MUT)
        self.log(f"START: {label}", ACC)
        self.log(f"  A = {self.cfg.iface_a}  [{self.cfg.mac_a}]", MUT)
        self.log(f"  B = {self.cfg.iface_b}  [{self.cfg.mac_b}]", MUT)
        self.worker = threading.Thread(target=self._wrap, args=(fn, label), daemon=True)
        self.worker.start()

    def _wrap(self, fn, label):
        s = Session(self.cfg, self.emit)
        self.session = s
        try:
            s.open()
            s.bit_tap.enabled = True      # always tap, it is nearly free
            fn(s)
            self.emit("done", f"{label} complete")
        except Exception as e:
            import traceback
            self.emit("logc", (f"ERROR: {e}", BAD))
            self.emit("logc", (traceback.format_exc(), MUT))
            self.emit("done", f"{label} aborted: {e}")
        finally:
            try:
                self._last_tap = s.bit_tap.snapshot()
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
            self.session = None

    def stop_run(self):
        if self.session:
            self.session.stop_event.set()
            self.log("stop requested...", WARN)

    # --- the three run modes ---------------------------------------------
    def run_quick(self):
        def job(s: Session):
            suite = TestSuite(s, self.emit)
            self.emit("progress", 10)
            self.emit("result", suite.t_link())
            self.emit("progress", 40)
            self.emit("result", suite.t_unknown_unicast())
            self.emit("progress", 70)
            self.emit("result", suite.t_broadcast())
            self.emit("progress", 100)
        self.results = []
        for i in self.tv.get_children():
            self.tv.delete(i)
        self._start(job, "Quick check")

    def run_load(self):
        def job(s: Session):
            c = self.cfg
            suite = TestSuite(s, self.emit)
            pps = suite._pps_for(c.frame_size)
            self.emit("log", f"offered load: {human_pps(pps) if pps else 'MAX'} pps "
                             f"@ {c.frame_size} B, {c.duration:.0f}s, "
                             f"{'bidirectional' if c.bidirectional else 'A->B only'}")
            r = s.run_stream(size=c.frame_size, pps=pps, duration=c.duration,
                             bidir=c.bidirectional, phase="load")
            ok, det = suite._verdict(r)
            rows = []
            for lbl, st in r["streams"].items():
                rows.append({
                    "direction": lbl, "tx": st["tx_frames"], "rx": st["rx_frames"],
                    "lost": st["lost"], "loss_pct": round(st["loss_pct"], 4),
                    "tx_mbps": round(st["tx_mbps"], 2), "rx_mbps": round(st["rx_mbps"], 2),
                    "lat_avg_us": round(st["lat_avg_us"], 1),
                    "lat_min_us": round(st["lat_min_us"], 1),
                    "lat_max_us": round(st["lat_max_us"], 1),
                    "p99_us": round(st.get("p99", 0), 1),
                    "jitter_us": round(st.get("jitter", 0), 1),
                    "reorder": st["reorder"], "dup": st["dup"],
                    "result": "PASS" if st["loss_pct"] <= c.loss_threshold_pct else "FAIL",
                })
            if r.get("tx_limited"):
                self.emit("logc", (f"NOTE: host generated only "
                                   f"{r['rate_accuracy_pct']:.0f}% of the requested rate "
                                   f"- this is a PC/USB-adapter limit, not the switch.", WARN))
            self.emit("result", TestResult(
                f"Load test  {c.frame_size}B  {human_pps(pps) if pps else 'MAX'}pps"
                f"  {'bidir' if c.bidirectional else 'uni'}", ok, det, {}, rows))
            self.emit("progress", 100)
        self._start(job, "Load test")

    def run_full(self):
        def job(s: Session):
            suite = TestSuite(s, self.emit)
            c = self.cfg
            steps = [
                (suite.t_link, {}),
                (suite.t_unknown_unicast, {}),
                (suite.t_broadcast, {}),
                (suite.t_mac_learning, {}),
                (suite.t_frame_sweep, {"per_size": max(4.0, c.duration / 2)}),
                (suite.t_load_ramp, {"per_step": max(5.0, c.duration / 2)}),
                (suite.t_burst, {}),
                (suite.t_bidir_soak, {"duration": max(10.0, c.duration)}),
                (suite.t_vlan, {}),
                (suite.t_frame_limits, {}),
                (suite.t_imix, {"duration": max(10.0, c.duration)}),
            ]
            for i, (fn, kw) in enumerate(steps):
                if s.stop_event.is_set():
                    self.emit("logc", ("suite stopped by user", WARN))
                    break
                self.emit("progress", i / len(steps) * 100)
                self.emit("result", fn(**kw))
            self.emit("progress", 100)
            n_fail = sum(1 for r in self.results if not r.ok)
            self.emit("logc", (f"SUITE FINISHED - {len(self.results)-n_fail} passed, "
                               f"{n_fail} failed", OK if n_fail == 0 else BAD))
        self.results = []
        for i in self.tv.get_children():
            self.tv.delete(i)
        self._start(job, "Full test suite")

    def run_calibrate(self):
        if not messagebox.askokcancel(
                "Latency calibration",
                "Unplug BOTH adapters from the switch and connect them "
                "DIRECTLY to each other with one cable.\n\n"
                "This measures the baseline latency of the PC + USB adapters, "
                "which is then subtracted so the reported figure reflects the "
                "switch.\n\nReady?"):
            return

        def job(s: Session):
            self.cfg.latency_offset_us = 0.0
            r = s.run_stream(size=self.cfg.frame_size, pps=1000, duration=0,
                             count=3000, bidir=False, phase="calibration")
            if r["rx_frames"] < 100:
                self.emit("logc", ("calibration failed - no frames received on the "
                                   "direct cable. Check the link.", BAD))
                return
            base = 0.0
            for st in r["streams"].values():
                base = st["lat_min_us"]
            self.cfg.latency_offset_us = base
            self.emit("logc", (f"baseline (direct cable) = {base:.1f} us  "
                               f"(min of {r['rx_frames']} frames). "
                               f"This is now subtracted from all latency figures.", OK))
            self.emit("result", TestResult(
                "0. Latency calibration (direct cable)", True,
                f"host+adapter baseline {base:.1f} us subtracted from later results",
                {}, [{"frames": r["rx_frames"],
                      "baseline_min_us": round(base, 1),
                      "avg_us": round(r["lat_avg_us"], 1),
                      "max_us": round(r["lat_max_us"], 1),
                      "result": "PASS"}]))
            self.emit("progress", 100)
        self._start(job, "Calibration")

    # ======================================================================
    # frame console
    # ======================================================================
    def console_clear(self):
        self.con.delete("1.0", "end")
        self.console_rows = 0

    def console_sniff_all(self):
        self._console_run(sniff_all=True)

    def console_send(self):
        self._console_run(sniff_all=False)

    def _console_run(self, sniff_all: bool):
        if self.running:
            messagebox.showinfo("Busy", "A test is running.")
            return
        try:
            self._read_cfg()
        except Exception as e:
            messagebox.showerror("Configuration", str(e))
            return
        dst = self.v_dst.get().strip()
        raw_pay = self.v_pay.get()
        try:
            count = max(1, int(self.v_cnt.get()))
        except Exception:
            count = 1
        from_a = self.v_from.get() == "A"

        if raw_pay.lower().startswith("0x"):
            try:
                payload = bytes.fromhex(raw_pay[2:].replace(" ", ""))
            except Exception as e:
                messagebox.showerror("Payload", f"bad hex: {e}")
                return
        else:
            payload = raw_pay.encode("utf-8", "replace")

        def job(s: Session):
            def hook(data: bytes, rx_ns: int):
                p = parse(data)
                ts = datetime.fromtimestamp(rx_ns / 1e9).strftime("%H:%M:%S.%f")[:-3]
                d = mac_bytes_to_str(data[0:6])
                sr = mac_bytes_to_str(data[6:12])
                et = struct.unpack_from("!H", data, 12)[0]
                if p:
                    sid, seq, tx_ns = p
                    lat = (rx_ns - tx_ns) / 1000.0
                    body = data[ETH_HDR_LEN + HDR_LEN:][:48]
                    txt = "".join(chr(b) if 32 <= b < 127 else "." for b in body)
                    line = (f"{ts}  {sr} -> {d}  0x{et:04x}  len={len(data)+4:4d}  "
                            f"stream={sid} seq={seq:<7d} lat={lat:8.1f}us  |{txt}|")
                    self.emit("console", (line, True))
                elif sniff_all:
                    line = (f"{ts}  {sr} -> {d}  0x{et:04x}  len={len(data)+4:4d}  "
                            f"(foreign traffic forwarded by the switch)")
                    self.emit("console", (line, False))
            s.console_hook = hook
            if sniff_all:
                # reopen capture without the BPF filter
                s.close()
                s.open(capture_all=True)
                s.console_hook = hook
                self.emit("logc", ("sniffing ALL traffic on both ports for 20 s...", ACC))
                t0 = time.perf_counter()
                while time.perf_counter() - t0 < 20 and not s.stop_event.is_set():
                    time.sleep(0.2)
                return
            c = self.cfg
            sender = s.sender_a if from_a else s.sender_b
            src = c.mac_a if from_a else c.mac_b
            sid = STREAM_A2B if from_a else STREAM_B2A
            size = max(MIN_FRAME, ETH_HDR_LEN + HDR_LEN + len(payload) + FCS_LEN)
            buf = build_template(dst, src, size, sid, pattern=b"\x00")
            off = ETH_HDR_LEN + HDR_LEN
            buf[off:off + len(payload)] = payload
            for i in range(count):
                stamp(buf, i, now_ns())
                sender.send(bytes(buf))
                self.emit("console",
                          (f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]}  TX {src} -> "
                           f"{dst}  0x88b5  len={size}  seq={i}  payload={payload[:40]!r}",
                           True))
                time.sleep(0.002)
            time.sleep(1.0)
        self._start(job, "Frame console")

    # ======================================================================
    # export
    # ======================================================================
    def export_report(self):
        if not self.results:
            messagebox.showinfo("Nothing to export", "Run a test first.")
            return
        default = f"switch_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        path = filedialog.asksaveasfilename(
            defaultextension=".html", initialfile=default,
            filetypes=[("HTML report", "*.html"), ("All files", "*.*")])
        if not path:
            return
        notes = (f"Adapters: A={self.cfg.iface_a} / B={self.cfg.iface_b}. "
                 f"Frames are raw EtherType 0x88B5 with sequence + timestamp; "
                 f"no TCP/IP involved.")
        with open(path, "w", encoding="utf-8") as f:
            f.write(build_report(self.cfg, self.results, notes))
        csv_path = os.path.splitext(path)[0] + ".csv"
        write_csv(csv_path, self.results)
        json_path = os.path.splitext(path)[0] + ".json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump([{"name": r.name, "ok": r.ok, "detail": r.detail,
                        "rows": r.rows} for r in self.results], f, indent=2)
        self.log(f"report written: {path}", OK)
        self.log(f"           csv: {csv_path}", MUT)
        try:
            os.startfile(path)  # type: ignore[attr-defined]
        except Exception:
            pass

    def _on_close(self):
        try:
            if self.session:
                self.session.stop_event.set()
                time.sleep(0.3)
                self.session.close()
        except Exception:
            pass
        self.destroy()


# ==========================================================================
# 8. ENTRY POINT
# ==========================================================================

def check_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True


def verify_honesty(iface_a: str, iface_b: str) -> int:
    """
    --verify : prove the measurements are not flattering reality.

    Injects a KNOWN amount of loss by discarding frames before they reach the
    wire, then checks that the reported numbers match what was actually
    destroyed. Run this on your own hardware whenever you doubt a result.
    """
    if not SCAPY_OK:
        print("scapy not available:", SCAPY_ERR)
        return 1
    cfg = Config(iface_a=iface_a, iface_b=iface_b,
                 mac_a=get_if_hwaddr(iface_a), mac_b=get_if_hwaddr(iface_b),
                 link_mbps=100, frame_size=512, loss_threshold_pct=0.10)
    print(f"A = {iface_a}  [{cfg.mac_a}]")
    print(f"B = {iface_b}  [{cfg.mac_b}]\n")

    state = {"mode": None, "n": 0, "killed": 0}
    orig = RawSender.send

    def sabotaged(self, data):
        if state["mode"] and iface_a in str(self.iface):
            i = state["n"]
            state["n"] += 1
            kind, param = state["mode"]
            hit = (i % param == 0) if kind == "every" else \
                  (param[0] <= i < param[1]) if kind == "window" else \
                  (i >= param)
            if hit:
                state["killed"] += 1
                return                      # destroyed before the wire
        return orig(self, data)

    RawSender.send = sabotaged
    fails = []

    def check(name, cond, msg):
        print(("  PASS      " if cond else "  ** FAIL **") + f" {name}: {msg}")
        if not cond:
            fails.append(name)

    s = Session(cfg, lambda k, p: None)
    try:
        s.open()
        print(f"capture: {s.capture_mode}\n")

        print("1) baseline, no sabotage")
        state["mode"] = None
        r = s.run_stream(size=512, pps=2000, duration=5.0, bidir=False, live=True)
        hd = r["host_capture_drops"]
        print(f"   tx={r['tx_frames']} rx={r['rx_frames']} lost={r['lost']} "
              f"host_drops={hd} loss={r['loss_pct']:.4f}% "
              f"worst_1s={r.get('worst_1s_loss_pct', 0):.3f}%")
        check("baseline attribution", r["lost"] == 0 or hd >= r["lost"] * 0.9,
              "any baseline loss must be attributed to host capture drops"
              f" (lost={r['lost']}, host={hd})")
        base_extra = max(0, r["lost"])

        print("\n2) exactly 1 frame in 200 destroyed (0.5%)")
        state["mode"], state["n"], state["killed"] = ("every", 200), 0, 0
        r = s.run_stream(size=512, pps=2000, duration=5.0, bidir=False, live=True)
        killed = state["killed"]
        print(f"   destroyed={killed}  reported lost={r['lost']}  "
              f"loss={r['loss_pct']:.4f}%  host_drops={r['host_capture_drops']}")
        check("uniform loss reported", r["lost"] >= killed,
              f"must report at least the {killed} frames actually destroyed")
        check("uniform loss not inflated",
              r["lost"] <= killed + base_extra + max(20, killed * 0.2),
              f"reported {r['lost']} vs {killed} destroyed + host drops")

        print("\n3) 300 consecutive frames destroyed mid-run (a burst)")
        state["mode"], state["n"], state["killed"] = ("window", (2000, 2300)), 0, 0
        r = s.run_stream(size=512, pps=2000, duration=5.0, bidir=False, live=True)
        print(f"   destroyed={state['killed']}  reported lost={r['lost']}  "
              f"run-average loss={r['loss_pct']:.4f}%  "
              f"WORST 1s window={r.get('worst_1s_loss_pct', 0):.2f}% "
              f"at t={r.get('worst_1s_at_s', 0):.1f}s")
        check("burst counted", r["lost"] >= state["killed"] * 0.98,
              f"reported {r['lost']} of {state['killed']} destroyed")
        check("burst visible as a spike", r.get("worst_1s_loss_pct", 0) >
              r["loss_pct"] * 1.5,
              f"the worst 1 s window ({r.get('worst_1s_loss_pct', 0):.2f}%) must "
              f"stand out above the run average ({r['loss_pct']:.4f}%) - "
              f"otherwise averaging would hide the event")

        print("\n4) the final 150 frames destroyed (no sequence gap follows them)")
        state["mode"], state["n"], state["killed"] = ("tail", 1850), 0, 0
        r = s.run_stream(size=512, pps=2000, duration=0, count=2000,
                         bidir=False, live=False)
        print(f"   destroyed={state['killed']}  reported lost={r['lost']}")
        check("tail loss counted", r["lost"] >= state["killed"] * 0.98,
              f"reported {r['lost']} of {state['killed']} - tail loss leaves no "
              f"sequence gap, so it must come from the TX counter")

        print("\n5) one-way fault: 2% on A->B only, B->A clean, bidirectional")
        state["mode"], state["n"], state["killed"] = ("every", 50), 0, 0
        r = s.run_stream(size=512, pps=2000, duration=5.0, bidir=True, live=False)
        a = r["streams"].get("A->B", {})
        b = r["streams"].get("B->A", {})
        print(f"   A->B loss={a.get('loss_pct', 0):.4f}%   "
              f"B->A loss={b.get('loss_pct', 0):.4f}%")
        print(f"   average={r['loss_pct']:.4f}%   worst-direction="
              f"{r.get('loss_pct_worst', 0):.4f}%")
        ok, det = TestSuite(s, lambda k, p: None)._verdict(r)
        print(f"   verdict -> {'PASS' if ok else 'FAIL'}: {det}")
        check("one-way fault judged on worst direction", not ok,
              "a 2% fault in one direction must fail even though the average "
              "of the two directions is only 1%")
        check("worst-direction reported",
              r.get("loss_pct_worst", 0) > r["loss_pct"] * 1.5,
              f"worst {r.get('loss_pct_worst', 0):.4f}% vs average "
              f"{r['loss_pct']:.4f}%")
    finally:
        RawSender.send = orig
        try:
            s.close()
        except Exception:
            pass

    print("\n" + "=" * 70)
    if fails:
        print("VERIFICATION FAILED:", fails)
        return 1
    print("VERIFICATION PASSED - reported numbers match the damage actually done")
    return 0


def _reexec_with_working_python() -> None:
    """
    Hand over to an interpreter that actually has scapy.

    Double-clicking a .py file on Windows runs it through py.exe, which selects
    the NEWEST installed Python. That is often a Microsoft Store build with no
    packages in it, so the tool would report "scapy is not installed" even
    though a perfectly good interpreter with scapy sits right there. Instead of
    blaming the user, find that interpreter and re-launch ourselves under it.
    """
    if SCAPY_OK or os.name != "nt" or os.environ.get("ETHSW_REEXEC"):
        return
    import glob
    me = os.path.abspath(sys.executable).lower()
    cands = (sorted(glob.glob(r"C:\Program Files\Python3*\python.exe"), reverse=True)
             + sorted(glob.glob(r"C:\Program Files (x86)\Python3*\python.exe"), reverse=True)
             + sorted(glob.glob(r"C:\Python3*\python.exe"), reverse=True))
    script = os.path.abspath(__file__)
    for c in cands:
        if os.path.abspath(c).lower() == me or not os.path.exists(c):
            continue
        try:
            r = subprocess.run([c, "-c", "import scapy"], capture_output=True,
                               timeout=30, creationflags=0x08000000)
        except Exception:
            continue
        if r.returncode != 0:
            continue
        try:
            env = dict(os.environ)
            env["ETHSW_REEXEC"] = "1"
            subprocess.Popen([c, script] + sys.argv[1:], env=env,
                             cwd=os.path.dirname(script) or None)
            sys.exit(0)
        except Exception:
            continue


def main() -> None:
    _reexec_with_working_python()
    if "--selftest" in sys.argv:
        selftest()
        return
    if "--verify" in sys.argv:
        i = sys.argv.index("--verify")
        rest = [a for a in sys.argv[i + 1:] if not a.startswith("-")]
        if len(rest) < 2:
            print("usage: eth_switch_tester.py --verify <ifaceA> <ifaceB>")
            print("       (interface names as shown by --list)")
            sys.exit(2)
        sys.exit(verify_honesty(rest[0], rest[1]))
    if "--list" in sys.argv:
        if get_windows_if_list:
            for d in get_windows_if_list():
                if d.get("mac"):
                    print(f"{d.get('name')}   |   {d.get('description')}   |   {d.get('mac')}")
        return
    if not TK_OK:
        print("Tkinter is not available in this Python installation.\n"
              f"  {TK_ERR}\n"
              "On Windows, reinstall Python from python.org with the\n"
              "'tcl/tk and IDLE' option ticked. On Linux: apt install python3-tk")
        sys.exit(1)
    app = App()
    if not check_admin():
        app.log("WARNING: not running as Administrator. Raw frame injection will "
                "most likely fail. Close this and re-launch from an elevated "
                "command prompt.", BAD)
    app.mainloop()


def selftest() -> None:
    """Offline validation of the frame codec and statistics engine."""
    print("frame codec ...", end=" ")
    for size in (64, 65, 128, 512, 1518):
        b = build_template("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", size, 3)
        assert len(b) == size - 4, (len(b), size)
        stamp(b, 12345, 987654321)
        p = parse(bytes(b))
        assert p == (3, 12345, 987654321), p
    assert parse(b"\x00" * 60) is None
    assert parse(b"") is None
    print("OK")

    print("loss accounting ...", end=" ")
    st = StreamStats("t")
    base = now_ns()
    sent = 1000
    st.on_tx(sent, sent * 60)
    dropped = {5, 6, 7, 500, 999}
    for i in range(sent):
        if i in dropped:
            continue
        st.on_rx(i, base, base + 25_000, 64)
    s = st.snapshot()
    assert s["lost"] == len(dropped), s
    assert abs(s["loss_pct"] - 0.5) < 1e-9, s
    assert abs(s["lat_avg_us"] - 25.0) < 0.01, s
    print(f"OK  (lost={s['lost']}, loss={s['loss_pct']}%, avg={s['lat_avg_us']}us)")

    print("reorder/dup ...", end=" ")
    st2 = StreamStats("r")
    for i in (0, 1, 3, 2, 4, 4, 5):
        st2.on_rx(i, base, base + 1000, 64)
    s2 = st2.snapshot()
    assert s2["reorder"] == 1, s2
    assert s2["dup"] == 1, s2
    print("OK")

    print("rate math ...", end=" ")
    assert abs(line_rate_pps(64, 1000) - 1_488_095.238) < 1.0
    assert abs(line_rate_pps(1518, 1000) - 81_274.1) < 1.0
    assert abs(line_rate_pps(64, 100) - 148_809.5) < 1.0
    print("OK")

    print("report render ...", end=" ")
    cfg = Config(iface_a="A", iface_b="B", mac_a="aa:aa:aa:aa:aa:aa",
                 mac_b="bb:bb:bb:bb:bb:bb")
    rs = [TestResult("5. Frame-size sweep", True, "ok", {},
                     [{"frame_size": s, "tx_mbps": s / 2, "rx_mbps": s / 2 - 1,
                       "lat_avg_us": 100 + s / 10, "lat_max_us": 200 + s / 5,
                       "loss_pct": 0.0, "result": "PASS"} for s in (64, 512, 1518)]),
          TestResult("7. Burst / buffer depth", False, "loss at 10000", {},
                     [{"burst_frames": n, "loss_pct": 0 if n < 10000 else 3.2,
                       "result": "PASS" if n < 10000 else "FAIL"}
                      for n in (100, 1000, 10000)])]
    h = build_report(cfg, rs, "selftest")
    assert "<svg" in h and "Frame-size sweep" in h and len(h) > 3000
    import tempfile
    p = os.path.join(tempfile.gettempdir(), "selftest_report.html")
    open(p, "w", encoding="utf-8").write(h)
    write_csv(p.replace(".html", ".csv"), rs)
    print(f"OK -> {p}")
    print("\nALL SELF-TESTS PASSED")


if __name__ == "__main__":
    main()
