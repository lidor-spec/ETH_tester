# ETH Switch Tester — project context

Layer-2 Ethernet switch validation tool with a live Tkinter GUI. Single file,
~3600 lines, no dependencies beyond `scapy` + Npcap.

## What is being tested

**DUT:** a custom board built around a **Microchip KSZ8895** — 5-port 10/100
managed Ethernet switch. In this hardware revision **port 4 is 100BASE-FX
fiber**; the rest are copper. Datasheet is in `~/Downloads`
(`KSZ8895MQX-...-DS00002246B.pdf`). The board's Altium project is
`PCB-0007_ETH_SWTCH`.

**Test rig:** Windows 11 PC, two USB-Ethernet adapters into two copper ports.
- `Ethernet 3` = Realtek USB GbE #2, MAC `0c:37:96:d3:b4:a6`
- `Ethernet 4` = Realtek USB GbE #3, MAC `00:e0:4c:68:00:58`
- Both negotiate **100 Mbps full duplex** with the DUT. Set `LINK Mbps = 100`.

The fiber port cannot be reached from the PC directly. To cover it: copper →
fiber → media converter → back into the second copper adapter, so a single
A→B run crosses the fabric twice and exercises the FX SERDES.

## Environment (already set up, do not re-install)

- Python **3.13.15** at `C:\Program Files\Python313\python.exe` — **use this
  one**. A Microsoft Store Python 3.14 also exists and has **no scapy**;
  `py.exe` (the `.py` file association) picks it and breaks the tool. The
  script now detects this and re-execs itself under a Python that has scapy.
- scapy **2.7.0**, Npcap **1.88** installed in WinPcap-compatible mode.
- Raw frame injection **requires Administrator**. `START-TESTER.bat`
  self-elevates.

## Run / verify

```powershell
# GUI (self-elevates)
.\START-TESTER.bat

# offline unit tests: frame codec, loss accounting, reorder/dup, rate math, report
& 'C:\Program Files\Python313\python.exe' eth_switch_tester.py --selftest

# list interfaces with their scapy names
& 'C:\Program Files\Python313\python.exe' eth_switch_tester.py --list

# HONESTY CHECK — destroys a known number of frames before they hit the wire
# and asserts the report matches. Run this after touching loss accounting.
& 'C:\Program Files\Python313\python.exe' eth_switch_tester.py --verify "Ethernet 3" "Ethernet 4"
```

`--verify` is the regression gate for the measurement path. It checks uniform
loss, a mid-run burst, tail loss (no trailing sequence gap), and a one-way
fault in bidirectional mode. Expected: exact matches (50/50, 300/300, 150/150).

## Architecture (single file, section numbers are comments in the source)

| Section | Contents |
|---|---|
| 1 | constants, `now_ns()` high-res epoch clock, rate math |
| 2 | `build_template` / `build_vlan_template` / `stamp` / `parse` / `payload_bit_errors` / `BitTap` |
| 3 | `StreamStats` — loss, latency, jitter, percentiles |
| 4 | `RawSender`, `Receiver` (pcap fast path + scapy fallback), `Transmitter` |
| 4b | `ReflectSession` — single-adapter ICMP reflection mode |
| 5 | `Config`, `Session.run_stream` (the one measurement primitive), `TestSuite` (11 tests) |
| 6 | self-contained HTML report with hand-built inline SVG charts |
| 7 | GUI: `LineChart`, `BitTimingView`, `App` |
| 8 | entry point, `--selftest`, `--verify`, `--list` |

**Measurement principle:** raw Ethernet frames, EtherType `0x88B5`, each
carrying `magic | ver | stream_id | flags | rsv | seq(4) | tx_ns(8)` plus a
deterministic filler `(k*7+0x5A)&0xFF`. Loss is counted from sequence gaps, not
inferred. RX timestamps come from the Npcap kernel capture clock; TX timestamps
from `now_ns()` (wall-clock base + monotonic delta, because Windows
`time.time()` has ~15 ms granularity).

## HARD INVARIANTS — do not regress these

These each cost a real debugging cycle. There are automated checks for most.

1. **Never fail the DUT for a limitation of the measuring PC.**
   `host_capture_drops` (from `pcap_stats()`) is subtracted before judging;
   the switch is scored on `dut_loss_pct`. Host-side drops are reported as
   *reduced confidence*, never as a fault.

2. **The live view must count only CONFIRMED sequence gaps**
   (`lost_confirmed`, gaps below `highest_seq`). Comparing against the TX
   counter mid-run counts frames still *in flight* as lost and manufactures
   phantom spikes. The TX-counter comparison (`lost`) is valid **only** after
   the drain wait, in `_collect`.
   - This bit twice: once in the live chart, once in `_timeline` →
     `_worst_window` → the burst detector, where it produced FAILs on runs
     with **zero** frames lost.

3. **The transmit loop must never busy-spin.** TX and capture share one GIL; a
   spinning transmitter starves the receiver and fabricates 60–90% loss. Use
   `time.sleep(0)` to yield when the wait is under ~600 µs.

4. **Judge on the worst direction, not the average.** A 2% fault on A→B with a
   clean B→A averages to 1% and can slip under the threshold.

5. **`settle()` before every measurement** — reset, wait 0.3 s, reset again.
   Stragglers from the previous run carry high sequence numbers that inflate
   `expected` and fabricate enormous loss.

6. **Rates use the transmit window**, not wall-clock of the whole call (which
   includes the 0.6 s drain) — otherwise every rate reads ~17% low.

7. **VLAN shifts every field by 4 bytes.** `stamp()`, `parse()`, `payload_ok()`
   and the BPF filter all check for `0x8100` first. Writing at untagged
   offsets silently corrupts tagged frames.

8. **Never offer Npcap pseudo-interfaces.** Entries whose description ends in
   `-\d{4}$` (e.g. `...-Npcap Packet Driver (NPCAP)-0000`) cannot be opened
   and produce "Interface not found". Also dedupe by MAC — one physical NIC
   appears once per protocol binding.

9. **Distinguish "adapter unplugged" from "driver record exists".** scapy
   enumerates from the registry and lists removed adapters. Cross-check
   against `Get-NetAdapter`; absence there means not physically present.

10. **Kernel BPF filter is mandatory for throughput.** Without it every frame
    is dissected in Python and the receiver drops frames above ~20–40 kpps.
    Also: a capture handle on the *transmitting* adapter sees our own outbound
    frames, so the filter narrows to the expected `stream_id` (byte 19,
    or 23 when tagged).

11. **Latency percentiles use reservoir sampling.** A plain cap fills early in
    long runs and biases p50/p95/p99 to the first seconds.

## Known limits (by design, not bugs)

- A Windows PC with USB-Ethernet adapters **cannot generate small-frame line
  rate**. Rows flagged `host_limited=yes` mean the offered load was lower than
  requested; the loss figure is still valid. At 1024 B+ it does reach 100 Mbps.
- Latency includes both USB adapters and the host capture path. Run
  **Calibrate (direct cable)** to measure and subtract that baseline; the
  switch's own contribution is the delta.
- `Bits / Timing` is **digital only** — no analogue sampling, so it is not an
  eye diagram. Capture snaplen is 128 B, so ~86 payload bytes per frame are
  compared. Raising snaplen costs receive throughput.
- Reflection mode cannot saturate a link: routers rate-limit ICMP. It measures
  latency, jitter and moderate-rate loss.

## Test suite (11)

1 link/bidirectional · 2 unknown-unicast flooding · 3 broadcast · 4 MAC
learning + 1000-MAC CAM fill · 5 frame-size sweep · 6 load ramp · 7
burst/buffer depth · 8 bidirectional soak · 9 VLAN tagged (VID 1/100/4094,
PCP 0/5/7) · 10 frame-size boundaries (64/65/127/512/1518 must forward;
1522/2048/9018 informational) · 11 IMIX (7×64 + 4×576 + 1×1518)

## Last hardware result (2026-08-17, uncalibrated)

Clean bring-up. ~400,000 frames, **0 lost, 0 reorder, 0 dup**, 0 bit errors
over 69,936 bits compared. Bidirectional soak 117,529 + 117,162 frames at
33.5 Mbps each way. 50,000-frame burst absorbed. Jumbo disabled (nothing above
1518 B forwards, including 1522 B — relevant if you ever need full-MTU tagged
frames). Latency avg 236 µs / p99 489 µs / jitter 34–38 µs **uncalibrated**,
so mostly USB adapters rather than the switch.

Tests 5 and 6 reported FAIL in that run; both were the phantom-burst bug in
invariant 2, since fixed. Re-run should be 11/11.

## Dev notes

- `dev_tests/` holds the harnesses used during development. They target Linux
  `veth` pairs, so they run on a Linux box, not on this Windows host:
  `integration_test.py` (full suite over veth), `truth_test.py` (deliberate
  loss injection), `reflect_test.py` (ICMP reflection with a responder).
  On Windows, `--verify` covers the same ground against real adapters.
- The GUI is pure Tkinter; charts are hand-drawn on a `Canvas` (no matplotlib).
  Worker threads never touch widgets — they push onto a `queue.Queue` drained
  by `_pump()` via `after()`.
- Verify GUI changes by **looking at a screenshot**, not by reading the code.
  Several layout bugs (clipped labels, a chart pushed off-screen, phase labels
  drifting) were only visible in a render.
