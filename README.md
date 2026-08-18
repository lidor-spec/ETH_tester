# ETH_USB_tester

Hardware bring-up test bench for a custom board carrying a **Microchip KSZ8895**
5-port 10/100 Ethernet switch (port 4 = 100BASE-FX fiber in this revision) and a
**USB2514-class hub**. Two separate benches behind one landing screen:

- **Test ETH** — Layer-2 switch validation over raw Ethernet frames, plus a live
  camera passthrough for visual proof
- **Test USB** — HID device timing through a hub, baseline vs through-hub

Single Python file, live Tkinter GUI, self-contained HTML reports.

![dashboard](docs/screenshot_dashboard.png)

## Test ETH — why raw frames

It does **not** use TCP/IP. It injects raw Ethernet frames with a private
EtherType (`0x88B5`), each carrying a sequence number and a transmit timestamp.
With TCP you measure the stack, not the switch — a dropped frame is
indistinguishable from a congestion-control decision. With raw frames every
frame is a controlled measurement:

- loss counted exactly, from sequence gaps
- one-way latency, jitter, reordering and duplication detected
- payload compared bit-for-bit against a known pattern
- **host-side capture drops subtracted before the switch is judged**

That last point matters more than it sounds. Frames discarded by the measuring
PC's own capture driver must never be reported as switch faults.

### The 11 tests

| # | Test | What it proves |
|---|---|---|
| 1 | Link / bidirectional | frames forward both ways |
| 2 | Unknown-unicast flooding | floods to an unlearned MAC, as L2 requires |
| 3 | Broadcast forwarding | replication, incl. 10k pps |
| 4 | MAC learning / CAM | learning, plus 1000 unique source MACs |
| 5 | Frame-size sweep | 64 → 1518 B, throughput and latency vs size |
| 6 | Load ramp | loss onset as offered load rises |
| 7 | Burst / buffer depth | back-to-back bursts locate output buffer limits |
| 8 | Bidirectional soak | full duplex, both directions at once |
| 9 | VLAN tagged | 802.1Q, VID 1/100/4094, PCP 0/5/7 |
| 10 | Frame-size boundaries | 64/65/127/512/1518 must forward; jumbo detected |
| 11 | IMIX | 7×64 + 4×576 + 1×1518, stresses buffer allocation |

Two adapters are required: a switch never sends a frame back out the port it
arrived on, so one adapter can prove the link came up but never that the fabric
forwards. A single-adapter **reflection mode** (ICMP echo off a device on an
uplinked port) covers latency and moderate-rate loss.

### Camera passthrough

Everything else produces numbers; this produces a **picture**. The webcam is
JPEG-encoded, chopped into raw frames on a *separate* EtherType (`0x88B6`, so it
can never alias the measurement stream), forwarded by the DUT, reassembled and
drawn beside the local preview. Two panes showing the same face is direct,
non-numeric evidence that real payload crosses the fabric — and routed copper →
fiber → media converter → copper, it is the easiest way to demonstrate the fiber
port the PC cannot reach directly.

A frame is displayed only when *every* chunk has arrived, so a torn image can
never be misread as switch corruption. Qualitative by design — ~0.5–0.7 Mbps
offered load. The 11-test suite remains the measurement of record.

### Bits / Timing

Digital, not an eye diagram: a per-frame transit diagram (each row aligned on
its own transmit instant, so bar length *is* that frame's latency), sent vs
received bit streams as NRZ waveforms with an XOR row, and cumulative bit errors
per bit position — which catches a stuck data line that random spot-checks miss.

## Test USB — HID timing through a hub

The obvious idea — loop a hub's upstream and downstream ports into two PC ports,
mirroring the two-NIC Ethernet loop — **cannot work**. A passive hub has one
meaningful upstream link and USB has no host-to-host mode; that wiring just
enumerates a second hub. So the hub is tested the way it is used: with a real
device on a downstream port.

Two mechanisms, zero new dependencies:

- **Win32 Raw Input** — the OS-sanctioned way to read *per-device* mouse
  reports. `RIDEV_INPUTSINK` on a message-only window observes input without
  focus and without stealing it, so the mouse keeps working everywhere else.
- **`Get-PnpDevice` polling** of the mouse and its hub ancestor, diffed between
  polls, to catch disconnect and reset events.

Capture a **baseline** with the device direct, then **through the hub**, and the
verdict compares them: report rate, inter-report interval, jitter, p95, longest
in-motion gap, and PnP fault count. A disconnect outranks every timing number —
a hub that drops the device is broken regardless of how good the intervals look.
Four trend charts share one timeline across both phases, so the comparison is
visible by eye and not just in text.

Not a throughput test: a mouse offers a few kB/s and can never load a hub. It
answers "does this hub carry a real device reliably", not "how fast is it".

## Requirements

- Windows 10/11, **Python 3.11+** (3.13 recommended)
- [Npcap](https://npcap.com) in WinPcap API-compatible mode
- `pip install scapy` — and `opencv-python` for the camera tab only
- **two** USB-Ethernet adapters for Test ETH; a USB mouse for Test USB
- Administrator (raw frame injection)

## Run

```powershell
.\START-TESTER.bat          # GUI, self-elevates
.\VERIFY-HONESTY.bat        # prove the measurements are not flattering reality

python eth_switch_tester.py --selftest    # offline unit tests
python eth_switch_tester.py --list        # interface names
python eth_switch_tester.py --verify "Ethernet 3" "Ethernet 4"
```

## Is the tool telling the truth?

`--verify` destroys a **known** number of frames before they reach the wire, then
asserts the report matches: uniform loss, a mid-run burst, tail loss (which
leaves no trailing sequence gap), and a one-way fault in bidirectional mode.
Expected output is exact — 50/50, 300/300, 150/150.

This exists because the tool twice reported faults that were not there: frames
still in flight counted as lost, and the measuring PC's own capture drops
charged to the switch. `--selftest` additionally covers the frame codec, loss
accounting, the camera chunk codec and channel isolation, and the USB verdict
logic. Run both after any change to a measurement path.

## Output

Self-contained HTML report with inline SVG charts, plus CSV and JSON. No CDN, no
JavaScript — opens anywhere.

## Documentation

[CLAUDE.md](CLAUDE.md) is the engineering reference: architecture by section,
the hard invariants with the failure each one caused, the traps that cost real
debugging time, and the limits that are by design rather than bugs.
