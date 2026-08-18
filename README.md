# ETH Switch Tester

Layer-2 Ethernet switch validation tool with a live GUI. Built to bring up a
custom board based on the **Microchip KSZ8895** (5-port 10/100 managed switch,
port 4 = 100BASE-FX fiber in this revision).

It does **not** use TCP/IP. It injects raw Ethernet frames with a private
EtherType (`0x88B5`), each carrying a sequence number and a transmit timestamp,
so packet loss is *counted* from sequence gaps rather than inferred, and latency
comes from the Npcap kernel capture clock.

![dashboard](docs/screenshot_dashboard.png)

## Why raw frames

With TCP you measure the stack, not the switch — a dropped frame is
indistinguishable from a congestion-control decision. With raw frames every
frame is a controlled measurement:

- loss counted exactly, from sequence gaps
- one-way latency, jitter, reordering and duplication detected
- payload compared bit-for-bit against a known pattern
- **host-side capture drops subtracted before the switch is judged**

That last point matters more than it sounds. Frames discarded by the measuring
PC's own capture driver must never be reported as switch faults. See the
invariants in [CLAUDE.md](CLAUDE.md).

## Requirements

- Windows 10/11, **Python 3.11+** (3.13 recommended)
- [Npcap](https://npcap.com) installed in WinPcap API-compatible mode
- `pip install scapy`
- **two** USB-Ethernet adapters, one per switch port
- Administrator (raw frame injection)

## Run

```powershell
.\START-TESTER.bat          # GUI, self-elevates
.\VERIFY-HONESTY.bat        # prove the measurements are not flattering reality

python eth_switch_tester.py --selftest                       # offline unit tests
python eth_switch_tester.py --list                           # interface names
python eth_switch_tester.py --verify "Ethernet 3" "Ethernet 4"
```

Two adapters are required: a switch never sends a frame back out the port it
arrived on, so one adapter can prove the link came up but never that the fabric
forwards. A single-adapter **reflection mode** (ICMP echo off a device on an
uplinked port) is implemented for latency and moderate-rate loss.

## Test suite

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

## Is the tool telling the truth?

`--verify` monkey-patches the sender to destroy a **known** number of frames
before they reach the wire, then asserts the report matches: uniform loss, a
mid-run burst, tail loss (which leaves no trailing sequence gap), and a one-way
fault in bidirectional mode. Expected output is exact — 50/50, 300/300, 150/150.

Run it whenever you doubt a result, and after any change to the measurement path.

## Output

Self-contained HTML report with inline SVG charts, plus CSV and JSON. No CDN,
no JavaScript — opens anywhere.

## Documentation

[CLAUDE.md](CLAUDE.md) is the engineering reference: architecture by section,
the hard invariants and the failure each one caused, and the known limits that
are by design rather than bugs.
