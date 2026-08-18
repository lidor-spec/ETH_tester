# ETH_USB_tester — project context

Layer-2 Ethernet switch validation tool with a live Tkinter GUI. Single file,
~4200 lines, no dependencies beyond `scapy` + Npcap — plus **OpenCV, which is
optional and used only by the Camera Passthrough tab** (see below).

## What is being tested

**Two DUTs, two benches.** The app opens on a landing screen: `Test ETH` or `Test USB`.
See "Test USB" below for the hub bench; everything up to it is the Ethernet bench.

**ETH DUT:** a custom board built around a **Microchip KSZ8895** — 5-port 10/100
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
- **OpenCV `cv2` 5.0.0 + numpy 2.5.2** — installed system-wide in
  `C:\Program Files\Python313\Lib\site-packages` (deliberately NOT the per-user
  dir, so the self-elevated launcher always finds it).

### The OpenCV exception — DO NOT "fix" this

`cv2` is the **one approved exception** to the "scapy + Npcap only" rule. It
exists solely for the Camera Passthrough tab. It is a **soft** dependency:

- imported on demand by `load_cv2()` (section 4c), never at module import, so
  `--selftest`, `--verify`, `--list` and the 11 tests never pay for it;
- if it is missing, the camera tab shows
  `OpenCV not installed - run: pip install opencv-python`, disables its Start
  button, and **everything else behaves exactly as before**.

A future agent must not harden this into a top-level `import cv2`, and must not
"clean up" the dependency by deleting the feature. There is also deliberately
**no Pillow**: received frames reach Tk as raw P6 PPM bytes via
`bgr_to_ppm()`, because `tk.PhotoImage(data=...)` reads PPM natively on
Tk 8.6. One extra dependency is an exception; two would be worse.

Reinstall command if it ever goes missing:
`& 'C:\Program Files\Python313\python.exe' -m pip install opencv-python`

## Run / verify

```powershell
# GUI (self-elevates)
.\START-TESTER.bat

# offline unit tests: frame codec, loss accounting, reorder/dup, rate math,
# camera chunk codec + incomplete-frame handling + channel isolation, report
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
| 4c | Camera passthrough: `build_video_chunks` / `parse_video_chunk` / `VideoAssembler` / `load_cv2` / `jpeg_to_bgr` / `bgr_to_ppm` / `CameraLink` |
| 4d | **Test USB**: `parse_rawinput_mouse` / `rawinput_path_to_instance_id` / `enum_raw_mice` / `pnp_*` helpers / `find_hub_ancestor` / `IntervalStats` / `UsbHidLink` |
| 5 | `Config`, `Session.run_stream` (the one measurement primitive), `TestSuite` (11 tests) |
| 6 | self-contained HTML report with hand-built inline SVG charts |
| 7 | GUI: `LineChart`, `BitTimingView`, `App` — landing screen → **Test ETH** (tabs: Live Dashboard, Results, Bits/Timing, Camera Passthrough, Frame Console, Log) or **Test USB** |
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
    - `Receiver` takes an optional `snaplen` (default `SNAPLEN` = 128). Only the
      camera channel raises it (`VID_SNAPLEN` = 1600, it needs whole frames).
      **Do not raise the default** — it costs receive throughput.
    - When `bpf_override` is given (reflection, camera) there is deliberately
      **no fallback to the 0x88B5 filter**. Falling back used to make those
      receivers silently deaf to the traffic they exist for; they now degrade to
      unfiltered capture + Python-side filtering instead.

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

## Camera Passthrough (visual proof, section 4c + GUI tab)

Everything else in this tool produces numbers; this produces a **picture**. The
PC webcam is JPEG-encoded, chopped into raw Ethernet frames, injected on adapter
A, forwarded by the DUT, captured on adapter B, reassembled and drawn next to
the local preview. Two panes showing the same face is direct, non-numeric
evidence that real payload crosses the fabric.

Cable **copper → fiber → media converter → copper** and the video crosses the
fabric twice and through the 100BASE-FX SERDES — the easiest way to demo the
fiber port, which the PC cannot reach directly.

**Wire format — EtherType `0x88B6`** ("local experimental 2"), deliberately a
*different* EtherType from the 0x88B5 measurement stream so the two can never
alias (there is a selftest asserting each parser rejects the other's frames):

```
Ethernet 14 B:  dst MAC(6) | src MAC(6) | 0x88B6(2)
Chunk hdr 22 B (VID_HDR_FMT "!4sBBHHHHQ"):
  14 magic(4)="SWCV" | 18 ver(1) | 19 flags(1) | 20 frame_id(2)
  22 chunk_idx(2) | 24 chunk_count(2) | 26 payload_len(2) | 28 tx_ns(8)
JPEG slice: payload_len bytes, max VID_MAX_CHUNK = 1518-4-14-22 = 1478
```

- `payload_len` is required because a short final chunk is zero-padded to the
  64 B Ethernet minimum.
- `tx_ns` is identical in every chunk of one video frame, so RX can price the
  whole frame from the last chunk's arrival.
- dst is the **receiving adapter's real MAC** (unicast), so a picture arriving
  also means the switch learned that MAC and forwarded rather than flooded.
- Untagged on purpose — this channel sidesteps invariant 7 entirely.

**The visual twin of invariant 2.** `VideoAssembler` never shows a partial
image: a frame is displayed only when *every* chunk is present, so a torn or
grey-blocked picture can never appear and be misread as switch corruption. And
it never writes a frame off while its chunks could still be in flight — only
once a **newer** frame completes, or the 4-frame pending window overflows.
Judging in-flight frames is exactly the bug invariant 2 describes.

**Known limits (by design):**

- **Qualitative only.** Offered load is ~0.5–0.7 Mbps at the 320x240 @ 12 fps
  q60 default — nothing like a throughput test. The frames-intact counter
  exists to explain a bad picture, not to grade the switch. The 11-test suite
  remains the measurement of record.
- **The latency on this tab is not the switch's latency.** It includes camera
  exposure, JPEG encode, USB and the host capture path, and is dominated by the
  camera. Not comparable to the 0x88B5 figures; use Calibrate for those.
- Webcams often ignore `CAP_PROP_FRAME_WIDTH/HEIGHT` (this one hands back
  640x480 regardless), so `CameraLink._tx_loop` re-scales with `cv2.resize` to
  keep the bitrate predictable.
- The webcam is a shared resource: Teams / Camera / a browser holding it makes
  `VideoCapture` fail. The error message says so.
- One direction at a time (`SEND FROM: A -> B` / `B -> A`). No simultaneous
  bidirectional video.
- The camera and the test suite are **mutually exclusive** — both own the same
  two adapters, and video sharing the link would distort a measurement. Each
  refuses to start while the other runs.
- While the camera is active `_pump()` ticks at 40 ms instead of 120 ms, so the
  video is not capped at ~8 fps. JPEG decode → PPM → `PhotoImage` happens
  **inside `_pump()` on the Tk thread**; `CameraLink` only ever pushes bytes
  onto the queue.

## Test USB — HID mouse through a hub (section 4d + its own view)

The app now opens on a **landing screen**: `Test ETH` (everything above) or
`Test USB`. They test different hardware with different mechanics, so they get
separate front doors rather than one more notebook tab.

**Why it is built around a mouse.** The obvious idea — loop a hub's upstream and
downstream ports into two of the PC's own USB ports, mirroring the two-NIC
Ethernet loop — **cannot work**. A passive hub has one meaningful upstream link
and USB has no host-to-host mode, so that wiring just enumerates a second
"Generic USB Hub": no bridge, no traffic. That is USB, not a missing driver. So
the hub is tested the way it is used: with a real device on a downstream port.

Two mechanisms, **zero new dependencies** (`ctypes` + `subprocess` are stdlib and
already in the file, so unlike OpenCV this needs no exception):

1. **Win32 Raw Input** — the OS-sanctioned way to read *per-device* mouse
   reports. Windows deliberately restricts opening a mouse as a generic HID
   handle from user mode, so hidapi is the wrong tool. `RIDEV_INPUTSINK` on a
   message-only window (`HWND_MESSAGE`) observes input without focus and
   **without stealing or blocking it** — the mouse keeps working everywhere else.
   One dedicated thread owns the window, the registration and the
   `GetMessageW` loop (Win32 windows are thread-affine); `stop()` posts `WM_QUIT`
   to that thread id, and the thread itself unregisters, destroys and returns.
2. **`Get-PnpDevice` polling** (~1.5 s) of the mouse and its hub ancestor,
   diffed between polls. Found by walking `DEVPKEY_Device_Parent` up the tree in
   **one** PowerShell call. `find_hub_ancestor` skips "USB Root Hub" — a device
   plugged straight into the PC still has a root-hub ancestor, and that is the
   host controller, not the DUT.

### Traps that cost real debugging time here

- **`RAWMOUSE` has 2 bytes of padding after `usFlags`** (the following union is
  4-byte aligned). Declaring the `USHORT`s back-to-back reads `usButtonFlags`
  two bytes early and mis-reports every click. The selftest hand-packs a buffer
  from the documented offsets to catch exactly this.
- **Declare `argtypes`/`restype` for every pointer-sized Win32 argument.** An
  undeclared 64-bit `HINSTANCE` raises `int too long to convert`, and an
  undeclared `HWND` return is truncated to 32 bits so every later call silently
  fails. This bit `CreateWindowExW` on the first live run.
- **Keep the `WINFUNCTYPE` WNDPROC alive on `self`.** If Python GCs it, Windows
  calls freed memory and the process dies with no traceback.
- **VID/PID appear in two forms**: USB `VID_046D`, Bluetooth
  `_Dev_VID&02046d_PID&b042_` (6 digits, last 4 are the ID). `_id_field` handles
  both; matching only the USB form labels every BT mouse "unknown VID/PID".
- **A mouse only reports while it is moving.** The multi-second silence when the
  user lets go is not a dropout. `IntervalStats` excludes intervals above
  `IDLE_MS` (250 ms) from avg/jitter/percentiles/max-gap and counts them as
  `pauses` — same principle as the Ethernet invariants: never manufacture a
  fault the DUT did not commit. Reports/s is therefore quoted **while moving**
  (`1000/avg`), not over wall-clock, which would just measure how much the user
  fidgeted.

### The verdict line (numbers are not a conclusion)

`usb_verdict()` (section 4d, pure and covered by `--selftest`) reduces the two
stored phase snapshots to **one** coloured line above the `BASELINE vs THROUGH
HUB` panel, in the same OK / WARN / BAD language the ETH Results tab uses for
PASS / FAIL. Evidence in order of strength:

1. **A fault outranks every timing number** — `ISSUES DETECTED - N
   disconnect/reset event(s)` in red even if the intervals looked perfect. A hub
   that drops the device is broken. Live faults count too, so a disconnect shows
   the moment `_on_usbstats` reports it rather than waiting for Stop.
2. **Both phases stored** → PASS (green) or WARN (amber) with the actual deltas
   quoted. Thresholds `USB_VERDICT_AVG_MS` / `USB_VERDICT_JIT_MS` = 1.0 ms,
   `USB_VERDICT_REL` = 25%: a delta passes if it is small in **absolute** OR in
   **relative** terms, whichever is kinder. Deliberately generous — both phases
   are hand-driven with a noisy source, and a tighter bar fails good hubs.
3. **One phase only** → its report count and fault total, so there is always a
   conclusion once a capture is stored, never a blank panel.

The timing half of the verdict is computed **only from stored, settled
captures**, so it does not flicker with the KPI row. The comparison panel below
it no longer draws its own conclusion (two sentences judging the same numbers on
different thresholds could disagree), and it now prints the **deltas first**:
the panel shares its height with the reserved chart strip, so its tail is off
screen, and the deltas are the part worth reading.

### Trend charts (the KPI row is not enough)

The KPI row is an instantaneous readout and it **flickers too much to conclude
anything from**, so the view also carries four `LineChart`s — report rate,
inter-report interval (avg + p95), jitter, and cumulative reliability events —
fed from `_on_usbstats` at the `TICK_S` cadence. Same KPI-row-plus-charts
relationship the ETH dashboard already has.

- They are **deliberately never cleared between runs.** Phase changes are marked
  with `LineChart`'s phase divider, so Baseline and Through Hub sit on **one**
  timeline and can be compared by eye — the chart twin of the text
  `BASELINE vs THROUGH HUB` panel.
- Before the first in-motion interval, avg/jitter/p95 are pushed as a **gap**,
  not 0: a dive to the axis reads as a fault that never happened. The events
  chart is never idled — a disconnect is real while the mouse sits still.
- maxlen stays at the 240 default (~72 s). A longer window was tried and
  rejected: it squeezes a normal capture into a sliver of the plot width.
- The chart strip is packed `side="bottom"` with a reserved height and
  `pack_propagate(False)`. Packed after the panels above it, a filled comparison
  readout grew row 0 and pushed the last chart off the bottom of the window.

### Known limits

- **Not a throughput test.** A mouse offers a few kB/s; this can never load a
  hub. It answers "does the hub carry a real device cleanly and stay connected",
  which is what a bad bench hub actually fails.
- **PnP status transitions only.** Precise USB error/reset codes are not
  reliably obtainable from user mode without a kernel driver, and this code does
  not pretend to have them.
- **A wireless mouse adds an RF hop** (mouse → receiver) with its own jitter on
  top of the USB link. Use a wired mouse for the cleanest hub comparison, or
  keep the same receiver in both phases so the RF hop cancels out.
- Phase tagging (`Baseline - direct to PC` / `Through Hub`) is set by the user;
  the tool cross-checks it by reporting whether an external hub was actually
  found above the device, and warns when they disagree.
- Only one of {ETH suite, camera, USB} runs at a time.

### Live reference numbers (2026-08-17, this bench)

Bluetooth mouse (`VID&02046D_PID&B042`), 25 s, not behind an external hub:
**3011 reports, avg interval 8.30 ms (~120 Hz), jitter 3.03 ms, p95 14.92 ms,
longest in-motion gap 203 ms, 0 PnP faults.** The Logitech Unifying mouse on the
`Generic USB Hub` (`VID_0424&PID_2514`) enumerated and polled OK but produced no
reports while idle/powered off — a through-hub capture still needs that mouse
actually moving.

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
- `_build()` no longer builds onto the Tk root. It creates three sibling frames
  — `frame_landing` / `frame_eth` / `frame_usb` — swapped by
  `_show_landing()` / `_show_eth()` / `_show_usb()` with `pack_forget()` +
  `pack(fill="both", expand=True)`. The old body lives in `_build_eth()`
  unchanged apart from its parent, so the ETH tabs look exactly as before.
- The GUI is pure Tkinter; charts are hand-drawn on a `Canvas` (no matplotlib).
  Worker threads never touch widgets — they push onto a `queue.Queue` drained
  by `_pump()` via `after()`.
- Verify GUI changes by **looking at a screenshot**, not by reading the code.
  Several layout bugs (clipped labels, a chart pushed off-screen, phase labels
  drifting) were only visible in a render.
