#!/usr/bin/env python3
"""Patch eth_switch_tester.py: never run a suite against a dead RX path.

Two defects:
  1. run_calibrate() returns silently when nothing arrives, and _wrap then
     reports "<label> complete". The failure only appears as one line in the
     Log tab, latency_offset_us stays 0 with nothing flagging it, and no
     FAILED result is emitted.
  2. Nothing verifies a frame can make the trip before committing to a
     multi-minute suite, so a board whose fabric is not forwarding produces
     eleven NO FRAMES RECEIVED failures instead of one clear diagnosis.
"""
import io
import re
import sys

P = r'C:\Users\lidor\ETH-Switch-Tester\eth_switch_tester.py'
src = io.open(P, encoding='utf-8').read()
orig = src
done = []


def sub(old, new, tag, count=1):
    global src
    if old not in src:
        print(f'  !! NOT FOUND: {tag}')
        return False
    src = src.replace(old, new, count)
    done.append(tag)
    return True


# ---------------------------------------------------------------- 1. exception
sub(
    'STREAM_A2B = 1      # port A -> switch -> port B',
    '''class PreflightError(RuntimeError):
    """
    Raised when the RX path is dead before a run starts.

    Carries a diagnosis rather than just a failure: a board can be linked and
    blinking while its fabric forwards nothing, and eleven consecutive
    NO FRAMES RECEIVED failures do not tell you which of the two it is.
    """

    def __init__(self, msg: str, detail: str = ""):
        super().__init__(msg)
        self.detail = detail


STREAM_A2B = 1      # port A -> switch -> port B''',
    'PreflightError class')

# ------------------------------------------------- 2. NIC error counters probe
sub(
    '    def _host_drops_raw(self) -> int:',
    '''    @staticmethod
    def nic_rx_counters(iface_name: str) -> Dict[str, int]:
        """
        Good frames / FCS errors / discards straight from the NIC, via
        Get-NetAdapterStatistics.

        This is the discriminator when Npcap sees nothing. Npcap only ever
        delivers frames that already passed FCS, so a corrupting physical layer
        and a switch that never forwards look identical through the capture
        API. The NIC's own error counter separates them.
        """
        if os.name != "nt":
            return {}
        ps = (
            "$a = Get-NetAdapter | Where-Object { $_.Name -eq '%s' -or "
            "$_.InterfaceDescription -eq '%s' } | Select-Object -First 1; "
            "if (-not $a) { 'x' } else { $s = Get-NetAdapterStatistics "
            "-Name $a.Name; \\"{0} {1} {2}\\" -f ($s.ReceivedUnicastPackets + "
            "$s.ReceivedNonUnicastPackets), $s.ReceivedPacketErrors, "
            "$s.ReceivedDiscardedPackets }"
        ) % (iface_name, iface_name)
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=25,
                creationflags=0x08000000).stdout.split()
            if len(out) < 3:
                return {}
            return {"good": int(out[0]), "errors": int(out[1]),
                    "discards": int(out[2])}
        except Exception:
            return {}

    def preflight(self, count: int = 200, pps: float = 500.0) -> Dict:
        """
        Prove a frame can make the trip before committing to a long run.

        Raises PreflightError with a diagnosis when nothing arrives. Cheap
        (~0.4 s per direction) and it runs before every suite.
        """
        res = {}
        for tag, tx, rx_if, stream, dst, src in (
                ("A->B", "a", self.cfg.iface_b, STREAM_A2B,
                 self.cfg.mac_b, self.cfg.mac_a),
                ("B->A", "b", self.cfg.iface_a, STREAM_B2A,
                 self.cfg.mac_a, self.cfg.mac_b)):
            before = self.nic_rx_counters(rx_if)
            self.settle(0.2)
            sender = self.sender_a if tx == "a" else self.sender_b
            st = self.stats[stream]
            tpl = build_template(dst, src, 64, stream)
            self.stop_event.clear()
            t = Transmitter(sender, tpl, st, pps, 0, self.stop_event,
                            count=count)
            t.start()
            t.join(timeout=10)
            time.sleep(0.6)
            got = st.snapshot()["rx_frames"]
            after = self.nic_rx_counters(rx_if)
            d_err = (after.get("errors", 0) - before.get("errors", 0)
                     if before and after else -1)
            d_dis = (after.get("discards", 0) - before.get("discards", 0)
                     if before and after else -1)
            res[tag] = {"tx": count, "rx": got, "nic_rx_errors": d_err,
                        "nic_rx_discards": d_dis}
            self.emit("log", f"preflight {tag}: {got}/{count} arrived"
                             + (f", NIC FCS errors +{d_err}" if d_err > 0 else ""))

        a, b = res["A->B"], res["B->A"]
        if a["rx"] == 0 and b["rx"] == 0:
            corrupt = (a["nic_rx_errors"] > 0 or b["nic_rx_errors"] > 0
                       or a["nic_rx_discards"] > 0 or b["nic_rx_discards"] > 0)
            if corrupt:
                raise PreflightError(
                    "Frames arrive but every one is CORRUPT - nothing usable "
                    "reaches either port.",
                    "The NIC is discarding frames on FCS, so the capture layer "
                    "never sees one. Signal reaches the PHY, so this is "
                    "physical rather than configuration:\\n"
                    "  - reference clock: crystal load caps, marginal solder, "
                    "wrong part\\n"
                    "  - magnetics: centre-tap caps, swapped pairs\\n"
                    "  - termination / impedance, long stubs\\n"
                    "  - supply noise on the PHY rails")
            raise PreflightError(
                "No frames arrive in EITHER direction, and not one corrupt "
                "frame either.",
                "Both ports report link up, but nothing crosses the fabric. "
                "Link and the activity LED are driven by the PHY and come up "
                "even when the switch core forwards nothing, so a blinking LED "
                "does not mean the switch is working.\\n"
                "Check, cheapest first:\\n"
                "  - are BOTH cables in the SAME board? one adapter in each "
                "board gives exactly this result\\n"
                "  - KSZ8895: Start Switch, Register 1 bit 0. The fabric is "
                "DISABLED at power-up and forwards nothing until it is set to "
                "1 (datasheet p.43/47)\\n"
                "  - strap resistors selecting managed vs unmanaged mode - "
                "compare against the board that works\\n"
                "  - whatever host writes that bit (MCU / SPI / I2C / EEPROM) "
                "may not have run on this unit")
        if a["rx"] == 0 or b["rx"] == 0:
            dead = "A->B" if a["rx"] == 0 else "B->A"
            raise PreflightError(
                f"Nothing arrives in the {dead} direction (the other "
                f"direction works).",
                "One-way forwarding narrows it to a single port or pair: the "
                "receive side of one PHY, one twisted pair, or a per-port "
                "enable bit. Swap the two cables at the board - if the dead "
                "direction follows the port, the fault is on the board; if it "
                "follows the cable, it is the cable.")
        return res

    def _host_drops_raw(self) -> int:''',
    'preflight + nic_rx_counters')

# --------------------------------------------------- 3. run the gate in _wrap
sub(
    '''            s.open()
            s.bit_tap.enabled = True      # always tap, it is nearly free
            fn(s)
            self.emit("done", f"{label} complete")
        except Exception as e:''',
    '''            s.open()
            s.bit_tap.enabled = True      # always tap, it is nearly free
            if getattr(fn, "needs_preflight", False):
                self.emit("log", "preflight: checking a frame can make the trip")
                s.preflight()
            fn(s)
            self.emit("done", f"{label} complete")
        except PreflightError as pe:
            # A dead RX path is not a crash and not a switch verdict - it is a
            # reason to refuse to run, stated once and clearly.
            self.emit("logc", (f"PREFLIGHT FAILED: {pe}", BAD))
            if pe.detail:
                self.emit("logc", (pe.detail, WARN))
            self.emit("result", TestResult(
                "0. Preflight - RX path", False, str(pe), {},
                [{"check": "frames arrive in both directions",
                  "result": "FAIL"}]))
            self.emit("preflight_fail", (str(pe), pe.detail))
            self.emit("done", f"{label} NOT RUN - preflight failed")
        except Exception as e:''',
    '_wrap preflight hook')

# ------------------------------------------- 4. modal dialog for the GUI side
sub(
    '''                elif kind == "done":
                    self._on_done(str(payload))''',
    '''                elif kind == "preflight_fail":
                    msg, detail = payload  # type: ignore
                    messagebox.showerror(
                        "Preflight failed - nothing was tested",
                        msg + "\\n\\n" + detail)
                elif kind == "done":
                    self._on_done(str(payload))''',
    'preflight_fail dialog')

# ------------------------------------------------ 5. arm the gate on the runs
for fn_name in ("run_quick", "run_load", "run_full"):
    m = re.search(r'(\n    def %s\(self\):\n)(.*?)(\n        self\._start\(job, )'
                  % fn_name, src, re.S)
    if not m:
        print(f'  !! could not arm preflight on {fn_name}')
        continue
    if 'needs_preflight' in m.group(2):
        continue
    src = (src[:m.end(2)] + '\n        job.needs_preflight = True'
           + src[m.end(2):])
    done.append(f'{fn_name} armed')

# -------------------------------------------------- 6. calibration must fail
sub(
    '''            if r["rx_frames"] < 100:
                self.emit("logc", ("calibration failed - no frames received on the "
                                   "direct cable. Check the link.", BAD))
                return''',
    '''            if r["rx_frames"] < 100:
                # Returning quietly here let _wrap report "<label> complete",
                # left latency_offset_us at 0 with nothing flagging it, and
                # produced no FAILED row. Calibrating against nothing must be
                # loud, because every later latency figure depends on it.
                nic = s.nic_rx_counters(self.cfg.iface_b)
                extra = ""
                if nic.get("errors"):
                    extra = (f"  The NIC logged {nic['errors']} FCS errors, so "
                             f"frames are arriving CORRUPT rather than not at "
                             f"all - suspect the cable or the adapter.")
                msg = (f"Calibration FAILED: only {r['rx_frames']} of "
                       f"{r['tx_frames']} frames came back over the direct "
                       f"cable.{extra}")
                self.emit("logc", (msg, BAD))
                self.emit("result", TestResult(
                    "0. Latency calibration (direct cable)", False, msg, {},
                    [{"frames_sent": r["tx_frames"],
                      "frames_returned": r["rx_frames"],
                      "nic_rx_errors": nic.get("errors", "n/a"),
                      "result": "FAIL"}]))
                self.emit("preflight_fail", (
                    msg,
                    "Latency figures stay UNCALIBRATED, so they still include "
                    "both USB adapters and the host capture path.\\n\\n"
                    "For this step the two adapters must be cabled DIRECTLY to "
                    "each other - not through the switch. If they are, and "
                    "still nothing returns, try the other cable and confirm "
                    "both adapters show link up."))
                self.emit("done", "Calibration FAILED")
                return''',
    'calibration hard-fail')

# ---------------------------------------------------------------------- write
print('applied:', ', '.join(done) or 'nothing')
if src == orig:
    print('NO CHANGES - aborting')
    sys.exit(1)
io.open(P, 'w', encoding='utf-8', newline='').write(src)
print('bytes:', len(orig), '->', len(src))
