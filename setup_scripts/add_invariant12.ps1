$p = 'C:\Users\lidor\ETH-Switch-Tester\CLAUDE.md'
$enc = New-Object System.Text.UTF8Encoding($false)
$t = [IO.File]::ReadAllText($p, $enc)

$anchor = '## Known limits (by design, not bugs)'
$add = @'
12. **Never run a suite against a dead RX path, and never report a failed
    calibration as success.** `Session.preflight()` sends 200 frames each way
    before any run; on zero RX it raises `PreflightError` and the run is
    refused with a diagnosis. The discriminator is the NIC''s own FCS error
    counter (`Session.nic_rx_counters`, via `Get-NetAdapterStatistics`):
    Npcap only ever delivers frames that already passed FCS, so a corrupting
    physical layer and a switch that never forwards are indistinguishable
    through the capture API.
    - errors climbing + 0 captured -> frames arrive CORRUPT (clock, magnetics,
      termination, PHY supply)
    - errors flat + 0 captured -> linked but NOT FORWARDING. On a KSZ8895
      suspect **Start Switch, Register 1 bit 0** - the fabric is disabled at
      power-up and forwards nothing until it is set (datasheet p.43/47) - or
      straps, or both cables sitting in different boards.
    - A blinking link/activity LED proves only that the PHY trained. It is
      driven by the PHY and comes up even when the switch core forwards
      nothing, so it is not evidence of forwarding.
    `run_calibrate` previously logged one red line and returned, after which
    `_wrap` still reported "Calibration complete" while `latency_offset_us`
    silently stayed 0. It now shows a modal, emits a FAILED result, and the
    done-message says FAILED. Verified against a board that does not forward.

'@

if ($t.Contains('12. **Never run a suite against a dead RX path')) {
  Write-Output 'invariant 12 already present'
} elseif ($t.Contains($anchor)) {
  $t = $t.Replace($anchor, $add + $anchor)
  [IO.File]::WriteAllText($p, $t, $enc)
  Write-Output 'invariant 12 added'
} else {
  Write-Output 'ANCHOR NOT FOUND - CLAUDE.md left untouched'
}
