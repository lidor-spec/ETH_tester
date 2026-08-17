$root = 'C:\Users\lidor\ETH-Switch-Tester'
Set-Location $root
New-Item -ItemType Directory -Force -Path (Join-Path $root 'setup_scripts') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $root 'dev_tests') | Out-Null

# move the one-off diagnostics out of the project root
$scratch = @('adapters.ps1','check_npcap.ps1','diag_scapy.ps1','find_script.ps1',
             'install.ps1','install_script.ps1','launch_npcap.ps1','patch_defaults.py',
             'phy_check.ps1','usb_probe.ps1','verify.ps1','restart.ps1',
             'prep_for_claude_code.ps1')
foreach ($f in $scratch) {
  $src = Join-Path $root $f
  if (Test-Path $src) { Move-Item $src (Join-Path $root ('setup_scripts\' + $f)) -Force }
}
Write-Output '--- project root now ---'
Get-ChildItem $root | Select-Object Name, Length | Format-Table -AutoSize | Out-String -Width 90

# git
if (-not (Test-Path (Join-Path $root '.git'))) {
  git init -q 2>&1 | Out-Null
  git branch -M main 2>&1 | Out-Null
}
git config user.name  "lidor" 2>&1 | Out-Null
git config user.email "lidor@skypulse-tec.com" 2>&1 | Out-Null
git add -A 2>&1 | Out-Null
$msg = @"
ETH Switch Tester v2.5 - L2 raw-frame validation for KSZ8895

11-test suite over raw EtherType 0x88B5 frames with sequence numbers and
embedded timestamps. Live Tkinter dashboard, bit/timing view, self-contained
HTML report, and a --verify mode that proves the loss accounting by injecting
known damage.

See CLAUDE.md for architecture and the hard invariants that must not regress.
"@
git commit -q -m $msg 2>&1 | Out-Null
Write-Output '--- git ---'
git log --oneline -n 3 2>&1
git status --short 2>&1 | Select-Object -First 5
