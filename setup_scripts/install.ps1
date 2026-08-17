# ETH Switch Tester - automated setup (runs elevated)
$ErrorActionPreference = 'Continue'
$root = 'C:\Users\lidor\ETH-Switch-Tester'
$log  = Join-Path $root 'setup.log'
New-Item -ItemType Directory -Force -Path $root | Out-Null
Set-Content -Path $log -Value '=== ETH Switch Tester setup ==='
function W($m) {
  $s = (Get-Date -Format 'HH:mm:ss') + '  ' + $m
  Add-Content -Path $log -Value $s
  Write-Host $s
}
W ('Admin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

# ---------- 1. Npcap ----------
if (Test-Path 'C:\Windows\System32\Npcap\wpcap.dll') {
  W 'STEP1 Npcap: already installed'
} else {
  W 'STEP1 Npcap: downloading 1.88 ...'
  $exe = Join-Path $env:TEMP 'npcap-1.88.exe'
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-1.88.exe' -OutFile $exe -UseBasicParsing -TimeoutSec 180
    W ('STEP1 downloaded ' + (Get-Item $exe).Length + ' bytes')
    W 'STEP1 installing silently with WinPcap API-compatible mode ...'
    $p = Start-Process -FilePath $exe -ArgumentList '/S','/winpcap_mode=yes' -Wait -PassThru
    W ('STEP1 installer exit code = ' + $p.ExitCode)
  } catch {
    W ('STEP1 ERROR: ' + $_.Exception.Message)
  }
}
if (Test-Path 'C:\Windows\System32\Npcap\wpcap.dll') { W 'STEP1 RESULT: NPCAP OK' } else { W 'STEP1 RESULT: NPCAP MISSING' }

# ---------- 2. A real (non-Store) Python ----------
# The Microsoft Store python.exe is an app-execution alias and misbehaves in
# elevated sessions, which is exactly how this tool has to run. Use a proper one.
function FindPy {
  $c = Get-ChildItem 'C:\Program Files\Python3*\python.exe' -ErrorAction SilentlyContinue |
       Sort-Object FullName -Descending | Select-Object -First 1
  if ($c) { return $c.FullName }
  $c = Get-ChildItem 'C:\Python3*\python.exe' -ErrorAction SilentlyContinue |
       Sort-Object FullName -Descending | Select-Object -First 1
  if ($c) { return $c.FullName }
  return $null
}
$py = FindPy
if (-not $py) {
  W 'STEP2 Python: no system-wide Python found, installing 3.13 via winget ...'
  try {
    $o = winget install --id Python.Python.3.13 --scope machine --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Out-String
    W ('STEP2 winget output tail: ' + ($o -split "`n" | Select-Object -Last 4 | Out-String))
  } catch {
    W ('STEP2 winget ERROR: ' + $_.Exception.Message)
  }
  $py = FindPy
} else {
  W ('STEP2 Python: found existing ' + $py)
}
if ($py) {
  W ('STEP2 RESULT: PYTHON = ' + $py + '  (' + ((& $py -V 2>&1) | Out-String).Trim() + ')')
  Set-Content -Path (Join-Path $root 'python_path.txt') -Value $py
} else {
  W 'STEP2 RESULT: PYTHON MISSING'
}

# ---------- 3. scapy + verify the fast capture path ----------
if ($py) {
  W 'STEP3 installing scapy ...'
  & $py -m pip install --upgrade pip --quiet 2>&1 | Out-Null
  $o = & $py -m pip install scapy 2>&1 | Out-String
  W ('STEP3 pip: ' + ($o -split "`n" | Select-Object -Last 3 | Out-String).Trim())
  $v = (& $py -c "import scapy; print(scapy.VERSION)" 2>&1) | Out-String
  W ('STEP3 RESULT: scapy version = ' + $v.Trim())
  $chk = (& $py -c "from scapy.config import conf; conf.use_pcap=True; import scapy.all; from scapy.arch.libpcap import open_pcap; print('FASTPATH_OK')" 2>&1) | Out-String
  W ('STEP4 Npcap fast-path check: ' + $chk.Trim())
  $ifs = (& $py -c "from scapy.arch.windows import get_windows_if_list as g; [print('IF|'+str(d.get('description'))+'|'+str(d.get('mac'))) for d in g() if d.get('mac')]" 2>&1) | Out-String
  W ('STEP5 adapters visible to the tool:')
  Add-Content -Path $log -Value $ifs
}
W 'SETUP_COMPLETE'
