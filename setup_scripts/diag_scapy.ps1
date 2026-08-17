$f = 'C:\Users\lidor\ETH-Switch-Tester\eth_switch_tester.py'
Write-Output ('tester file size: ' + (Get-Item $f).Length + '  modified ' + (Get-Item $f).LastWriteTime)
Write-Output ''
Write-Output '=== which python is associated with .py files ==='
cmd /c "assoc .py" 2>&1
cmd /c "ftype Python.File" 2>&1
Write-Output ''
Write-Output '=== every python on this machine, and does it have scapy ==='
$cands = @('C:\Program Files\Python313\python.exe',
           'C:\Program Files\Python312\python.exe',
           'C:\Users\lidor\AppData\Local\Microsoft\WindowsApps\python.exe')
foreach ($c in $cands) {
  if (Test-Path $c) {
    $v = (& $c -V 2>&1) | Out-String
    $sc = (& $c -c "import scapy; print('scapy', scapy.VERSION)" 2>&1) | Out-String
    Write-Output ("  " + $c)
    Write-Output ("      version: " + $v.Trim())
    Write-Output ("      scapy  : " + $sc.Trim().Split("`n")[-1])
  }
}
Write-Output ''
Write-Output '=== the REAL import error, straight from the tester module ==='
& 'C:\Program Files\Python313\python.exe' -c @"
import sys
sys.path.insert(0, r'C:\Users\lidor\ETH-Switch-Tester')
import eth_switch_tester as E
print('SCAPY_OK =', E.SCAPY_OK)
print('SCAPY_ERR =', repr(E.SCAPY_ERR))
"@ 2>&1
