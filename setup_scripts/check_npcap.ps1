Write-Output ('installer file exists : ' + (Test-Path 'C:\Users\lidor\ETH-Switch-Tester\npcap-1.88.exe'))
$p = Get-Process npcap-1.88 -ErrorAction SilentlyContinue
if ($p) { Write-Output ('installer RUNNING, pid ' + $p.Id) } else { Write-Output 'installer NOT running' }
Write-Output ('wpcap System32        : ' + (Test-Path 'C:\Windows\System32\wpcap.dll'))
Write-Output ('wpcap System32\Npcap  : ' + (Test-Path 'C:\Windows\System32\Npcap\wpcap.dll'))
$s = Get-Service npcap -ErrorAction SilentlyContinue
if ($s) { Write-Output ('npcap service         : ' + $s.Status) } else { Write-Output 'npcap service         : not installed' }
Write-Output ('tester script         : ' + (Test-Path 'C:\Users\lidor\ETH-Switch-Tester\eth_switch_tester.py'))
Write-Output '--- any eth_switch_tester.py on disk ---'
Get-ChildItem 'C:\Users\lidor' -Filter 'eth_switch_tester*' -Recurse -ErrorAction SilentlyContinue -Depth 3 | Select-Object -First 5 FullName, Length | Format-List
