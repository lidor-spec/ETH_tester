$root = 'C:\Users\lidor\ETH-Switch-Tester'
$hits = @()
foreach ($d in @('C:\Users\lidor\Downloads','C:\Users\lidor\Desktop','C:\Users\lidor\Documents')) {
  $hits += Get-ChildItem $d -Filter 'eth_switch_tester*.py' -Recurse -ErrorAction SilentlyContinue
}
if ($hits.Count -eq 0) {
  Write-Output 'NOT_FOUND - no eth_switch_tester*.py in Downloads/Desktop/Documents'
} else {
  $f = $hits | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  Write-Output ('FOUND: ' + $f.FullName + '  (' + $f.Length + ' bytes)')
  Copy-Item $f.FullName (Join-Path $root 'eth_switch_tester.py') -Force
  $t = Get-Item (Join-Path $root 'eth_switch_tester.py')
  Write-Output ('COPIED to ' + $t.FullName + '  (' + $t.Length + ' bytes)')
}
Write-Output '--- Npcap status ---'
Write-Output ('wpcap System32       : ' + (Test-Path 'C:\Windows\System32\wpcap.dll'))
Write-Output ('wpcap System32\Npcap : ' + (Test-Path 'C:\Windows\System32\Npcap\wpcap.dll'))
$s = Get-Service npcap -ErrorAction SilentlyContinue
if ($s) { Write-Output ('npcap service        : ' + $s.Status) } else { Write-Output 'npcap service        : NOT INSTALLED' }
