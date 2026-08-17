$root = 'C:\Users\lidor\ETH-Switch-Tester'
$py = 'C:\Program Files\Python313\python.exe'
$f = Join-Path $root 'eth_switch_tester.py'
Write-Output ('tester script  : ' + (Test-Path $f) + '  (' + (Get-Item $f -ErrorAction SilentlyContinue).Length + ' bytes)')
Write-Output ('wpcap System32 : ' + (Test-Path 'C:\Windows\System32\wpcap.dll'))
Write-Output ('npcap service  : ' + (Get-Service npcap -ErrorAction SilentlyContinue).Status)
Write-Output ''
Write-Output '--- self-test of the tool itself ---'
& $py $f --selftest 2>&1 | Out-String
Write-Output '--- Npcap fast path (kernel BPF + raw capture) ---'
& $py -c "from scapy.config import conf; conf.use_pcap=True; import scapy.all; from scapy.arch.libpcap import open_pcap; print('FASTPATH_OK')" 2>&1 | Out-String
Write-Output '--- USB Ethernet adapters the tool can use ---'
& $py -c "from scapy.arch.windows import get_windows_if_list as g
rows=[d for d in g() if d.get('mac') and ('USB' in str(d.get('description','')) or 'ASIX' in str(d.get('description','')))]
for d in rows: print('  ', d['description'], '|', d['mac'])
print('  count:', len(rows))" 2>&1 | Out-String
