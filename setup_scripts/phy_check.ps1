$py = 'C:\Program Files\Python313\python.exe'
$a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'USB|ASIX' } | Select-Object -First 1
if (-not $a) { Write-Output 'no USB Ethernet adapter with link up'; exit }
Write-Output ('=== ' + $a.InterfaceDescription + '  (' + $a.Name + ') ===')
$adv = Get-NetAdapterAdvancedProperty -Name $a.Name -ErrorAction SilentlyContinue |
       Where-Object { $_.DisplayName -match 'Speed|Duplex|Flow' }
$adv | Select-Object DisplayName, DisplayValue | Format-Table -AutoSize | Out-String -Width 120
Write-Output ('negotiated link  : ' + $a.LinkSpeed + '  full-duplex=' + $a.FullDuplex)
Write-Output ('media connect    : ' + $a.MediaConnectionState)
$s0 = Get-NetAdapterStatistics -Name $a.Name
Write-Output '--- injecting 2000 frames into the switch (64 B, 2000 pps) ---'
& $py -c "import sys; sys.argv=['x']
from scapy.config import conf; conf.use_pcap=True
sys.path.insert(0,r'C:\Users\lidor\ETH-Switch-Tester')
from eth_switch_tester import RawSender, build_template, stamp, now_ns
import time
snd = RawSender(r'$($a.Name)')
tpl = build_template('ff:ff:ff:ff:ff:ff', '$($a.MacAddress)'.replace('-',':').lower(), 64, 1)
t0=time.perf_counter()
for i in range(2000):
    while (time.perf_counter()-t0) < i/2000.0: pass
    stamp(tpl,i,now_ns()); snd.send(tpl)
print('   sent 2000 broadcast frames in %.2f s' % (time.perf_counter()-t0))
snd.close()" 2>&1 | Out-String
Start-Sleep -Seconds 1
$s1 = Get-NetAdapterStatistics -Name $a.Name
Write-Output ('frames OUT delta : ' + ($s1.SentUnicastPackets + $s1.SentNonUnicastPackets - $s0.SentUnicastPackets - $s0.SentNonUnicastPackets))
Write-Output ('frames IN  delta : ' + ($s1.ReceivedUnicastPackets + $s1.ReceivedNonUnicastPackets - $s0.ReceivedUnicastPackets - $s0.ReceivedNonUnicastPackets))
Write-Output ('OUT errors       : ' + ($s1.OutboundPacketErrors - $s0.OutboundPacketErrors))
Write-Output ('OUT discards     : ' + ($s1.OutboundPacketsDiscarded - $s0.OutboundPacketsDiscarded))
Write-Output ('IN  errors       : ' + ($s1.ReceivedPacketErrors - $s0.ReceivedPacketErrors))
