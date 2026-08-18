# Splits "no RX data" into its two possible causes:
#   errors climbing + 0 frames  -> physical layer: frames arrive but fail FCS
#   errors flat    + 0 frames  -> the switch is not forwarding to this port
$ad = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'USB|ASIX' }
if (-not $ad) { Write-Output 'no USB Ethernet adapters present'; exit }

Write-Output '=== link state (compare bad board vs good board) ==='
$ad | Select-Object Name, Status, LinkSpeed, FullDuplex, MediaConnectionState,
                    @{n='MAC';e={$_.MacAddress}} |
  Format-Table -AutoSize | Out-String -Width 150

Write-Output '=== autoneg / advertised settings ==='
foreach ($a in $ad) {
  $p = Get-NetAdapterAdvancedProperty -Name $a.Name -ErrorAction SilentlyContinue |
       Where-Object { $_.DisplayName -match 'Speed|Duplex|Flow' }
  Write-Output ("--- " + $a.Name + " (" + $a.InterfaceDescription + ") ---")
  $p | Select-Object DisplayName, DisplayValue | Format-Table -AutoSize | Out-String -Width 90
}

Write-Output '=== counters: sampling 6 s of whatever the board is sending ==='
$s0 = @{}
foreach ($a in $ad) { $s0[$a.Name] = Get-NetAdapterStatistics -Name $a.Name }
Start-Sleep -Seconds 6
foreach ($a in $ad) {
  $x = Get-NetAdapterStatistics -Name $a.Name
  $y = $s0[$a.Name]
  $rxOk  = ($x.ReceivedUnicastPackets + $x.ReceivedNonUnicastPackets) -
           ($y.ReceivedUnicastPackets + $y.ReceivedNonUnicastPackets)
  $rxErr = $x.ReceivedPacketErrors - $y.ReceivedPacketErrors
  $rxDis = $x.ReceivedDiscardedPackets - $y.ReceivedDiscardedPackets
  $txOk  = ($x.SentUnicastPackets + $x.SentNonUnicastPackets) -
           ($y.SentUnicastPackets + $y.SentNonUnicastPackets)
  Write-Output ("--- " + $a.Name + " ---")
  Write-Output ("   good frames IN : " + $rxOk)
  Write-Output ("   RX ERRORS      : " + $rxErr + "   <-- FCS/alignment failures")
  Write-Output ("   RX discarded   : " + $rxDis)
  Write-Output ("   frames OUT     : " + $txOk)
  if ($rxOk -eq 0 -and $rxErr -gt 0) {
    Write-Output '   VERDICT: signal reaches the PHY but every frame is CORRUPT.'
    Write-Output '            Physical layer / clock, not switch configuration.'
  } elseif ($rxOk -eq 0 -and $rxErr -eq 0) {
    Write-Output '   VERDICT: nothing arrives at all - no corrupt frames either.'
    Write-Output '            Port is linked but not forwarding, or it is idle.'
  } else {
    Write-Output '   VERDICT: this port is receiving good frames.'
  }
}
