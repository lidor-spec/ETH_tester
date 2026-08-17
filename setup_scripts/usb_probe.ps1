Write-Output '=== devices with a PROBLEM (plugged in but not working) ==='
Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
  Where-Object { $_.Status -ne 'OK' } |
  Select-Object Status, Class, FriendlyName, InstanceId |
  Format-Table -AutoSize | Out-String -Width 190

Write-Output '=== all USB controllers / hubs / devices present ==='
Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
  Where-Object { $_.Class -in @('USB','Net','USBDevice') } |
  Select-Object Status, Class, FriendlyName |
  Sort-Object Class, FriendlyName | Format-Table -AutoSize | Out-String -Width 150

Write-Output '=== count of USB-attached network devices present ==='
$n = (Get-PnpDevice -PresentOnly -Class Net -ErrorAction SilentlyContinue |
      Where-Object { $_.FriendlyName -match 'USB|ASIX' }).Count
Write-Output ("USB network adapters PRESENT: " + $n)
Write-Output ("(need 2 for a forwarding test)")
