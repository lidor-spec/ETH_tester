$py = 'C:\Program Files\Python313\python.exe'
Write-Output '=== Get-NetAdapter (Windows view, ALL states) ==='
Get-NetAdapter -IncludeHidden | Where-Object { $_.MacAddress } |
  Select-Object InterfaceDescription, Status, LinkSpeed, MacAddress |
  Format-Table -AutoSize | Out-String -Width 200
Write-Output '=== USB devices that look like network adapters ==='
Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
  Select-Object Status, FriendlyName | Format-Table -AutoSize | Out-String -Width 200
Write-Output '=== what scapy/Npcap can actually open ==='
& $py -c "from scapy.arch.windows import get_windows_if_list as g
for d in g():
    if d.get('mac'): print('  ', d.get('description'), '|', d.get('mac'), '|', d.get('ips'))" 2>&1 | Out-String
