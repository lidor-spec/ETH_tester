Write-Output '--- files modified in the last 60 minutes under C:\Users\lidor (py/bat/zip/txt) ---'
$cut = (Get-Date).AddMinutes(-60)
Get-ChildItem 'C:\Users\lidor' -Recurse -ErrorAction SilentlyContinue -Include '*.py','*.zip','*.bat' |
  Where-Object { $_.LastWriteTime -gt $cut } |
  Select-Object -First 25 FullName, Length, LastWriteTime | Format-Table -AutoSize | Out-String -Width 200

Write-Output '--- anything named like the tester anywhere on C: ---'
Get-ChildItem 'C:\' -Filter 'eth_switch*' -Recurse -ErrorAction SilentlyContinue -Force |
  Select-Object -First 10 FullName, Length | Format-Table -AutoSize | Out-String -Width 200

Write-Output '--- 15 newest files in Downloads ---'
Get-ChildItem 'C:\Users\lidor\Downloads' -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 15 Name, Length, LastWriteTime |
  Format-Table -AutoSize | Out-String -Width 200
