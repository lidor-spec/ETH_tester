$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath
  exit
}
Get-Process python -ErrorAction SilentlyContinue | ForEach-Object {
  try { Stop-Process -Id $_.Id -Force; Write-Host ('killed ' + $_.Id) } catch {}
}
Start-Sleep -Seconds 2
Set-Location 'C:\Users\lidor\ETH-Switch-Tester'
Start-Process -FilePath 'C:\Program Files\Python313\python.exe' `
  -ArgumentList 'eth_switch_tester.py' `
  -WorkingDirectory 'C:\Users\lidor\ETH-Switch-Tester'
Write-Host 'fresh instance started (elevated)'
