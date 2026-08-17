$root = 'C:\Users\lidor\ETH-Switch-Tester'
$dst = Join-Path $root 'npcap-1.88.exe'
if (-not (Test-Path $dst)) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-1.88.exe' -OutFile $dst -UseBasicParsing -TimeoutSec 180
}
Write-Output ('Installer: ' + $dst + '  (' + (Get-Item $dst).Length + ' bytes)')
Start-Process explorer.exe -ArgumentList ('/select,' + $dst)
Start-Sleep -Seconds 1
try {
  Start-Process -FilePath $dst -Verb RunAs
  Write-Output 'LAUNCHED - approve the UAC prompt, then click through the installer'
} catch {
  Write-Output ('LAUNCH FAILED: ' + $_.Exception.Message)
}
