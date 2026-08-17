$bin = Join-Path $env:USERPROFILE '.local\bin'
if (-not (Test-Path (Join-Path $bin 'claude.exe'))) {
  Write-Output 'claude.exe not found - install did not complete'
  exit 1
}
$u = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($u -split ';' -contains $bin) {
  Write-Output "already on user PATH: $bin"
} else {
  [Environment]::SetEnvironmentVariable('Path', ($u.TrimEnd(';') + ';' + $bin), 'User')
  Write-Output "added to user PATH: $bin"
  Write-Output '(open a NEW terminal for it to take effect)'
}
& (Join-Path $bin 'claude.exe') --version
