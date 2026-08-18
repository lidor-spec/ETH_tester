Set-Location 'C:\Users\lidor\ETH-Switch-Tester'
$url = 'https://github.com/lidor-spec/ETH_tester.git'

# point origin at the repo the user created
$has = $false
try { git remote get-url origin *> $null; $has = ($LASTEXITCODE -eq 0) } catch {}
if ($has) { git remote set-url origin $url } else { git remote add origin $url }
Write-Output ('origin -> ' + (git remote get-url origin))
Write-Output ''

Write-Output '=== does this machine already have GitHub credentials? ==='
Write-Output ('credential.helper : ' + (git config --get credential.helper))
$env:GIT_TERMINAL_PROMPT = '0'
Write-Output ''
Write-Output '=== probing the remote (read-only, no push) ==='
$out = git ls-remote --heads origin 2>&1 | Out-String
Write-Output ('exit code: ' + $LASTEXITCODE)
Write-Output ($out.Trim())
if ($LASTEXITCODE -eq 0) {
  if ($out.Trim().Length -eq 0) {
    Write-Output 'RESULT: authenticated, and the remote is EMPTY -> safe to push'
  } else {
    Write-Output 'RESULT: authenticated, but the remote ALREADY HAS COMMITS -> do not force'
  }
} else {
  Write-Output 'RESULT: not authenticated yet (or repo not reachable)'
}
