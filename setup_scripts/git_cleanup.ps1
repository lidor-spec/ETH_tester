Set-Location 'C:\Users\lidor\ETH-Switch-Tester'

# Stop tracking artefacts that should never have been committed.
# --cached keeps the files on disk, it only removes them from the index.
foreach ($f in @('~$README.md', '.claude/settings.local.json')) {
  git rm --cached --quiet -- $f 2>&1 | Out-Null
  Write-Output ("untracked: " + $f)
}

# extend .gitignore (idempotent)
$gi = '.gitignore'
$lines = @()
if (Test-Path $gi) { $lines = Get-Content $gi }
$add = @(
  '',
  '# Microsoft Office lock files (appear while a doc is open)',
  '~$*',
  '',
  '# Claude Code per-machine settings (settings.json IS shared, .local.json is not)',
  '.claude/settings.local.json',
  '',
  '# generated test reports',
  'docs/*.tmp'
)
$new = $add | Where-Object { $lines -notcontains $_ -or $_ -eq '' }
Add-Content -Path $gi -Value $new

git add -A 2>&1 | Out-Null
git commit -q -m "Stop tracking Office lock files and per-machine Claude settings" 2>&1 | Out-Null
$env:GIT_TERMINAL_PROMPT = '0'
git push origin main 2>&1 | Out-String
Write-Output ('push exit: ' + $LASTEXITCODE)
Write-Output ''
Write-Output '=== verify ==='
Write-Output ('files tracked : ' + (git ls-files | Measure-Object).Count)
Write-Output ('still tracking junk? : ' + ((git ls-files | Where-Object { $_ -like '*~$*' -or $_ -like '*settings.local*' }) -join ', '))
Write-Output ('local HEAD  : ' + (git rev-parse --short HEAD))
Write-Output ('remote HEAD : ' + (git rev-parse --short origin/main))
git status -sb 2>&1 | Select-Object -First 4
