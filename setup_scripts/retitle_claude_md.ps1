$p = 'C:\Users\lidor\ETH-Switch-Tester\CLAUDE.md'
$enc = New-Object System.Text.UTF8Encoding($false)   # UTF-8, no BOM
$t = [IO.File]::ReadAllText($p, $enc)

# Match only the leading words so the em-dash in the rest of the line is
# preserved byte-for-byte rather than guessed at.
$before = $t
$t = [regex]::Replace($t, '(?m)^# ETH Switch Tester', '# ETH_USB_tester')
if ($t -eq $before) { Write-Output 'TITLE NOT MATCHED' } else { Write-Output 'title replaced' }

[IO.File]::WriteAllText($p, $t, $enc)

# report
$first = ([IO.File]::ReadAllLines($p, $enc))[0]
Write-Output ('first line: ' + $first)
$b = [IO.File]::ReadAllBytes($p)
$em = 0
for ($i = 0; $i -lt $b.Length - 2; $i++) {
  if ($b[$i] -eq 0xE2 -and $b[$i+1] -eq 0x80 -and $b[$i+2] -eq 0x94) { $em++ }
}
Write-Output ('UTF-8 em-dashes intact: ' + $em)
Write-Output ('size: ' + $b.Length)
