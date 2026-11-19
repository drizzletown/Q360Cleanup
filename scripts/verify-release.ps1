$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$exe = Join-Path $root 'dist/Q360Cleanup_Windows_x64.exe'
$sumPath = Join-Path $root 'dist/SHA256SUMS.txt'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Missing release EXE' }
if (-not (Test-Path -LiteralPath $sumPath -PathType Leaf)) { throw 'Missing SHA256SUMS.txt' }
$expected = ((Get-Content -Raw -LiteralPath $sumPath).Trim() -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($expected -ne $actual) { throw "Checksum mismatch: $actual != $expected" }
if ($expected -notmatch '^[0-9a-f]{64}$') { throw 'Malformed SHA-256 checksum' }
Write-Host "SHA256 verified: $actual"
Write-Host 'Note: this verifies integrity only; the executable is not Authenticode-signed.'
