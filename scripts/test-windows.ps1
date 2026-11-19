$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location (Join-Path $root 'source')
try {
    Write-Host 'Read-only Windows native tests; does NOT uninstall software or delete files.'
    go test -count=1 -timeout=5m -v ./...
    if ($LASTEXITCODE -ne 0) { throw 'Native tests failed' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Windows vet failed' }
} finally { Pop-Location }
& (Join-Path $PSScriptRoot 'build-windows.ps1')
& (Join-Path $PSScriptRoot 'verify-release.ps1')
