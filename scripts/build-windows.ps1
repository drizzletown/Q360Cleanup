$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Path $dist -Force | Out-Null
Push-Location (Join-Path $root 'source')
try {
    $env:CGO_ENABLED = '0'
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    go test -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go test failed' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go vet failed' }
    go build -trimpath -buildvcs=false -ldflags='-H windowsgui -s -w' -o (Join-Path $dist 'Q360Cleanup_Windows_x64.exe') .
    if ($LASTEXITCODE -ne 0) { throw 'Go build failed' }
}
finally { Pop-Location }
$exe = Join-Path $dist 'Q360Cleanup_Windows_x64.exe'
$hash = (Get-FileHash -Path $exe -Algorithm SHA256).Hash.ToLowerInvariant()
$hash + '  Q360Cleanup_Windows_x64.exe' | Set-Content -Encoding ascii (Join-Path $dist 'SHA256SUMS.txt')
Write-Host "Build complete: $exe"
Write-Host "SHA256: $hash"
