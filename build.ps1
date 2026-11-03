# build.ps1 - build the bilingual gitleak binaries.
#
# Produces three single-file executables in this directory:
#   gitleak-en.exe  default language: en
#   gitleak-zh.exe  default language: zh
#   gitleak.exe     default language: en (generic name)
#
# Both language builds are identical except for the compiled-in default
# (i18n.BuildDefault); --lang en|zh and GITLEAK_LANG override it at runtime.
#
# Usage:  .\build.ps1
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:GOCACHE = Join-Path $root '.gocache'
$env:GOTMPDIR = Join-Path $root '.gotmp'
New-Item -ItemType Directory -Force -Path $env:GOCACHE, $env:GOTMPDIR | Out-Null

Push-Location $root
try {
    Write-Host '==> gitleak-en.exe (default language: en)'
    go build -o gitleak-en.exe .
    if ($LASTEXITCODE -ne 0) { throw 'go build gitleak-en.exe failed' }

    Write-Host '==> gitleak-zh.exe (default language: zh)'
    go build -ldflags '-X gitleak/internal/i18n.BuildDefault=zh' -o gitleak-zh.exe .
    if ($LASTEXITCODE -ne 0) { throw 'go build gitleak-zh.exe failed' }

    Write-Host '==> gitleak.exe (default language: en)'
    go build -o gitleak.exe .
    if ($LASTEXITCODE -ne 0) { throw 'go build gitleak.exe failed' }

    Get-ChildItem -File gitleak.exe, gitleak-en.exe, gitleak-zh.exe |
        ForEach-Object { Write-Host ('  ' + $_.Name + '  ' + $_.Length + ' bytes') }
    Write-Host 'build OK'
} finally {
    Pop-Location
}
