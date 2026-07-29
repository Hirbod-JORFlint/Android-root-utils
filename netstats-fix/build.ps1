param([string]$NdkRoot="G:\EvoX\android-ndk-r27d")
$ErrorActionPreference="Stop"
$Root=Split-Path -Parent $MyInvocation.MyCommand.Path

# Compile netproxy.c with NDK
$cc = "$NdkRoot\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android21-clang.cmd"
$src = "$Root\src\netproxy.c"
$bin = "$Root\module\system\bin\netproxy"
Write-Host "Compiling netproxy.c..."
& $cc -O2 -Wall -o $bin $src 2>&1
if (-not $?) { throw "compilation failed" }
Write-Host "Binary size: $((Get-Item $bin).Length) bytes"

# Build module zip
$zip = "$Root\netstats-fix-v9.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Push-Location "$Root\module"
try {
    & "C:\Program Files\7-Zip\7z.exe" a -mx=9 $zip module.prop customize.sh sepolicy.rule post-fs-data.sh service.sh system\bin\netproxy 2>&1 | Out-Null
} finally {
    Pop-Location
}
Write-Host "Done: $zip ($((Get-Item $zip).Length/1KB) KB)"
