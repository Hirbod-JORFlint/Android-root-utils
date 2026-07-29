param([string]$NdkRoot="G:\EvoX\ims\android-ndk-r27c")
$ErrorActionPreference="Stop"
$Root=Split-Path -Parent $MyInvocation.MyCommand.Path
$ModuleDir = "$Root\module"

$cc = "$NdkRoot\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android21-clang.cmd"
$src = "$Root\src\netproxy.c"
$bin = "$ModuleDir\system\bin\netproxy"

Write-Host "=== Compiling netproxy.c ==="
& $cc -O2 -Wall -o $bin $src 2>&1
if (-not $?) { throw "compilation failed" }
Write-Host "Binary size: $((Get-Item $bin).Length) bytes"
Write-Host ""

function Build-Zip {
    param([string]$ZipName, [string]$PropSrc, [string]$ServiceSrc, [string]$PostFsSrc)
    $zip = "$Root\$ZipName"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    $staging = "$Root\staging"
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
    New-Item -ItemType Directory -Path "$staging\system\bin" -Force | Out-Null

    Copy-Item "$ModuleDir\$PropSrc" "$staging\module.prop"
    Copy-Item "$ModuleDir\customize.sh" "$staging\customize.sh"
    Copy-Item "$ModuleDir\sepolicy.rule" "$staging\sepolicy.rule"
    Copy-Item "$ModuleDir\$PostFsSrc" "$staging\post-fs-data.sh"
    Copy-Item "$ModuleDir\$ServiceSrc" "$staging\service.sh"
    Copy-Item "$ModuleDir\system\bin\netproxy" "$staging\system\bin\netproxy"

    Push-Location $staging
    try {
        & "C:\Program Files\7-Zip\7z.exe" a -mx=9 $zip * -r 2>&1 | Out-Null
    } finally {
        Pop-Location
    }
    Remove-Item $staging -Recurse -Force
    Write-Host "Built: $zip ($((Get-Item $zip).Length/1KB) KB)"
}

Write-Host "=== Building full module (BPF repair + proxy) ==="
Build-Zip -ZipName "netstats-fix-v10.zip" `
          -PropSrc "module.prop" `
          -ServiceSrc "service.sh" `
          -PostFsSrc "post-fs-data.sh"

Write-Host ""
Write-Host "=== Building lite module (proxy only, no BPF) ==="
Build-Zip -ZipName "netstats-fix-v10-lite.zip" `
          -PropSrc "module_lite.prop" `
          -ServiceSrc "service_lite.sh" `
          -PostFsSrc "post-fs-data_lite.sh"

Write-Host ""
Write-Host "Done."
