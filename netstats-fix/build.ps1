param(
    [string]$NDKPath = "G:\EvoX\ims\android-ndk-r27c"
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Src = "$ScriptDir\src"
$Mod = "$ScriptDir\module"
$Out = "$ScriptDir"

$Toolchain = "$NDKPath\toolchains\llvm\prebuilt\windows-x86_64\bin"
if (-not (Test-Path "$Toolchain\aarch64-linux-android21-clang.cmd")) {
    Write-Error "NDK not found at $NDKPath or toolchain missing"
    exit 1
}

Write-Output "Using NDK: $NDKPath"

Remove-Item -Path "$Mod\system\bin\netproxy" -ErrorAction SilentlyContinue
Remove-Item -Path "$Mod\system\bin\netproxy_arm" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path "$Mod\system\bin" -Force | Out-Null

Write-Output "Compiling ARM64..."
& "$Toolchain\aarch64-linux-android21-clang.cmd" -o "$Mod\system\bin\netproxy" -O2 -s -static "$Src\netproxy.c" 2>&1
if ($?) {
    $size = (Get-Item "$Mod\system\bin\netproxy").Length
    Write-Output "  ARM64: $size bytes"
} else {
    Write-Error "ARM64 compilation failed!"
    exit 1
}

Write-Output "Compiling ARM32..."
& "$Toolchain\armv7a-linux-androideabi21-clang.cmd" -o "$Mod\system\bin\netproxy_arm" -O2 -s -static "$Src\netproxy.c" 2>&1
if ($?) {
    $size = (Get-Item "$Mod\system\bin\netproxy_arm").Length
    Write-Output "  ARM32: $size bytes"
} else {
    Write-Error "ARM32 compilation failed!"
    exit 1
}

Write-Output "Building full module..."
$FullZip = "$Out\netstats-fix-v10.zip"
Remove-Item -Path $FullZip -ErrorAction SilentlyContinue

# Use a temp dir approach for precise control
$tmpDir = "$env:TEMP\netstats-fix-build"
Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

# Copy module files, excluding lite and arm variants
Get-ChildItem -Path $Mod | Where-Object { $_.Name -notmatch '_lite' -and $_.Name -notlike '*.git*' } | ForEach-Object {
    if ($_.PSIsContainer) {
        Copy-Item -Path $_.FullName -Destination "$tmpDir\$($_.Name)" -Recurse -Force
    } else {
        Copy-Item -Path $_.FullName -Destination "$tmpDir\$($_.Name)" -Force
    }
}

# Keep ARM binary in full module for compatibility

Compress-Archive -Path "$tmpDir\*" -DestinationPath $FullZip -CompressionLevel Optimal
Write-Output "  Created: $FullZip"

Write-Output "Building lite module..."
$LiteZip = "$Out\netstats-fix-v10-lite.zip"
Remove-Item -Path $LiteZip -ErrorAction SilentlyContinue

$tmpDirLite = "$env:TEMP\netstats-fix-build-lite"
Remove-Item -Path $tmpDirLite -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $tmpDirLite -Force | Out-Null

# Copy module files with lite renaming
Get-ChildItem -Path $Mod | Where-Object { $_.Name -notmatch '\.git' } | ForEach-Object {
    if ($_.PSIsContainer) {
        Copy-Item -Path $_.FullName -Destination "$tmpDirLite\$($_.Name)" -Recurse -Force
    } else {
        Copy-Item -Path $_.FullName -Destination "$tmpDirLite\$($_.Name)" -Force
    }
}

# Rename for lite
Copy-Item "$tmpDirLite\service_lite.sh" "$tmpDirLite\service.sh" -Force
Copy-Item "$tmpDirLite\post-fs-data_lite.sh" "$tmpDirLite\post-fs-data.sh" -Force
Copy-Item "$tmpDirLite\module_lite.prop" "$tmpDirLite\module.prop" -Force
Remove-Item "$tmpDirLite\service_lite.sh", "$tmpDirLite\post-fs-data_lite.sh", "$tmpDirLite\module_lite.prop" -ErrorAction SilentlyContinue
# Keep ARM binary in lite module for compatibility

Compress-Archive -Path "$tmpDirLite\*" -DestinationPath $LiteZip -CompressionLevel Optimal
Write-Output "  Created: $LiteZip"

# Cleanup
Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $tmpDirLite -Recurse -Force -ErrorAction SilentlyContinue

Write-Output ""
Write-Output "Done! Modules built:"
Write-Output "  $FullZip"
Write-Output "  $LiteZip"
