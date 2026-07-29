param(
    [string]$NDKPath = "G:\EvoX\ims\android-ndk-r27c",
    [string]$SevenZip = "C:\Program Files\7-Zip\7z.exe"
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Src = "$ScriptDir\src"
$Mod = "$ScriptDir\module"
$Out = "$ScriptDir"

if (-not (Test-Path $SevenZip)) {
    Write-Error "7z not found at $SevenZip. Install 7-Zip or set -SevenZip path."
    exit 1
}

$Toolchain = "$NDKPath\toolchains\llvm\prebuilt\windows-x86_64\bin"
if (-not (Test-Path "$Toolchain\aarch64-linux-android21-clang.cmd")) {
    Write-Error "NDK not found at $NDKPath or toolchain missing"
    exit 1
}

Write-Output "Using NDK: $NDKPath"
Write-Output "Using 7z: $SevenZip"

Remove-Item -Path "$Mod\system\bin\netproxy" -ErrorAction SilentlyContinue
Remove-Item -Path "$Mod\system\bin\netproxy_arm" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path "$Mod\system\bin" -Force | Out-Null

Write-Output "Compiling ARM64..."
& "$Toolchain\aarch64-linux-android21-clang.cmd" -o "$Mod\system\bin\netproxy" -O2 -s -static "$Src\netproxy.c" 2>&1
if (-not $?) { Write-Error "ARM64 compilation failed!"; exit 1 }
$size = (Get-Item "$Mod\system\bin\netproxy").Length
Write-Output "  ARM64: $size bytes"

Write-Output "Compiling ARM32..."
& "$Toolchain\armv7a-linux-androideabi21-clang.cmd" -o "$Mod\system\bin\netproxy_arm" -O2 -s -static "$Src\netproxy.c" 2>&1
if (-not $?) { Write-Error "ARM32 compilation failed!"; exit 1 }
$size = (Get-Item "$Mod\system\bin\netproxy_arm").Length
Write-Output "  ARM32: $size bytes"

function Build-ModuleZip {
    param([string]$OutputZip, [string]$TempSuffix, [scriptblock]$Customize)

    $tmpDir = "$env:TEMP\netstats-fix-build-$TempSuffix"
    Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    Get-ChildItem -Path $Mod | Where-Object { $_.Name -notmatch '\.git' } | ForEach-Object {
        if ($_.PSIsContainer) {
            $dest = "$tmpDir\$($_.Name)"
            Copy-Item -Path $_.FullName -Destination $dest -Recurse -Force
        } else {
            Copy-Item -Path $_.FullName -Destination "$tmpDir\$($_.Name)" -Force
        }
    }

    if ($Customize) { Invoke-Command $Customize }

    Remove-Item -Path $OutputZip -ErrorAction SilentlyContinue

    # Build list of files relative to tmpDir with forward slashes
    $fileList = @()
    Get-ChildItem -Path $tmpDir -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($tmpDir.Length).TrimStart('\')
        $rel = $rel.Replace('\', '/')
        $fileList += $rel
    }

    $listFilePath = "$tmpDir\filelist.txt"
    $fileList | Out-File -FilePath $listFilePath -Encoding ascii

    Push-Location $tmpDir
    & $SevenZip a -tzip -mx=9 "$OutputZip" "@$listFilePath" 2>&1
    Pop-Location

    if ($?) {
        Write-Output "  Created: $OutputZip"
    } else {
        Write-Error "  7z failed for $OutputZip"
    }

    Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output "Building full module..."
Build-ModuleZip -OutputZip "$Out\netstats-fix-v10.zip" -TempSuffix "full" -Customize {
    Remove-Item "$tmpDir\service_lite.sh" -Force -ErrorAction SilentlyContinue
    Remove-Item "$tmpDir\post-fs-data_lite.sh" -Force -ErrorAction SilentlyContinue
    Remove-Item "$tmpDir\module_lite.prop" -Force -ErrorAction SilentlyContinue
}

Write-Output "Building lite module..."
Build-ModuleZip -OutputZip "$Out\netstats-fix-v10-lite.zip" -TempSuffix "lite" -Customize {
    Remove-Item "$tmpDir\service.sh", "$tmpDir\post-fs-data.sh", "$tmpDir\module.prop" -Force -ErrorAction SilentlyContinue
    Move-Item "$tmpDir\service_lite.sh" "$tmpDir\service.sh" -Force
    Move-Item "$tmpDir\post-fs-data_lite.sh" "$tmpDir\post-fs-data.sh" -Force
    Move-Item "$tmpDir\module_lite.prop" "$tmpDir\module.prop" -Force
}

Write-Output ""
Write-Output "Done! Modules built:"
Write-Output "  $Out\netstats-fix-v10.zip"
Write-Output "  $Out\netstats-fix-v10-lite.zip"
