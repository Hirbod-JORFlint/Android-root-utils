param(
    [string]$JdkHome = "",
    [string]$R8Jar = "",
    [int]$MinApi = 34
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- Locate JDK ---
if (-not $JdkHome) {
    $candidates = @(
        "${env:JAVA_HOME}",
        "C:\Program Files\Java\jdk-24",
        "C:\Program Files\Java\jdk-21",
        "C:\Program Files\Java\jdk-17"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path "$c\bin\javac.exe")) { $JdkHome = $c; break }
    }
}
if (-not $JdkHome) { throw "JDK 17+ not found. Set `$JdkHome or JAVA_HOME." }
Write-Host "JDK: $JdkHome"

# --- Locate / download r8 ---
if (-not $R8Jar) {
    $r8Candidates = @(
        "$Root\r8lib.jar",
        "$Root\libs\r8lib.jar",
        "${env:LOCALAPPDATA}\opencode\r8lib.jar"
    )
    foreach ($c in $r8Candidates) {
        if (Test-Path $c) { $R8Jar = $c; break }
    }
}
if (-not $R8Jar) {
    $R8Jar = "$Root\r8lib.jar"
    $r8Url = "https://storage.googleapis.com/r8-releases/raw/main/com/android/tools/r8/r8/9.1.31/r8-9.1.31.jar"
    Write-Host "Downloading r8 from $r8Url ..."
    Invoke-WebRequest -Uri $r8Url -OutFile $R8Jar -UseBasicParsing
    Write-Host "Downloaded r8"
}
if (-not (Test-Path $R8Jar)) { throw "r8 JAR not found at $R8Jar" }

$BuildDir = "$Root\build"
if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
New-Item -ItemType Directory -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Path "$BuildDir\classes" | Out-Null

$Src = "$Root\src"
$Stubs = "$Root\stubs"
$Module = "$Root\module"

Write-Host "Compiling..."
& "$JdkHome\bin\javac" --release 17 -d "$BuildDir\classes" -sourcepath "$Src;$Stubs" "$Src\com\opencode\netstats\NetworkStatsProxy.java" 2>&1
if (-not $?) { throw "javac failed" }

Write-Host "Converting to DEX..."
& "$JdkHome\bin\java" -cp $R8Jar com.android.tools.r8.D8 --release --min-api $MinApi --output "$BuildDir\proxy_out.zip" "$BuildDir\classes\com\opencode\netstats\NetworkStatsProxy.class" 2>&1
if (-not $?) { throw "d8 failed" }

# Extract classes.dex
& "C:\Program Files\7-Zip\7z.exe" e "$BuildDir\proxy_out.zip" "classes.dex" "-o$BuildDir" -y 2>&1 | Out-Null
Copy-Item "$BuildDir\classes.dex" "$Module\proxy.dex" -Force

# Package module zip
$OutputZip = "$Root\netstats-fix-v7.zip"
if (Test-Path $OutputZip) { Remove-Item $OutputZip -Force }
& "C:\Program Files\7-Zip\7z.exe" a -mx=9 $OutputZip "$Module\module.prop" "$Module\customize.sh" "$Module\sepolicy.rule" "$Module\post-fs-data.sh" "$Module\service.sh" "$Module\proxy.dex" 2>&1 | Out-Null

Write-Host "Done: $OutputZip ($((Get-Item $OutputZip).Length / 1KB) KB)"
