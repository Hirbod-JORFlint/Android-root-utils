param([string]$JdkHome="",[string]$R8Jar="",[int]$MinApi=34)
$ErrorActionPreference="Stop"
$Root=Split-Path -Parent $MyInvocation.MyCommand.Path
if(-not $JdkHome){$cs=@("${env:JAVA_HOME}","C:\Program Files\Java\jdk-24","C:\Program Files\Java\jdk-21","C:\Program Files\Java\jdk-17");foreach($c in $cs){if($c -and (Test-Path "$c\bin\javac.exe")){$JdkHome=$c;break}}}
if(-not $JdkHome){throw "JDK 17+ not found"}
if(-not $R8Jar){$rc=@("$Root\r8lib.jar","$Root\libs\r8lib.jar","${env:LOCALAPPDATA}\Flint\r8lib.jar");foreach($c in $rc){if(Test-Path $c){$R8Jar=$c;break}}}
if(-not $R8Jar){$R8Jar="$Root\r8lib.jar";Write-Host "Downloading r8...";Invoke-WebRequest -Uri "https://storage.googleapis.com/r8-releases/raw/main/com/android/tools/r8/r8/9.1.31/r8-9.1.31.jar" -OutFile $R8Jar -UseBasicParsing}
$bd="$Root\build";if(Test-Path $bd){Remove-Item $bd -Recurse -Force};New-Item -ItemType Directory -Path "$bd\classes"|Out-Null
Write-Host "Compiling..."; & "$JdkHome\bin\javac" --release 17 -d "$bd\classes" -sourcepath "$Root\src;$Root\stubs" "$Root\src\com\flint\netstats\NetworkStatsProxy.java" 2>&1; if(-not $?){throw "javac failed"}
Write-Host "D8..."; & "$JdkHome\bin\java" -cp $R8Jar com.android.tools.r8.D8 --release --min-api $MinApi --output "$bd\proxy_out.zip" "$bd\classes\com\flint\netstats\NetworkStatsProxy.class" 2>&1; if(-not $?){throw "d8 failed"}
& "C:\Program Files\7-Zip\7z.exe" e "$bd\proxy_out.zip" "classes.dex" "-o$bd" -y 2>&1|Out-Null
Copy-Item "$bd\classes.dex" "$Root\module\proxy.dex" -Force
$zip="$Root\netstats-fix-v8.zip";if(Test-Path $zip){Remove-Item $zip -Force}
Push-Location "$Root\module"
try {
    & "C:\Program Files\7-Zip\7z.exe" a -mx=9 $zip module.prop customize.sh sepolicy.rule post-fs-data.sh service.sh proxy.dex system\lib64\libbinder_pool.so 2>&1|Out-Null
} finally {
    Pop-Location
}
Write-Host "Done: $zip ($((Get-Item $zip).Length/1KB) KB)"
