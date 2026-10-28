$ErrorActionPreference = "Stop"

Write-Host "=== HYDRA FIREWALL v1.5-beta6-final ===" -ForegroundColor Cyan

$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"

$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } elseif ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { "$env:LOCALAPPDATA\Android\Sdk" }
# No pisar local.properties si existe (puede tener la firma y el feed de amenazas).
if (!(Test-Path "local.properties")) {
    ("sdk.dir=" + ($sdk -replace '\\','\\')) | Out-File -Encoding ASCII local.properties
}

Write-Host "[1/4] Unit tests + debug APK..." -ForegroundColor Yellow
$apk = ".\app\build\outputs\apk\debug\app-debug.apk"
Remove-Item $apk -ErrorAction SilentlyContinue
.\gradlew.bat testDebugUnitTest assembleDebug
if ($LASTEXITCODE -ne 0) {
    throw "Gradle fallo (codigo $LASTEXITCODE). No se instala ningun APK."
}

if (!(Test-Path $apk)) {
    throw "No se genero el APK: $apk"
}

$adb = Join-Path $sdk "platform-tools\adb.exe"
if (!(Test-Path $adb)) {
    throw "No se encontro adb: $adb"
}

Write-Host "[2/4] Verificando dispositivo..." -ForegroundColor Yellow
& $adb devices

Write-Host "[3/4] Instalando APK..." -ForegroundColor Yellow
& $adb install -r $apk
if ($LASTEXITCODE -ne 0) {
    throw "adb install fallo"
}

Write-Host "[4/4] Abriendo Hydra Firewall..." -ForegroundColor Yellow
$appId = if ($env:HYDRA_APPLICATION_ID) { $env:HYDRA_APPLICATION_ID } else {
    $m = Select-String -Path "app\build.gradle.kts" -Pattern 'cfg\("HYDRA_APPLICATION_ID",\s*"([^"]+)"' | Select-Object -First 1
    if ($m) { $m.Matches[0].Groups[1].Value } else { "com.hydraroot.firewall" }
}
& $adb shell monkey -p $appId 1 | Out-Host

Write-Host "Listo. APK: $apk" -ForegroundColor Green
