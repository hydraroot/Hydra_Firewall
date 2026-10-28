#!/usr/bin/env bash
# Compila Hydra Firewall en Linux/macOS.
#   ./build.sh            -> tests + APK debug
#   ./build.sh release    -> tests + APK release (firmada si hay keystore configurada)
#   ./build.sh install    -> compila debug e instala por adb en el celular conectado
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-debug}"

if [ ! -f local.properties ]; then
  SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  if [ -z "$SDK" ]; then
    for c in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk"; do [ -d "$c" ] && SDK="$c" && break; done
  fi
  [ -n "$SDK" ] || { echo "ERROR: no encuentro el Android SDK. Definí ANDROID_HOME o creá local.properties (ver local.properties.example)." >&2; exit 1; }
  echo "sdk.dir=$SDK" > local.properties
  echo "local.properties creado con sdk.dir=$SDK"
fi

chmod +x ./gradlew
case "$MODE" in
  debug|install)
    ./gradlew --no-daemon testDebugUnitTest assembleDebug
    APK="app/build/outputs/apk/debug/app-debug.apk" ;;
  release)
    ./gradlew --no-daemon testDebugUnitTest assembleRelease
    APK="$(ls app/build/outputs/apk/release/*.apk | head -n1)" ;;
  *) echo "Uso: $0 [debug|release|install]" >&2; exit 2 ;;
esac

[ -f "$APK" ] || { echo "ERROR: no se generó el APK ($APK)" >&2; exit 1; }
echo "APK listo: $APK"
case "$APK" in *unsigned*) echo "AVISO: el APK release está SIN FIRMAR y no se puede instalar. Configurá la keystore (local.properties.example) o usá debug." ;; esac

if [ "$MODE" = "install" ]; then
  command -v adb >/dev/null || { echo "ERROR: adb no está en el PATH" >&2; exit 1; }
  adb devices
  adb install -r "$APK"
  APPID="${HYDRA_APPLICATION_ID:-$(grep -oE 'cfg\("HYDRA_APPLICATION_ID", *"[^"]+"' app/build.gradle.kts | grep -oE '"[^"]+"$' | tr -d '"')}"
  adb shell monkey -p "${APPID:-com.hydraroot.firewall}" 1 >/dev/null 2>&1 || true
  echo "Instalado."
fi
