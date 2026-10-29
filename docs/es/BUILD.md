# Compilar e instalar

## Requisitos
- JDK 17
- Android SDK con plataforma 35 (Android Studio lo instala solo)
- Un celular con Android 7.0+ y depuración USB (para instalar por `adb`), o transferir la APK a mano

## 1. Probar rápido (APK debug)
```bash
./build.sh              # tests + app/build/outputs/apk/debug/app-debug.apk
./build.sh install      # además instala por adb
```
Windows: `./BUILD-AND-INSTALL.ps1` (usa `ANDROID_HOME`/`%LOCALAPPDATA%\Android\Sdk`; no pisa tu `local.properties`).

La APK debug se instala directamente (activá "instalar apps desconocidas" si la pasás a mano).

## 2. APK release firmada
1. Creá la keystore **una sola vez** y guardala con backup (sin ella no podrás actualizar la app instalada):
   ```bash
   keytool -genkeypair -v -keystore hydra-release.jks -alias hydra -keyalg RSA -keysize 4096 -validity 10000
   ```
2. Copiá `local.properties.example` a `local.properties` y completá `HYDRA_KEYSTORE_FILE`, `HYDRA_KEYSTORE_PASSWORD`, `HYDRA_KEY_ALIAS`, `HYDRA_KEY_PASSWORD`.
3. `./build.sh release` → `app/build/outputs/apk/release/app-release.apk`.

Sin keystore, el release queda `unsigned` y Android no lo instala.
Las variables también pueden venir del entorno (útil en CI). Nunca subas `local.properties` ni `.jks`.

### Backup de claves (hacerlo antes de publicar)

Hay **dos** claves privadas distintas en este proyecto, y perder cualquiera de
las dos tiene consecuencias que no se pueden deshacer después:

| Clave | Archivo | Si la perdés |
|---|---|---|
| Keystore de firma de la app | `hydra-release.jks` (la que creaste arriba) | No podés publicar una actualización que Android acepte como "la misma app" sobre instalaciones existentes. Tenés que lanzar con otro `applicationId` y todos reinstalan desde cero, perdiendo configuración. |
| Clave privada de firma del pack de amenazas | `secrets/hydra_threat_signing_key.pem` (la crea `tools/generate_signing_key.sh`) | No podés publicar actualizaciones del pack de amenazas que la app vaya a aceptar (`ThreatSignatureVerifier` las rechaza sin la firma correcta). Hay que generar una clave nueva y volver a publicarla como `HYDRA_THREAT_PUBLIC_KEY` en todos los builds futuros — los que ya instalaron la app vieja quedan con la clave anterior hasta que actualicen. |

Ninguna de las dos debe estar solo en la máquina donde compilás:

1. **Nunca las subas al repo** (`.gitignore` ya excluye `*.jks` y `secrets/`, pero
   doble chequeo antes del primer push público).
2. Guardá una copia de cada una en **al menos dos lugares** fuera de esa máquina
   — por ejemplo un gestor de contraseñas con adjuntos (Bitwarden, 1Password) y
   un pendrive o disco externo guardado aparte. Un solo backup en la nube no
   alcanza si esa cuenta se compromete o se pierde el acceso.
3. Guardá junto con cada clave sus contraseñas/alias (`HYDRA_KEYSTORE_PASSWORD`,
   `HYDRA_KEY_ALIAS`, `HYDRA_KEY_PASSWORD`) — una keystore sin su contraseña es
   tan inútil como no tenerla.
4. Los secrets de GitHub Actions (`HYDRA_KEYSTORE_BASE64`, `HYDRA_THREAT_SIGNING_KEY`,
   etc.) son necesarios para el CI pero **no sustituyen** el backup: si se borra
   el repo o se pierde acceso a la organización de GitHub, esos secrets se
   pierden con él.

## 3. Compilar en GitHub (sin Android Studio)
Subí el proyecto a un repositorio. `.github/workflows/android.yml` corre los tests y publica la APK debug como artefacto (pestaña *Actions*).
Para una release firmada al crear un tag `vX.Y.Z`, cargá estos *secrets*: `HYDRA_KEYSTORE_BASE64` (`base64 -w0 hydra-release.jks`), `HYDRA_KEYSTORE_PASSWORD`, `HYDRA_KEY_ALIAS`, `HYDRA_KEY_PASSWORD`.

## Migrar desde la versión con ID `com.example.firewall`
El ID instalable cambió a `com.hydraroot.firewall` (se puede cambiar con `HYDRA_APPLICATION_ID`). El código vivía en el paquete `com.example.firewall`; desde esta versión el namespace es `com.hydra.firewall`. Android trata el ID instalable viejo y el nuevo como apps distintas, así que **no actualiza** la anterior:
1. En la versión **vieja**: pestaña *Perfiles* → **Exportar** (guarda un `.json`; no incluye PIN, historial ni estadísticas).
2. Instalá la versión nueva (puede convivir un rato con la vieja, pero **no actives las dos VPN a la vez**).
3. En la nueva: instalá/abrí tus apps, *Perfiles* → **Importar**. Las reglas se aplican por nombre de app; las apps no instaladas se omiten y se avisa. Se guarda una copia automática y hay botón **Deshacer**.
4. Desinstalá la versión vieja. Volvé a poner el PIN y la huella (no se exportan a propósito).

> Importá solo archivos propios: un archivo ajeno podría permitir apps que hoy tenés bloqueadas.

## Primer uso en el celular
1. Abrí la app y aceptá el diálogo de VPN y el permiso de notificaciones.
2. Excluí Hydra de la optimización de batería (si no, Android puede cerrar el servicio).
3. Con "Apps de confianza" desactivado, las apps nuevas piden confirmación en su primera conexión.
4. Probá primero con apps no críticas y usá **Autotest** para validar DNS/SNI/TCP.
5. No se puede usar otra VPN al mismo tiempo.
