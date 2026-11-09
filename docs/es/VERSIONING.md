# Versiones y actualizaciones

## Esquema de versiones

La versión vive en un solo archivo: [`version.properties`](../../version.properties).

| Tipo de cambio | Ejemplo | Comando |
|---|---|---|
| **Pequeño** (arreglos, textos, ajustes) | 1.1.0 → 1.1.**1** | `python tools/bump_version.py patch` |
| **Mediano** (funciones nuevas, cambios visibles) | 1.1.3 → 1.**2**.0 | `python tools/bump_version.py minor` |
| **Grande** (cambios de fondo, rediseños) | 1.4.2 → **2**.0.0 | `python tools/bump_version.py major` |

La parte que sube lo hace de a 1 y las de la derecha vuelven a 0.

El `versionCode` (el número interno que Android compara) se calcula solo:
`mayor × 10000 + menor × 100 + parche`. Ejemplos: 1.1.0 → 10100, 1.1.1 → 10101, 1.2.0 → 10200, 2.0.0 → 20000.
Siempre crece al subir la versión, y es mayor que el 164 que usaban las versiones anteriores a este esquema.
Menor y parche no pueden pasar de 99.

Cada cambio debería: (1) subir la versión con el comando de arriba, (2) agregar su entrada en `CHANGELOG.md` con ese número.

## Por qué Android pedía desinstalar

Android solo actualiza una app si **(1)** el APK está firmado con la **misma clave** que el instalado y **(2)** su
`versionCode` es **mayor** (o igual). Los APK *debug* que genera GitHub Actions se firman con una clave temporal
distinta en cada ejecución, por eso Android los trata como "otra app" y obliga a desinstalar.

La solución es firmar siempre con **tu** clave de release. En cada push y pull request el workflow corre las pruebas y genera una APK debug. Al subir un tag `vX.Y.Z`, si están configurados los cuatro secrets, genera el artefacto **`hydra-release-apk`** y publica el APK firmado como activo del GitHub Release.

## Configurar la firma (una sola vez)

1. Creá la keystore (necesitás JDK) y **guardá una copia fuera de GitHub**; sin ella no podés volver a actualizar la app:
   ```powershell
   keytool -genkeypair -v -keystore hydra-release.jks -alias hydra -keyalg RSA -keysize 4096 -validity 10000
   ```
2. Convertila a Base64 (PowerShell):
   ```powershell
   [Convert]::ToBase64String([IO.File]::ReadAllBytes("hydra-release.jks")) | Set-Clipboard
   ```
3. En GitHub: **Settings → Secrets and variables → Actions → New repository secret**, creá estos cuatro:
   `HYDRA_KEYSTORE_BASE64` (pegá lo copiado), `HYDRA_KEYSTORE_PASSWORD`, `HYDRA_KEY_ALIAS` (por ejemplo `hydra`) y `HYDRA_KEY_PASSWORD`.
   (Si ya los tenías para Google Play, no hace falta repetir nada: son los mismos.)
4. Nunca subas el `.jks` al repositorio (el `.gitignore` ya lo excluye).

## Instalar y actualizar

- **Primera vez con firma propia:** la app que tenés instalada hoy está firmada con una clave temporal, así que
  hay que **desinstalarla una última vez** (antes: Ajustes/Perfiles → *Exportar* tu configuración; el PIN y la huella no se exportan).
- Instalá el APK de `hydra-release-apk` (pestaña **Actions** → ejecución → *Artifacts*).
- **A partir de ahí**, cada versión nueva se instala encima, sin desinstalar y conservando tu configuración, siempre que
  la firma sea la misma y la versión sea mayor.
- Si Android dice "la app no se instaló" al actualizar: la firma es distinta (instalaste un APK debug) o la versión no es mayor.

## Publicar una versión

```powershell
python tools/bump_version.py minor      # o patch / major
# editá CHANGELOG.md con la entrada de la nueva versión
git add -A; git commit -m "Version 1.2.0"; git push origin main
git tag v1.2.0; git push origin v1.2.0   # genera el Release firmado en GitHub
```
