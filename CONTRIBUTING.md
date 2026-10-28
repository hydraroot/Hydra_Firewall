# Contribuir a Hydra Firewall

Gracias por el interés. Esta guía es corta a propósito; el proyecto es
chico y la mayoría de las contribuciones son bienvenidas sin mucho trámite.

## Antes de escribir código

- Para cambios chicos (typos, docs, fixes puntuales): abrí directamente un
  Pull Request.
- Para cambios grandes (nueva función, refactor, cambio de comportamiento de
  red/firewall): abrí primero un issue describiendo qué y por qué, así no
  trabajás en algo que termine rechazado por razones de diseño.
- Para vulnerabilidades de seguridad: **no** uses un issue público — seguí
  [`SECURITY.md`](SECURITY.md).

## Entorno de desarrollo

Ver [`docs/BUILD.md`](docs/BUILD.md) para compilar e instalar. En resumen:

```bash
./build.sh install      # tests + APK debug + instalación por adb
```

Requiere JDK 17 y el Android SDK (Android Studio los trae).

## Antes de abrir el PR

- `./gradlew testDebugUnitTest` tiene que pasar.
- Si tocaste `tools/build_hydra_threat_pack.py` o
  `tools/rebuild_bundled_blocklist.py`, corré también
  `python3 -m unittest discover -s tools -v`.
- Si agregás una fuente de datos de terceros (blocklist, feed de amenazas,
  librería), confirmá que su licencia sea compatible con GPL-3.0 y agregala
  a `THIRD_PARTY_NOTICES.md` o `third_party/licenses/` según corresponda —
  ver ahí mismo qué licencias ya se evaluaron y por qué algunas quedaron
  afuera.
- Si cambiás algo visible para el usuario (reglas, UI, permisos, qué se
  bloquea por defecto), agregá una línea en `CHANGELOG.md`.

## Estilo

- Kotlin + Jetpack Compose en `app/`, siguiendo el estilo ya presente en el
  archivo que estés tocando más que una guía externa.
- Python en `tools/` sigue `black`/PEP 8 de forma laxa; priorizá que sea
  legible y testeable sobre seguir una regla al pie de la letra.
- Commits y PRs pueden estar en español o inglés; el repo ya mezcla ambos.

## Qué esperar del review

Es un proyecto con un mantenedor part-time, así que el review puede tardar.
Un PR chico y enfocado en una sola cosa se revisa más rápido que uno grande
que mezcla varios cambios.
