# Hydra Firewall

🇬🇧 [English version](README.md)

Firewall por app para Android (7.0+), sin root. Funciona como una **VPN local**: todo el tráfico del
teléfono pasa por la app, que decide qué apps pueden salir a internet, por Wi‑Fi o datos móviles,
y filtra anuncios, rastreadores y dominios maliciosos. Nada se envía a servidores de Hydra.

> Estado: **beta** (`1.5-beta6-final-r13-fix174`). Probala primero con apps no críticas.
> Leé [`docs/LIMITATIONS.md`](docs/es/LIMITATIONS.md) antes de confiar en ella para protegerte de malware.

<!--GALLERY-->

## English

Per-app firewall for Android (7.0+), no root required. Works as a **local VPN**: all
device traffic passes through the app, which decides which apps can reach the
internet over Wi‑Fi or mobile data, and filters ads, trackers and malicious
domains. Nothing is sent to Hydra's servers — there are none; everything runs
on-device.

Highlights: per-app allow/block/essential rules split by network, a
quarantine step for newly installed apps, a bundled ad/tracker blocklist
(license-compatible sources only — see `THIRD_PARTY_NOTICES.md`) plus
optional live lists (HaGeZi, 1Hosts), encrypted DNS (DoH/DoT), SNI/JA3-based
TLS filtering without decryption, a signed threat-intelligence pack
(IPs/domains, e.g. Feodo Tracker/URLhaus), an on-device behavior-learning
layer per app, and a static APK scanner (permissions, exported components,
DEX + YARA‑Lite rules + a small on-device model as a secondary signal). See
the table above (in Spanish) for the full feature list,
[`docs/BUILD.md`](docs/es/BUILD.md) to build it, and
[`docs/LIMITATIONS.md`](docs/es/LIMITATIONS.md) before relying on it against
malware. The project is GPL‑3.0‑or‑later; see [`LICENSE`](LICENSE).

Two rows in Security Center legitimately start at zero on a fresh install
and are not bugs: **"Threat intelligence (0 domains)"** stays at 0 until you
run an update from the blocklist screen with the HaGeZi Threat Intelligence
mini source enabled — it is separate from the bundled ad/tracker blocklist,
which is already active. **"Local behavior learning (0 apps)"** stays at 0
until you turn on traffic recording in the Analyzer tab (OFF by default) and
reopen Security Center after some real usage — that screen recalculates the
count from recorded traffic each time it opens.

## Qué hace

| Función | Detalle |
|---|---|
| Reglas por app | Permitir / Bloquear / Esencial / Sin firewall / Personalizado, con Wi‑Fi y datos móviles por separado, horarios y reglas avanzadas |
| Primera conexión | Las apps nuevas arrancan **bloqueadas** y la app te pregunta (permitir, 10 min, 1 h, siempre) |
| Cuarentena | Las apps recién instaladas quedan pendientes de revisión |
| Filtro DNS | ~18 000 dominios de anuncios/trackers incluidos en el APK (solo fuentes MIT/CC0/CC BY, ver THIRD_PARTY_NOTICES.md); al actualizar, la app descarga más desde HaGeZi, 1Hosts y, opcionalmente, StevenBlack y OISD |
| DNS cifrado | DoH/DoT con Cloudflare, Google o Quad9 |
| Inspección TLS (sin descifrar) | Bloqueo por nombre del sitio (SNI) y huella JA3 |
| QUIC/HTTP3 | Mejor esfuerzo: correlaciona con el DNS que la misma app resolvió antes |
| Inteligencia de amenazas | IPs/dominios (p. ej. Feodo Tracker, URLhaus) mediante un *pack firmado* — ver [`docs/THREAT-PACK.md`](docs/es/THREAT-PACK.md). Es distinta de la blocklist de ads/trackers: en el Centro de seguridad arranca en "0 dominios" hasta que corrés "Actualizar listas" con la fuente HaGeZi Threat Intelligence mini habilitada |
| Aprendizaje local de comportamiento | Perfil de tráfico por app aprendido en el propio teléfono, sin nube. Depende de activar el registro del Analizador (apagado por defecto); con eso apagado, el Centro de seguridad muestra "0 apps" aunque el firewall funcione normalmente |
| Escáner de APK | Análisis estático (permisos, componentes exportados, DEX) + reglas YARA‑Lite + modelo MH‑100K como señal secundaria |
| Seguridad de la app | PIN (PBKDF2) con límite de intentos, huella digital |
| ¿Por qué se conecta? | En el aviso de primera conexión y en el detalle del historial: dominio que la app resolvió, si está en listas o en inteligencia de amenazas, qué es el puerto, origen de instalación y antigüedad de la app |
| Consumo por app | Ranking de la sesión, de hoy y de 7 días con banderas ("sube más de lo que baja", "insiste y se la bloquea"); se guarda solo en el teléfono |
| Respaldo | Exportar/importar reglas, listas y ajustes a un archivo; viajan por nombre de app, no por UID |
| Estado del pack | Versión, vencimiento, contenido, último error y botón "Actualizar ahora" en el Centro de Seguridad |
| Diagnóstico | Historial, estadísticas por app/destino, autotest |

## Compilar e instalar

Necesitás JDK 17 y el Android SDK (o Android Studio). Guía completa: [`docs/BUILD.md`](docs/es/BUILD.md).

> El ID de la app ahora es `com.hydraroot.firewall` (antes `com.example.firewall`). Android la ve como **otra app**: **exportá tu configuración desde la versión vieja** antes de instalarla (ver `docs/BUILD.md`).

```bash
./build.sh install      # tests + APK debug + instalación por adb
./build.sh release      # APK release (firmada si configuraste keystore)
```

En Windows: `BUILD-AND-INSTALL.ps1`. También hay CI en `.github/workflows/` que compila y testea en GitHub sin Android Studio.

## Estructura

```
app/                      Código de la app (Kotlin + Jetpack Compose)
  src/main/java/.../vpn/        Motor de red: reenvío TCP/UDP/ICMP, DNS, reglas
  src/main/java/.../security/   Escáner de APK, YARA‑Lite, IA, packs de amenazas
tools/                    Entrenamiento de modelos y generador de packs firmados
docs/                     Guías (BUILD, THREAT-PACK, LIMITATIONS), referencia e historial
```

## Marca

El código es software libre (GPL‑3.0‑or‑later) y cualquiera puede hacer un fork. Los **nombres
«Hydra Firewall» y «Hydraroot» y el logo no se licencian junto con el código**. Si publicas una
versión modificada, usa otro nombre, otro logo y otro `applicationId`, y no la presentes como la app
oficial. Ver [`TRADEMARK.es.md`](TRADEMARK.es.md).

## Licencia

GPL‑3.0‑or‑later — ver `LICENSE` y `docs/reference/THIRD_PARTY-SECURITY-SOURCES.md`.
