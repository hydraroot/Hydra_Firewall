# Pack de amenazas firmado

La app puede recibir IPs, dominios y reglas YARA‑Lite de un **pack firmado** (ECDSA P‑256 / SHA‑256).
Solo se instala si la firma verifica con la clave pública compilada en la app; un pack manipulado se descarta.

## Estado por defecto
- El pack incluido en la app (`assets/hydra_threat_pack_v1.json`) trae **solo reglas YARA‑Lite** y está firmado con la clave original del proyecto (la misma clave pública que está en `app/build.gradle.kts` y en `ThreatSignatureVerifier.DEFAULT_PUBLIC_KEY_B64`; ambas deben coincidir — lo comprueba `ThreatKeyConsistencyTest`).
- Una variable `HYDRA_THREAT_PUBLIC_KEY` vacía se trata como no definida (usa la clave por defecto).
- **Build sin configurar nada** (sin `HYDRA_THREAT_PUBLIC_KEY` en `local.properties` ni como variable de CI): la app usa esa clave por defecto, y el pack incluido verifica correctamente contra ella — el feed de reglas YARA‑Lite arranca con contenido, no vacío. Esto es lo que pasa en un build público normal.
- La actualización automática está **desactivada** hasta que compiles la app con `HYDRA_THREAT_FEED_URL`.
- **Atención si seteás `HYDRA_THREAT_PUBLIC_KEY` con tu propia clave** (ver sección siguiente): a partir de ahí la app deja de aceptar la clave por defecto, así que el pack incluido en `assets/` queda rechazado hasta que lo vuelvas a firmar con tu clave privada corriendo `tools/rebuild_bundled_pack.sh`. Si configurás `HYDRA_THREAT_PUBLIC_KEY` en GitHub (Settings → Variables) para el workflow de CI pero no re‑firmás el pack bundleado del repo, el build público que arma esa Action sí te va a quedar con el feed incluido vacío/rechazado.

## Verificar un pack
`pip install cryptography` y luego `python tools/verify_threat_pack.py <archivo o URL del pack>` (usa la clave de `app/build.gradle.kts`; `--key` para otra).

## Activarlo con tu propia clave (recomendado)
1. `tools/generate_signing_key.sh` → crea `secrets/hydra_threat_signing_key.pem` (privada, backup, nunca al repo) y la pública en Base64.
2. En `local.properties` poné `HYDRA_THREAT_PUBLIC_KEY=<pública>` y `HYDRA_THREAT_FEED_URL=https://raw.githubusercontent.com/Hydraroot/HYDRA_FIREWALL/threat-pack/hydra_threat_pack.json`.
3. `tools/rebuild_bundled_pack.sh` → re‑firma el pack incluido con tu clave (si no, la app rechazaría el original y arrancaría sin firmas).
4. En GitHub cargá el secret `HYDRA_THREAT_SIGNING_KEY` (contenido del PEM) y, opcional, `ABUSECH_AUTH_KEY` (gratis en https://auth.abuse.ch/). `.github/workflows/threat-pack.yml` genera y publica el pack a diario en la rama `threat-pack`.
5. Compilá la app (`./build.sh`).

Si tenés la clave privada original del proyecto, podés saltear 1–2 y usarla en 3.

## Feeds soportados por `tools/build_hydra_threat_pack.py`
| Feed | Clave | Qué aporta |
|---|---|---|
| Feodo Tracker (`--feodo`) | no | IPs de C2 de botnets |
| URLhaus (`--urlhaus-api`) | opcional | hosts que distribuyen malware (solo el host; IP literal → IP, dominio → dominio) |
| ThreatFox (`--threatfox-api`) | sí (`ABUSECH_AUTH_KEY`) | IOCs de los últimos días |
| Exports manuales (`--threatfox-export`, `--urlhaus-export`, `--feodo-file`, `--urlhaus-text-file`) | — | para uso offline |

> Los endpoints de abuse.ch están escritos según su documentación pública pero **no pude probarlos en vivo**; cada feed falla de forma aislada (aviso en el log) y `--min-indicators` evita publicar un pack vacío si todos caen.

## Protecciones contra falsos positivos
Las coincidencias de amenaza bloquean tráfico, así que el generador:
- excluye dominios de servicios legítimos muy usados (GitHub, Google, Cloudflare, Discord, Telegram, etc.) aunque un feed los liste;
- descarta IPs privadas, locales o reservadas;
- limita el tamaño (150 000 dominios / 60 000 IPs) priorizando los de mayor confianza;
- usa expiración (14 días en el workflow): un pack vencido se ignora y la app vuelve al incluido.

La lista segura es acotada y **no es exhaustiva**: revisá `SAFE_DOMAIN_SUFFIXES` según tu uso.
