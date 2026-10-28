# Third-party notices

Hydra is free software under GPL-3.0-or-later (see `LICENSE`). This file lists third-party
material it uses. Sections A–D are in English; the detailed per-blocklist breakdown (sections 1–2)
below is kept in Spanish.

## A. Libraries linked into the APK

| Component | Version | License | Source |
|---|---|---|---|
| Kotlin (stdlib, Compose compiler plugin) | Gradle plugin version | Apache-2.0 | https://github.com/JetBrains/kotlin |
| androidx.core:core-ktx | 1.13.1 | Apache-2.0 | https://developer.android.com/jetpack/androidx |
| androidx.activity:activity-compose | 1.9.3 | Apache-2.0 | same |
| androidx.lifecycle:lifecycle-runtime-ktx | 2.8.7 | Apache-2.0 | same |
| androidx.fragment:fragment-ktx | 1.8.5 | Apache-2.0 | same |
| androidx.appcompat:appcompat | 1.7.0 | Apache-2.0 | same |
| androidx.biometric:biometric | 1.1.0 | Apache-2.0 | same |
| Jetpack Compose (BOM; ui, ui-graphics, material3, foundation) | see `app/build.gradle.kts` | Apache-2.0 | https://developer.android.com/jetpack/compose |
| org.jetbrains.kotlinx:kotlinx-coroutines-android | 1.9.0 | Apache-2.0 | https://github.com/Kotlin/kotlinx.coroutines |
| junit:junit (tests only, not shipped) | 4.13.2 | EPL-1.0 | https://junit.org/junit4/ |

Apache-2.0 text: `third_party/licenses/Apache-2.0`. Transitive dependencies of the above are
covered by their own (Apache-2.0 / compatible) licenses; run `./gradlew :app:dependencies` for the
full list.

## B. Machine-learning data

- **MH-100K Android Malware Dataset** (https://huggingface.co/datasets/hendriow/mh100k) — CC BY 4.0.
  The dataset is **not** bundled. The compact model `hydra_apk_ai_mh100k_v2.*` was trained from it
  with `tools/train_hydra_apk_ai_mh100k.py`. Attribution: see `docs/reference/MH100K-ATTRIBUTION.md`.
- `hydra_ai_model_v1/v2/v3.json` and `hydra_ai_privacy_v1.json` are Hydra's own models trained on
  synthetic data (see `docs/reference/HYDRA-AI-LITE-TRAINING-REPORT.md`).
- Python training tools use numpy, pandas and scikit-learn (BSD-3-Clause; development only, not shipped).

## C. Certificates

`app/src/main/res/raw/hydra_extra_roots.pem` contains four public root CA certificates
(DigiCert Global Root CA, DigiCert Global Root G2, ISRG Root X1, ISRG Root YR). They are public
certificates used only as an additive fallback for HTTPS update downloads on old Android versions.

## D. Services contacted by the app

Cloudflare (`cloudflare-dns.com`, `security.cloudflare-dns.com`), Google (`dns.google`) and Quad9
(`dns.quad9.net`) for encrypted DNS; `raw.githubusercontent.com` for blocklists and the signed threat
pack; `big.oisd.nl` only if OISD is enabled. These are third-party services under their own terms.

---

# Detalle de listas de dominios (español)

Hydra es software libre bajo GPL-3.0 (ver LICENSE). Este archivo lista las listas de
dominios de terceros que usa la app, separadas según si van **empaquetadas dentro
del APK** (sección 1) o si la app las **descarga en el teléfono** después de instalada
(sección 2). La diferencia importa porque empaquetar un archivo de otro autor dentro
del APK es redistribuirlo, y ahí aplican las condiciones de su licencia.

Este documento es un resumen de buena fe, no asesoramiento legal.

## 1. Empaquetado en el APK (app/src/main/assets/blocklist.txt.gz)

A partir de esta versión, blocklist.txt.gz ya **no** usa la lista unificada de
StevenBlack/hosts, porque esa lista agrega fuentes con licencias no comerciales
(MVPS, Dan Pollock) o de tipo compartir-igual (KADhosts) y otra sin licencia
declarada (pgl.yoyo.org), incompatibles con redistribuir dentro de un APK GPL-3.0.

En su lugar, blocklist.txt.gz se genera combinando solo fuentes con licencia
permisiva o CC0/CC BY, que sí permiten esta redistribución:

| Fuente | Licencia | Origen |
|---|---|---|
| Steven Black's ad-hoc list | MIT | https://github.com/StevenBlack/hosts/blob/master/data/StevenBlack/hosts |
| AdAway | CC BY 3.0 | https://github.com/AdAway/adaway.github.io |
| add.2o7Net (FadeMind hosts.extras) | MIT | https://github.com/FadeMind/hosts.extras |
| add.Dead (FadeMind hosts.extras) | MIT | https://github.com/FadeMind/hosts.extras |
| add.Risk (FadeMind hosts.extras) | MIT | https://github.com/FadeMind/hosts.extras |
| add.Spam (FadeMind hosts.extras) | MIT | https://github.com/FadeMind/hosts.extras |
| UncheckyAds (FadeMind hosts.extras) | MIT | https://github.com/FadeMind/hosts.extras |
| Mitchell Krog's Badd Boyz Hosts | MIT | https://github.com/mitchellkrogza/Badd-Boyz-Hosts |
| hostsVN | MIT | https://github.com/bigdargon/hostsVN |
| minecraft-hosts (tracking list) | CC0-1.0 | https://github.com/jamiemansfield/minecraft-hosts |
| Tiuxo hostlist - ads | CC BY 4.0 | https://github.com/tiuxo/hosts |

**Atribución (requerida por CC BY):**
- AdAway — © Kicelo, Dominik Schuermann y colaboradores. https://adaway.org/
- Tiuxo hostlist - ads — © tiuxo. https://github.com/tiuxo/hosts

Las fuentes MIT y CC0 no requieren atribución para redistribuir, pero se listan
igual por transparencia. El texto completo de MIT está en
`third_party/licenses/MIT`.

**Deliberadamente excluidas de este paquete** (y por qué):
- StevenBlack/hosts, variante unificada — incluye, aguas arriba, MVPS y Dan Pollock.
- MVPS hosts file (winhelp2002.mvps.org) — CC BY-NC-SA 4.0, solo uso no comercial;
  incompatible con que cualquiera pueda redistribuir y usar comercialmente el APK
  bajo GPL-3.0.
- Dan Pollock / someonewhocares.org — licencia no comercial con atribución; mismo
  conflicto que MVPS.
- KADhosts — CC BY-SA 4.0 (compartir-igual). No es imposible de combinar con
  GPL-3.0, pero exige tratamiento cuidadoso aparte; se deja fuera del paquete
  bundleado hasta resolverlo explícitamente.
- pgl.yoyo.org — no declara licencia; sin permiso explícito no hay base para
  redistribuirla dentro del APK.

Dominios totales en este paquete: ver `domainCount` en
`app/src/main/assets/blocklist_meta.json` (generado junto con este archivo).

## 2. Descargado por la app (no empaquetado)

Estas fuentes no viajan dentro del APK. El teléfono las descarga directamente
desde el servidor del autor cuando el usuario actualiza las listas, así que
Hydra no las redistribuye: la licencia de cada una aplica entre su autor y el
usuario final.

- HaGeZi Multi PRO mini — GPL-3.0. https://github.com/hagezi/dns-blocklists
- HaGeZi Threat Intelligence mini — GPL-3.0. https://github.com/hagezi/dns-blocklists
- 1Hosts Lite — MPL-2.0 (según los metadatos del repositorio). https://github.com/badmojr/1Hosts
- URLhaus, Feodo Tracker, ThreatFox (abuse.ch) — CC0. El pack de amenazas firmado
  que arma `tools/build_hydra_threat_pack.py` sí se publica en el repositorio de
  Hydra, es decir, sí se redistribuye; como las fuentes de abuse.ch son CC0 esto
  no genera conflicto, pero conviene reconfirmar sus términos vigentes antes de
  cada publicación del pack.
- OISD — términos a confirmar antes de ofrecerla como fuente.

Condiciones que siguen aplicando igual, aunque sea por descarga y no por empaquetado:
- Las licencias no comerciales (MVPS, Dan Pollock) solo cubren uso no comercial;
  si alguien hiciera un fork de pago de Hydra, bajar esas listas dejaría de encajar
  con su licencia.
- No deben quedar copias de estas listas guardadas en el repositorio de Hydra ni
  en ramas como `threat-pack`; guardarlas ahí sería redistribuirlas.

## Cómo se regeneró blocklist.txt.gz

Generado el día indicado en `blocklist_meta.json` con `tools/rebuild_bundled_blocklist.py`,
que descarga cada fuente de la tabla de la sección 1 directamente desde su raw URL en
GitHub, extrae los dominios (formato hosts `0.0.0.0 dominio` / `127.0.0.1 dominio`, o
lista plana de dominios según la fuente), unifica y quita duplicados, y escribe
`app/src/main/assets/blocklist.txt.gz` y `blocklist_meta.json`. El proceso es repetible:

```bash
python3 tools/rebuild_bundled_blocklist.py
```

Usá `--dry-run` para ver el resumen sin escribir archivos, o `--offline NOMBRE=ruta`
(repetible) para usar una copia local de alguna fuente en vez de descargarla.
