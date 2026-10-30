## Sin publicar
- PIN: los PIN nuevos o cambiados deben tener de 5 a 8 dígitos (los PIN de 4 dígitos existentes siguen funcionando hasta que se cambien).
- PIN: el tiempo de espera tras intentos fallidos se mide con el reloj monotónico del sistema, así que cambiar la fecha del teléfono ya no lo acorta.
- README en español reescrito por completo y alineado con el README en inglés; capturas de pantalla agregadas; sección "Qué hace la IA incorporada"; lista completa de permisos; aclaración de que la cuarentena es opcional.

## 1.0.0 — primera versión para prueba cerrada (versionCode 163)
- Corregido el `applicationId` para que el AAB coincida con el paquete creado en Google Play Console: `com.hydra.firewall`.
- Preparación del paquete de lanzamiento para la prueba cerrada de Google Play.
- El historial que sigue documenta builds locales de desarrollo; esta es la primera candidata que se enviará a Play Console.
- Configuración de compilación y destino actualizada a Android 16 (API 36).
- Etiqueta y nombre de versión sincronizados a `Hydra Firewall - V1.0.0` / `1.0.0`.
- Herramientas de compilación actualizadas a Android Gradle Plugin 8.10.1, Kotlin 2.2.21 y Gradle 8.11.1 para compatibilidad con API 36.

## 1.5-beta6-final-r13 — FIX174 (versionCode 163)
- Seguridad: el analizador DNS (`DnsWireParser`) era recursivo y un puntero de compresión circular provocaba `StackOverflowError`; ahora es iterativo con límites. Tests: DnsWireParserTest.
- Seguridad: se quitó la atribución de UID por IP de destino compartida (CDN); sin UID la conexión se bloquea.
- Pack de amenazas: una sola clave pública por defecto (la que verifica el pack incluido); variables de entorno vacías se tratan como ausentes. Test: ThreatKeyConsistencyTest.
- Motores TCP IPv4/IPv6: cola de paquetes acotada (2048 paquetes / 4 MB) y drenaje por lotes.
- VPN: rutas NAT64 (64:ff9b::/96 y 64:ff9b:1::/48) para no dejar fugas en redes DNS64.
- Resolución de UID en Android 7–9: espera máxima en el hilo del motor reducida de 535 ms a 85 ms.
- Ayuda y docs: "Bloquear todo" explica sus excepciones.
- UI: botones del prompt de primera conexión en una sola línea con fuente que se ajusta (ya no se corta "PERMISSIVE").
- Idioma: con "Sistema" y el teléfono en inglés ahora toda la app usa inglés (antes solo con "English" forzado). Traducidos PERSONALIZED/PERMISSIVE/NO FIREWALL/Details en la lista de reglas, "Allow/Block by default" y las descripciones de canales de notificación.
- Tests: corregidos 2 tests que ya fallaban (org.json de tests, aserción de checksum).
- README en inglés ampliado, THIRD_PARTY_NOTICES con librerías, datos y servicios.

## 1.5-beta6-final-r13 — FIX172 (versionCode 161)
- Aviso de primera conexión: la descripción de ESENCIAL se cortaba ("…con compatibilidad más"). Ahora dice "Pasa por HYDRA con más compatibilidad." y las descripciones admiten hasta 3 líneas.

## 1.5-beta6-final-r13 — FIX171 (versionCode 160)
- Reglas: "Usuario" es el primer botón y el filtro inicial; "Todas" y "Sistema" muestran el aviso de apps de sistema.
- Reglas: descripción de cada app en versión corta (máx. 2 líneas) para que entren más apps en pantalla; el detalle largo sigue en el diálogo de la app.

## 1.5-beta6-final-r13 — FIX170 (versionCode 159)
- Reglas: buscador compacto (36 dp, con ✕ para borrar) que ya no se superpone con los botones de filtro.

## 1.5-beta6-final-r13 — FIX169 (versionCode 158)
- Corregido: "Buscar actualización" de la lista de amenazas + publicidad decía siempre que había una versión nueva aunque ya estuviera instalada. Comparaba la fecha de una sola fuente contra las fechas de todas unidas y el total de dominios combinado contra el de esa fuente. Ahora se guarda la fecha de cada fuente al instalar y se compara fuente por fuente. Test: BlocklistUpdaterTest.
- Nota: la primera comprobación tras actualizar a esta versión ofrecerá actualizar una vez (todavía no hay fechas guardadas); al aplicarla, las siguientes dirán "ya está actualizado".

## 1.5-beta6-final-r13 — FIX168 (versionCode 157)
- Corregido: el mismo aviso de primera conexión se abría varias veces apilado (había que elegir la regla varias veces). Ahora hay una sola ventana por solicitud (NEW_DOCUMENT + data único), las copias duplicadas se cierran y una ventana obsoleta se cierra sola al reanudarse. Se quitó MULTIPLE_TASK, que era contraproducente.
- La pestaña inicial es Protección.
- Botón claro/oscuro (icono mitad negro/mitad blanco) arriba a la derecha, en la misma fila del encabezado.

## 1.5-beta6-final-r13 — FIX167 (versionCode 156)
- Corregido: con varias solicitudes de acceso acumuladas en las notificaciones, tocar una no abría el aviso (Android trataba todos los intents como iguales porque solo cambiaban los extras). Ahora cada solicitud tiene su propio intent y ventana. Si la solicitud ya estaba resuelta, se avisa y se limpia la notificación.

## 1.5-beta6-final-r13 — FIX166 (versionCode 155)
- Reglas: "Todas" ahora muestra todas las apps (usuario y sistema) y reinicia los filtros; los filtros se pueden desactivar tocándolos de nuevo.
- Botones: seleccionados con color, no seleccionados en gris.

## 1.5-beta6-final-r13 — FIX165 (versionCode 154)
- Reglas: se quitó el interruptor "Sistema" (lo reemplaza el botón Sistema) y los botones de orden; el orden es siempre por nombre. "Apps de confianza" pasó a ser el botón "Confianza ✓" junto a los filtros, con el botón ↻ de actualizar.

## 1.5-beta6-final-r13 — FIX164 (versionCode 153)
- Aviso de primera conexión: Wi‑Fi y Móvil arrancan ACTIVADOS por defecto (si la app ya tiene regla explícita se respeta).
- Reglas: al permitir una app sin regla propia se activan Wi‑Fi y móvil juntos; al apagar una red ya no se pierde silenciosamente la otra.
- Ayuda revisada: interruptor VPN en Protección, modo normal/avanzado, aviso de primera conexión, Bloquear IPv6, exportar/importar, tarjetas de consumo y paquete de amenazas; numeración automática.

## 1.5-beta6-final-r13 — FIX163 (versionCode 152)
- Interruptor **Modo normal/avanzado** también en la pestaña Protección.
- Encabezado compacto: el estado de protección aparece una sola vez (ACTIVADA / PARCIAL / DESACTIVADA).
- Reglas: botones y filtros más bajos, campo de búsqueda más chico, texto largo de "Apps de confianza" solo en modo avanzado y aviso "▼ hay más abajo" cuando la lista continúa.

## 1.5-beta6-final-r13 — FIX162 (versionCode 151)
- Nuevo: **Modo normal / avanzado** (Ajustes). Normal (por defecto) oculta IP/Puertos, Analizador, Perfiles y Prueba; avanzado muestra todo. Las reglas existentes siguen activas.

## 1.5-beta6-final-r13 — FIX161 (versionCode 150)
- Nuevo: ajuste **Bloquear IPv6** (Ajustes). Descarta todo el tráfico IPv6 en el túnel, con efecto inmediato; las apps pasan a IPv4, donde aplican todos los filtros.

## 1.5-beta6-final-r13 — FIX160 (versionCode 149)
- Corregido: en el aviso de primera conexión, al abrir **PERSONALIZADO** los interruptores se superponían. La pantalla solo se desplazaba con "Detalles" abierto; ahora también se desplaza con "Personalizado" abierto.

## 1.5-beta6-final-r13 — FIX159 (versionCode 148)
- ID de la app: `com.hydraroot.firewall` (**reinstalación**: exportá antes la configuración).
- Nuevo: exportar/importar configuración (por nombre de app) con deshacer; incluye apps Esenciales.
- Nuevo: "¿Por qué se conecta?" en el aviso de primera conexión y en el historial.
- Nuevo: consumo por app (sesión / hoy / 7 días) con banderas.
- Nuevo: tarjeta de estado del pack de amenazas con "Actualizar ahora".
- Tests: +80 (DNS, TLS, JA3, checksum, JSON, respaldo, explicador, consumo, estado del pack). Detalle: `docs/history/FIX159-EXPORT-EXPLAIN-USAGE-PACKSTATUS.md`.

## 1.5-beta6-final-r12 — FIX158 (versionCode 147)
- Build: firma de release configurable, `build.sh`, CI de GitHub, script PowerShell que ya no pisa `local.properties`.
- Amenazas: generador de packs con Feodo/URLhaus/ThreatFox, lista anti falsos positivos, feed por defecto configurable en build, claves propias.
- YARA‑Lite: condiciones sobre todo el APK, coincidencia UTF‑16 y modificadores combinados; reglas semilla ajustadas (menos falsos positivos).
- Tests: `SecurityRiskEngineTest` volvía a compilar; nuevas regresiones YARA y del generador.
- Docs: README y guías nuevas; historial movido a `docs/history/`. Detalle: `docs/history/FIX158-BUILD-THREATS-DOCS.md`.

## 1.5-beta6-final-r11-custom — PERSONALIZADO

- Added a new per-app `PERSONALIZADO` mode in Rules, positioned before `ESENCIAL`.
- Added per-app protection switches for: ads/trackers, Secure DNS, HTTPS SNI, QUIC, TLS fingerprint (JA3/JA3N), known threats, and local-network blocking.
- `PERSONALIZADO` keeps the app inside HYDRA/VPN; Wi-Fi and Mobile permissions remain separate.
- Added the same `PERSONALIZADO` choice to the first-connection prompt so a user can select the protection profile at approval time.
- Existing `PERMITIR`, `ESENCIAL`, `SIN FIREWALL`, and prompt behavior remain otherwise unchanged.
- Custom protection profiles are persisted per UID and can be edited again from the app rule details.
- Build version synchronized to versionCode 144 / versionName `1.5-beta6-final-r11-custom`.


## 1.5-beta6-final-r10 — FIX154/FIX155
- Prompt flow: repeated TCP SYNs for the same 5-tuple now retry the pending prompt instead of returning silently.
- Prompt Activity is reordered to the foreground rather than stacking duplicate screens.
- Quarantine BLOCK/BLOCK is now marked as a quarantine default, so it remains blocked but still qualifies for first-connection review.
- Pending quarantine entries from older builds are migrated to the new marker.
- ESENCIAL and ESENCIAL-COMPAT explicitly start with Wi-Fi + mobile enabled when selected from Rules/Details.
- ESENCIAL recognition also honors the persisted compatibility mode directly.
- Transient Android 7 UID misses no longer cause an immediate TCP RST; the SYN is dropped fail-closed while UID recovery can observe the socket on retransmission.
- Added prompt suppression diagnostics.
# FIX152 — Prompt reliability + ESENCIAL connectivity

- Every new app/UID/network prompt now opens its own decision Activity even when another prompt is already pending; each remains independently represented in the notification queue.
- Android 7 first-connection UID attribution now retries `/proc/net` for ~535 ms and schedules a bounded background recovery when the socket is still not visible, preserving fail-closed behavior until a real UID is resolved.
- ESENCIAL now grants effective connectivity inside HYDRA when no explicit Wi‑Fi/Mobile rule exists, while explicit rules, schedules, advanced rules and strong threat/IP/global protections remain authoritative.
- User Essential apps now bypass the normal public ad/tracker domain filter when their network is effectively allowed.
- Access-request notifications use high/default-to-interruptive priority.

# FIX152 — Prompt reliability + Android 7 UID attribution

- Fixed a prompt regression where `FirewallVpnService.onCreate()` could cancel
  all current access-request notifications during a VPN service restart.
- Added restoration of pending access-request notifications when the service is
  recreated while the app process still owns the pending queue.
- Changed queued prompt Activity launch mode from `singleTop` to `standard` so
  tapping a second app notification cannot reuse the first prompt screen with
  a stale token.
- Replaced hash-only prompt notification IDs with collision-resistant in-process
  allocation, so separate pending prompts cannot overwrite each other.
- Extended Android 7–9 `/proc/net` UID attribution retries from ~26 ms to a
  bounded 110 ms window to reduce transient INVALID_UID -> BLOCK before the app
  socket appears in the kernel table.
- Added `UID_RESOLUTION_FAILED` diagnostic logging for remaining attribution
  failures; unresolved identities still fail closed and are never auto-prompted.

VersionCode: 140
VersionName: 1.5-beta6-final-r7

- Fixed the Rules → **Hacer esencial** action for never-configured apps: it now
  explicitly grants Wi‑Fi + Mobile instead of copying the default BLOCK/BLOCK
  state into an Essential profile. Existing explicit user restrictions remain
  unchanged.
- The **ESENCIAL-COMPAT** diagnostic button similarly grants both networks only
  when the app has no explicit rule, so a default-blocked app can actually be
  tested through the VPN without silently overriding a deliberate block.


## BUILD 1.5-beta6-final-r6 — versionCode 139

## FIX151 — ESSENTIAL-COMPAT diagnostic mode
- Added per-app **ESENCIAL-COMPAT** diagnostic mode. The app remains inside HYDRA/VPN; it is not a SIN FIREWALL exclusion.
- In ESENCIAL-COMPAT, the normal public ad/tracker domain blocklist is bypassed at DNS, TLS SNI and QUIC checks so compatibility can be tested without removing the app from the VPN.
- Explicit user domain **BLOCK** rules and confirmed threat/IP/domain protections remain authoritative.
- Added visible **Probar ESENCIAL-COMPAT / Volver a ESENCIAL** control in per-app Details and diagnostic log events for every bypass.
- Switching from SIN FIREWALL back to ESENCIAL/ESENCIAL-COMPAT forces a controlled VPN Builder rebuild so the app is re-included in the TUN.

## BUILD 1.5-beta6-final-r5 — versionCode 138

## FIX150 — Rules visual state + Details close action
- Added a fixed **Cerrar** action in the per-app Details dialog so it remains accessible while the details body is scrolled.
- Rule status colors now follow effective network access: **green** for Wi-Fi + mobile, **yellow** for exactly one network, **red** for neither.
- `SIN FIREWALL` uses a **dark blue** visual state.
- The same visual policy is used for normal rules and **ESENCIAL**, so changing one network off immediately changes the status color.

## BUILD 1.5-beta6-final-r4 — versionCode 137

## FIX137 — Prompt, trusted-apps and per-app policy polish
- Fresh/unconfigured application UIDs remain BLOCKED until the first-connection prompt is resolved.
- Removed broad automatic essential treatment for ordinary system/Google packages; only core Android UIDs 1000/1001 stay automatic essentials.
- Added an optional global **Apps de confianza** switch in RULES, OFF by default. When enabled, apps installed by Google Play or platform-signed system apps may be auto-allowed.
- Added per-app **Reset rule (ask again)** so an explicit rule can be cleared without erasing unrelated settings.
- Made compatibility modes mutually exclusive across Rules and prompts: NORMAL/ESSENTIAL/SIN FIREWALL cannot remain active together.
- Centralized rule descriptions and added immediate action feedback via Toast.

# FIX149 / Final policy polish

- `SIN FIREWALL` and `ESENCIAL` are now mutually exclusive and synchronized across Rules, details, and first-connection prompts.
- Switching from `SIN FIREWALL` to `ESENCIAL` re-includes the app in the VPN through a controlled rebuild; switching the other way excludes it and clears user-essential state.
- Rules now show an immediate plain-language description of the active network behavior.
- Wi-Fi and Mobile switches remain independently editable for PERMITIR/ESENCIAL and are explicitly marked not applicable under SIN FIREWALL.
- Details now refresh immediately after policy changes and display the current compatibility mode.

# V1.5-beta6-final — compatibility toggle fix

- Fixed `SIN FIREWALL` visual state not recomposing in Rules when its persisted mode changed.
- Fixed the retired Mercado Pago beta diagnostic selection being carried into the final build on upgrade; it is cleared once on first launch of this final build.
- No Mercado Pago-specific runtime bypass/test mode remains in the production policy.
- `SIN FIREWALL` remains a generic per-app user-controlled compatibility mode.

# HYDRA Firewall — Final

## FINAL-STATE-FIX
- Fixed `SIN FIREWALL` Rules state persistence/activation.
- Compatibility EXCLUDED/NORMAL now use a controlled VPN rebuild inside `FirewallVpnService`.
- Persisted compatibility mode is committed before VPN reconstruction.

# V1.5-beta6-final — product polish

- Removed the temporary Mercado Pago compatibility test and its app-specific normal-domain bypass.
- Removed Mercado Pago-only diagnostic UI/instrumentation from the product build.
- Retained generic HYDRA self-test, live connectivity test, and ADB-readable diagnostics.
- Normal domain filtering is now uniformly enforced; per-app compatibility uses only NORMAL / ESSENTIAL / SIN FIREWALL.
- Final networking hardening keeps upstream sockets bound to the selected physical network before VPN-loop protection.
- VersionCode: 133.

# FIX147 — Mercado Pago network diagnostics

- Added a Mercado Pago-specific observational diagnostic ring buffer and counters.
- Captures TCP/UDP/QUIC/TLS/DNS events, policy/security blocks and VPN network capabilities without changing routing.
- Added VPN/physical-network state sampling around VPN startup, including interface, validation and DNS state.
- Added compact diagnostics to the `PRUEBA` screen with recent events and counters.
- Re-activating the Mercado Pago test starts a clean diagnostic capture.
- Synchronized `versionCode`, `versionName` and `BUILD_LABEL` to FIX147.

## FIX144 — Secure DNS diagnostics + Android 7 trust
- Secure DNS DoT/DoH sockets use HYDRA merged TLS trust.
- Live test reports configured VPN DNS and recent Secure DNS stages on normal-DNS failure.

## FIX133 — Android 7 self-test crash fix
- Replaced `java.nio.file.Files.createTempFile()` in the PRUEBA self-test with `java.io.File.createTempFile()` for minSdk 24 compatibility.

# FIX132 — Prueba en vivo (real, opt-in)

- Added HydraLiveTest + FirewallVpnService.setLiveTestMode(): temporarily includes HYDRA's own package in the tunnel to run a real DNS-block/allow + TCP handshake check end-to-end. See FIX132-LIVE-TEST.md.

# FIX131 — Pestaña PRUEBA (self-test)

- New SELFTEST tab running HydraSelfTest.runAll(): operational status + synthetic-packet checks against real ICMPv4/DNS/TLS/checksum/UID-parsing code. See FIX131-SELF-TEST-TAB.md.

# FIX128 — Audit fixes

- Prompt Wi‑Fi preselection, SIN FIREWALL no longer writes allow rules, system DNS allowed, link-local DNS filtered, test/build fixes. See FIX128-AUDIT-FIXES.md.

## 1.5-beta6-fix124 — Prompt regression + non-app UID suppression

- Fixed BLOQUEAR so it persists an explicit deny rule instead of merely dismissing the prompt.
- Prevented first-connection prompts for Android/system/root UIDs and unresolved non-application identities; these now fail closed.
- This removes the repeated `Aplicación desconocida / UID 0` prompt regression seen after FIX123.

# FIX123 — prompt queue + full labels + per-request notifications

- First-connection prompts keep the compact icon + app name + action-button layout; detailed network/identity/permissions/decision data stays grouped behind `+ Detalles`.
- Prompt action labels are full words: `PERMITIR`, `ESENCIAL`, `COMPATIBILIDAD`, `BLOQUEAR`.
- App label/icon resolution falls back through shared-UID packages so the prompt still shows the application identity on Android 7.
- Pending prompts are no longer collapsed into one notification: every unresolved app/UID/network request gets its own persistent notification and can be opened independently.
- Only the first pending request auto-opens as a full-screen/activity prompt; later requests stay queued in separate notifications so one decision does not overwrite another.
- Resolving/canceling one request removes only that request's notification and leaves the other pending requests intact.
- Notification PendingIntents are unique per request.

# FIX120 — DNS configuration + IPv4 ICMP diagnostics

# FIX119 — ADB-readable diagnostic log

- DiagnosticLogger also writes to files/hydra-diagnostic.log (pull with adb), rotated at 3 MB.
- Throttled repetitive policy/DNS events, DNS_QUERY/DNS_RESPONSE lines.
- MercadoPago diagnostic exclusion set back to false.

# FIX118 — Diagnostic MercadoPago exclusion (temporary)

# FIX117 — /proc/net UID column

- Corrected Android 7–9 UID parsing: UID is column 7 of a data row (column 8 is `timeout`).
- Test fixture replaced with real kernel format.

# FIX116 — Essential App Mode

- Added user-selected Essential mode from Rules and first-connection prompts.
- Essential keeps the app inside HYDRA while bypassing normal app-level filters.
- Critical threat/IP controls and global kill-switch remain authoritative.

# FIX115 — Prompt persistence, system essentials and full connectivity

- Persistent notification for pending first-connection prompts; grouped requests remain recoverable from the notification bar.
- UID-shared permissions and application/process details are shown together.
- System apps remain hidden by default; conservative auto-essential system roles can be allowed without exposing every system package.
- Explicitly allowed apps now bypass optional Secure DNS interception, normal ad/tracker blocklists and optional TLS fingerprint blocking while threat/IP/global security controls remain authoritative.
- Global Block All now blocks even essential UIDs.

# FIX114 — App policy defaults + grouped access requests
- Shared-UID access prompts now show the related packages/icons and grouped network attempts remain tied to one UID/network decision.

- New apps default to BLOCK until an explicit per-UID rule allows them.
- System apps hidden by default; duplicate Settings control removed.
- First-connection requests grouped by UID/network across TCP/UDP/IPv4/IPv6.
- Access screen now shows icon, label, package, UID, grouped attempts and grouped declared Android permissions.
- Added APP_POLICY_DECISION diagnostics to identify the exact reason a connection is blocked.

# FIX113 — Protected App Compatibility

- Added per-application protected compatibility policy.
- Enabled `com.mercadopago.wallet` by default for this Android 7 compatibility test.
- Keeps app firewall, kill switch, explicit blocks and confirmed threats authoritative.
- Bypasses only normal ad/tracker domain blocklists, HYDRA Secure DNS interception and optional JA3 blocking for the compatibility app.
- Added physical-network tracking with `NET_CAPABILITY_NOT_VPN` and VPN underlying-network updates.

# HYDRA CHANGELOG

## 1.5-beta6-fix112-app-connection-affinity
- Android 7–9 legacy UID attribution now uses a bounded `/proc/net` retry and does not negative-cache transient INVALID_UID results.
- Explicitly allowed apps no longer get made effectively offline by normal ad/tracker domain blocklists at DNS, TLS SNI, or QUIC correlation layers.
- Threat intelligence, explicit custom BLOCK rules, IP threat indicators, global Block All, and advanced firewall policy remain authoritative.

# FIX109 — Security 5 points

## FIX107 — Build fixes

- Fixed compile errors in ThreatIntelDomainStore integration, CustomDomainRuleStore, DnsIpCorrelationStore and NotificationHelper.


## FIX106 — Security completion
- Live HaGeZi Threat Intelligence domains are separated from generic blocklists and fed into the Threat Signature decision path.
- Custom domain rules remain available with threat signatures taking precedence over ALLOW.
- QUIC/UDP 443 now gets best-effort domain correlation from recent DNS answers, plus existing destination-IP threat blocking.
- Separate local Privacy/Tracking AI signal added; it is not a malware verdict.
- Serious threat notifications remain HIGH/CRITICAL only; ad/tracker blocks stay silent.
- VPN recovery and Direct-Boot-aware recovery retained.
# FIX104

Android 7 updater TLS compatibility: merged platform roots with additive compatibility roots and the current DigiCert Global G2 TLS intermediate; hostname verification remains enabled.


## FIX105 — Android 7 TLS Root YR compatibility
- Added cross-signed Let's Encrypt Root YR to updater-only trust bundle.
- Preserved hostname verification and merged system + extra public roots.
- Fixed current Generation Y certificate-chain compatibility for legacy Android devices.

## FIX110 — MH-100K static APK AI

- Integrated `hydra-apk-ai-mh100k-v2` (2,048-feature FNV-1a-64 logistic model) as a local secondary APK-security signal.
- Added bounded DEX `invoke-*` API extraction plus permission/intent feature extraction compatible with the supplied feature vocabulary.
- Added MH-100K score display to Security Center and APK scan history.
- The model never blocks or overrides deterministic Hydra security decisions.
- Incomplete static extraction suppresses the model score so unknown/unscanned content is not treated as feature absence.

## FIX112 — App connection affinity

- Corrected Android 7 `/proc/net` UID parsing to read the actual UID column (column 8 when `sl` is retained).
- Added a strict unique-local-endpoint fallback when the exact remote tuple is not visible yet.
- Added short-lived per-app source-endpoint attribution recovery for Android 7+ legacy UID misses.
- Added DNS-answer-to-destination-IP attribution fallback when exactly one explicitly allowed UID is eligible.
- Passed active network context into UID resolution so affinity is only used for a UID explicitly allowed on that network.
- Kept threat intelligence, explicit BLOCK rules, kill-switch, advanced rules and schedules authoritative.
- Normal app allow still bypasses ordinary ad/tracker blocklists as established by FIX111.
## FIX115 build fix — NotificationCompat category

- Replaced the unavailable `NotificationCompat.CATEGORY_PERMISSION` constant with `NotificationCompat.CATEGORY_EVENT` in the persistent grouped access-request notification.
- No behavior change to grouping, pending-request persistence, firewall policy, or security decisions.


## FIX137 — live test compile fix
- Restored missing `tcpConnectivityCheck()` removed accidentally from FIX136.
- No behavioral changes to PERMITIR / ESENCIAL / SIN FIREWALL / BLOQUEAR.


## FIX142 — Secure DNS TLS trust fallback + VPN DNS diagnostics
- Retry encrypted DNS TLS with HYDRA's merged public-root compatibility trust only after platform TLS handshake failure.
- Log VPN DNS LinkProperties after establish() to catch Android 7 empty-DNS tunnel state.

## Final compile fix

Fixed Kotlin `Unresolved reference: bindUpstreamSocketToPhysicalNetwork` in the
IPv4/IPv6 TCP/UDP forwarding engines by adding a concrete-service compatibility
bridge.

## r11-custom-fix1 — compile fix
- Added the missing `CustomProtectionProfileStore` import to `AppAccessRequestActivity`.
- Marked the nested `row()` composable helpers with `@Composable` in `MainActivity` and `AppAccessRequestActivity`.
- No functional changes to PERSONALIZADO, existing modes, or firewall policy.

## FIX158 — SYSTEM DNS DEFAULT
- System/netd DNS on TCP/UDP port 53 is permitted by default for system UIDs when the destination is a configured resolver or a local RFC1918/link-local resolver.
- Applied to both `evaluateApplicationPolicy()` (DNS preflight) and `evaluate()`.
- Global kill-switch, explicit IP blocks, and confirmed threat matches remain authoritative.
- Added `SYSTEM_DNS_DEFAULT` diagnostics.
- VersionCode 146.
