## 3.6.4 (versionCode 30604)
Selector de seis temas visuales, con preferencias persistentes e independencia entre paleta y modo claro/oscuro.
- **Temas:** Neon Tech, Dark Premium, Light Modern, Cyber Orange, Material Modern y Glass Green; cada uno dispone de variante clara y oscura.
- **Preferencias:** el tema elegido se guarda localmente; se conserva el selector Sistema/Claro/Oscuro existente.
- **Consistencia:** la pantalla principal y los avisos de primera conexión utilizan el mismo tema seleccionado.
- **Alcance:** cambios exclusivamente visuales; no se modifica el motor VPN, IPv4/IPv6, TCP/UDP, DNS, SNI, reglas ni actualizadores.

## 3.6.3 (versionCode 30603)
Refresh visual identity with the Neon Tech interface. No firewall, VPN, packet-processing, DNS, SNI, rule, or security decision behavior is intentionally changed.
- **Theme:** dark navy surfaces, cyan/turquoise accents, refined typography and rounded component shapes.
- **Consistency:** shared cards, segmented controls, dialogs, navigation and security section chips use the same palette.
- **Preference:** fresh installs start in the dark Neon Tech theme; an existing explicit light/dark/system choice is preserved.

## 3.6.2 (versionCode 30602)
Unificación de políticas compartidas entre IPv4 e IPv6, sin mezclar los formatos de paquete específicos de cada familia.
- **SNI/TCP:** IPv4 e IPv6 usan ahora el mismo inspector y la misma decisión de amenazas, reglas de dominio personalizadas, blocklist pública, compatibilidad y ajuste SNI.
- **Reensamblado TCP:** la inspección SNI se ejecuta después de entregar datos en orden desde `TcpReassembly`, también en IPv6. Antes IPv6 inspeccionaba segmentos TCP sin reensamblar, por lo que el ClientHello podía llegar fuera de orden y no producir la misma decisión que IPv4.
- **DNS:** las decisiones de bloqueo por amenaza, regla de usuario y blocklist opcional usan una única tabla de política compartida por IPv4/IPv6.
- **Analizador de tráfico:** IPv6 vuelve a registrar conexiones TCP/UDP y datos TCP/QUIC en el analizador local opt-in, igual que IPv4. El límite y la opción de activación del analizador no cambian.
- **Arquitectura:** `IpParser` sigue clasificando cada paquete una sola vez. Los adaptadores TCP/UDP y los constructores IPv4/IPv6 permanecen separados porque sus cabeceras, checksums y límites son distintos; se comparte la política, no se procesa dos veces el mismo paquete.
- **Pruebas:** se agregan pruebas para la precedencia de amenazas, reglas explícitas, bypass de blocklist y switch SNI.

## 3.6.1 (versionCode 30601)
Correcciones de publicación y de la cadena de actualización.
- **Red de actualizaciones:** el pack de amenazas, las listas de dominios y el actualizador de Hydra usan exclusivamente conexiones abiertas sobre una red física explícita. Se elimina la alternativa de la red predeterminada, que podía ser la propia VPN.
- **Redirecciones:** los tres actualizadores siguen manualmente hasta 3 redirecciones HTTPS y mantienen cada salto en la misma red física. Se rechazan los descensos a HTTP, credenciales embebidas y bucles.
- **Pruebas:** se agregan tests unitarios para la política de redirecciones HTTPS.
- **Publicación:** se incorporan workflows de GitHub Actions para pruebas Android/Python, APK de depuración, Releases firmadas con los secrets configurados y publicación diaria del pack firmado (si está configurada la clave).
- **Documentación:** se sincronizan las funciones y la versión de los README, la guía de compilación, permisos y versionado; se agregan `.gitignore` y `.gitattributes`.
- **Ayuda y guías:** se corrigen los filtros de Apps y se eliminan las referencias a la pestaña Prueba y al modo Permissive-compat retirados.

## 3.6.0 (versionCode 30600)
Recorte de funciones de bajo valor o con riesgo.
- **Limpieza:** el parser del ClientHello ya solo extrae el SNI (se quitan cifrados, extensiones, curvas, ALPN y versiones que solo usaba JA3).
- **Privacidad:** el log de diagnóstico (`hydra-diagnostic.log`) ya no se escribe en builds release y se borra el que hubiera de versiones anteriores.
- **Se quita** el autotest y el «modo de prueba en vivo» (incluía un `ALLOW` incondicional para el UID propio en `RuleEngine`).
- **Se quita** la huella TLS (JA3/JA3N/Hydra-lite): estaba apagada y sin UI desde la 2.3.0. El parser del ClientHello se conserva como `TlsSniInspector` porque alimenta el bloqueo por SNI (IPv4 e IPv6).
- **Se quita** el aprendizaje local de comportamiento (`AppBehaviorBaselineStore`). La correlación de comportamiento y los puntajes de IA se mantienen.
- **Escáner de APK:** se quita la búsqueda de cadenas en los DEX (WebView, `addJavascriptInterface`, URLs…), principal fuente de falsos positivos. Permisos, componentes exportados, firmas de amenazas y MH-100K no cambian.
- **Modos por app:** se retira `ESSENTIAL_COMPAT` (se comportaba como `ESSENTIAL`); lo guardado y los backups viejos se migran a `ESSENTIAL`.
- **Se quita** «Apps de confianza» (auto-permitir apps instaladas desde Play). Quien lo tenía activo vuelve a recibir el aviso de primera conexión.
- **Listas de dominios:** se siguen hasta 3 redirecciones, solo hacia HTTPS.
- La unificación de motores IPv4/IPv6 no forma parte de esta versión; la huella digital sigue siendo una comodidad sobre el PIN, no una barrera criptográfica.

## 3.4.8 (versionCode 30408)
- **Seguridad — bloqueo por SNI:** el inspector de TLS se rendía a los 8 KB, así que una app podía rellenar el ClientHello (padding) para que no se leyera el SNI y evadir el bloqueo por dominio. El tope pasa a 16 389 bytes (un registro TLS completo). Sigue sin verse el SNI si el ClientHello se parte en varios registros, usa ECH o no trae SNI (límite inherente de no descifrar). Test nuevo con un ClientHello de unos 12 KB.
- **Rendimiento:** el contador «bloqueados hoy» escribía las preferencias por cada dominio bloqueado; ahora a lo sumo cada 5 s.

## 3.4.7 (versionCode 30407)
- **Corrección — auto-actualización:** la 3.4.5 rechazaba el APK nuevo con «unreadable_signature» en dispositivos donde Android no expone la firma de un APK aún no instalado (ya estaba documentado en el código). Se quita ese rechazo: vuelve a delegarse en el instalador de Android, que sí rechaza una firma distinta. Las versiones 3.4.5 y 3.4.6 instaladas no pueden actualizarse solas a esta: hay que instalar la 3.4.7 a mano una vez.

## 3.4.6 (versionCode 30406)
Segunda pasada de auditoría: fuzzing de los parsers de red (2,85 millones de entradas: TLS ClientHello, QUIC, DNS, IPv4/IPv6 y fragmentos; sin excepciones ni lentitud) y barrido de patrones de riesgo.
- **Corrección — reensamblado de fragmentos IPv6:** nunca reensamblaba un paquete real. Comparaba la cabecera base completa entre fragmentos, incluido «Payload Length», que en el último fragmento es siempre menor; el resultado era descartar todo datagrama IPv6 fragmentado (UDP/QUIC grandes). Ahora se ignora ese campo y se recalcula al reconstruir.
- **Corrección — cabeceras de extensión:** si había una cabecera (p. ej. Hop-by-Hop) antes del Fragment header, el paquete reconstruido quedaba mal formado (se pisaba el Next Header de la cabecera base y el de la extensión seguía apuntando al Fragment header). Ahora se parchea el byte correcto.
- **Privacidad — log de diagnóstico:** `hydra-diagnostic.log` (paquete, IP y puerto de cada conexión) se escribía siempre en la carpeta externa de la app, legible por otras apps con permiso de almacenamiento en Android 7-10. Ahora va al almacenamiento interno (privado) en Android 7-10 y solo en Android 11+ queda en la carpeta externa para `adb pull`.
- Tests nuevos: `Ipv6FragmentReassemblerTest` (último fragmento menor, desorden, extensión previa, mezcla de orígenes, solapamientos).

## 3.4.5 (versionCode 30405)
Revisión de seguridad de la cadena de actualización, importación de configuración, bloqueo por PIN, listas de dominios y reporte de diagnóstico.
- **Seguridad — importar configuración (ConfigPortability):** un archivo ajeno podía escribir cualquier ajuste global, incluidos los que cambian la postura de seguridad (`default_wifi_allowed`, `default_mobile_allowed`, `policy_mode`, `threat_protection_enabled`, `ask_on_first_connection`, DNS personalizado, `trusted_apps_enabled`…). Ahora esos ajustes se marcan como *sensibles*, el diálogo los lista y **no se aplican salvo que el usuario marque la casilla**; sus valores se validan de forma estricta (enums, IP, hostname, URL `https://`). Las reglas avanzadas comodín que PERMITEN (todas las apps) siguen la misma regla, y la lista de IP bloqueadas se filtra por formato. «Deshacer» restaura la copia propia completa.
- **Seguridad — listas de dominios (BlocklistUpdater):** el tope de 18 MB solo valía con `Content-Length`; ahora se cuenta cada byte leído (respuestas chunked). Las listas descargadas ya no pueden bloquear `github.com`, `githubusercontent.com` ni los hosts de DNS cifrado (cloudflare-dns.com, dns.google, dns.quad9.net), que Hydra necesita para actualizarse y resolver. Sigue pendiente firmar las listas como el threat pack.
- **Seguridad — bloqueo por PIN:** desactivar el bloqueo ahora pide el PIN actual; el tile de Ajustes Rápidos ya no pausa el firewall con el bloqueo activo (abre la app, que pide el PIN); con el bloqueo activo la pantalla usa `FLAG_SECURE` (sin capturas ni miniatura en Recientes) y toda la interfaz ignora toques cuando otra app dibuja encima (anti-tapjacking).
- **Privacidad — reporte de diagnóstico:** los títulos de eventos podían incluir el nombre de paquete de apps instaladas (`Baseline created: com.banco.app`); ahora paquetes, hosts e IPv4 salen como `<redacted>`.
- **Auto-actualización (AppUpdater):** se ignoran las pre-releases; una firma ilegible del APK nuevo se rechaza desde Android 9 (antes se delegaba en el instalador); las versiones con números absurdos ya no provocan excepciones; las respuestas de texto (releases y `.sha256`) tienen tope de 2 MB; si falla la escritura de la sesión de instalación se abandona (`abandonSession`).
- Tests nuevos: ajustes sensibles y valores DNS hostiles, comodines, IP bloqueadas, pre-releases y versiones inválidas, dominios protegidos, redacción del diagnóstico.
- Pendiente (necesita dispositivo/fuzzing): parsers de paquetes (`TlsClientHello`, `Ipv6FragmentReassembler`, `DnsWireParser`, `QuicInspector`), compatibilidad entre versiones de Android, rendimiento real del túnel.

## 3.4.4 (versionCode 30404)
- **Seguridad — escáner de apps instaladas (AppThreatScanner):** si una app no se podía escanear (APK ilegible, excepción, o más de 512 MB) se trataba como «limpia»: se borraba su hallazgo previo y se la marcaba como ya revisada, lo que permitía evadir el escáner inflando el APK. Ahora lo no escaneable no modifica hallazgos, no se marca como visto (se reintenta) y deja un evento «N app(s) no se pudieron escanear».
- **Seguridad — baseline de APK (BaselineStore):** al superar 500 apps se descartaba el baseline recién creado (esa app quedaba en «primera vez» para siempre y no detectaba cambios de certificado). Ahora se descartan los más viejos.
- **Comportamiento (AppBehaviorBaselineStore):** una muestra ahora es una observación espaciada (mínimo 15 min por app) y no cada refresco de la pantalla; antes unos pocos refrescos hacían que una anomalía pasara a ser «lo normal». El perfil se cachea en memoria (antes se parseaba y reescribía el JSON completo por app en cada refresco) y, con el cupo lleno, se descarta la app observada hace más tiempo en vez de la nueva.
- **MH-100K:** el presupuesto de strings por DEX se limita al tamaño del archivo (offsets superpuestos podían forzar ~96 MB de heap) y el modelo se rechaza si tiene pesos/intercepto no finitos.
- **ApkScanner:** la pista estática «su» coincidía con casi cualquier DEX («support», «result»…); ahora busca `/system/xbin/su` y `/system/bin/su`.

## 3.4.3 (versionCode 30403)
- **Estabilidad — arranque de la VPN:** la carga del pack de amenazas (verificación de firmas ECDSA + parseo del JSON) ya no corre en el hilo principal del Service; se hace en un hilo de fondo para evitar ANR al encender el firewall. `ThreatSignatureStore.init()` pasa a ser thread-safe y, si no hay ningún pack válido, reintenta como máximo una vez por minuto en vez de recargar en cada consulta de red.
- **Estabilidad — YARA-lite:** `HydraYaraLite.parse()` rechaza fuentes de más de 512 KB y limita a 2000 reglas por fuente.
- **Seguridad — análisis de APK (MH-100K):** la lectura de `classes.dex` y `AndroidManifest.xml` ahora se acota por bytes realmente descomprimidos y no por el tamaño declarado en el header del ZIP, que controla el APK analizado (defensa ante zip bombs).
- Auditoría: DNS/TLS/QUIC revisado sin hallazgos de código (limitación de QUIC con DoH propio ya documentada en LIMITATIONS.md). Pendiente: el baseline de comportamiento se actualiza en cada refresco de UI, no en cadencia fija.

## 3.4.2 (versionCode 30402)
- **Rendimiento — TCP Window Scale:** el SYN-ACK que arma Hydra enviaba una opción TCP mal formada (no cumplía RFC 1323) y nunca negociaba escalado de ventana de su lado, aunque sí leía el de la app. En redes con latencia alta (4G, etc.) esto podía limitar la ventana anunciada a ~64 KB en vez de aprovechar el ancho de banda real disponible. Ahora Hydra ofrece una opción Window Scale válida (shift 7, hasta ~8 MB de ventana) en cada SYN-ACK.
- Se agregó un test de regresión (`TcpPacketBuilderOptionsTest`) que verifica que la opción generada se parsea correctamente de vuelta con el mismo parser que usa el motor en paquetes reales.
- Sigue sin tocarse: DNS/TLS/QUIC a fondo, motores de IA, compatibilidad Android, resto de la Fase 6 (performance real en dispositivo).

## 3.4.1 (versionCode 30401)
- **Seguridad — atribución de UID:** la ventana en la que Hydra podía atribuir tráfico de una app a otra por coincidencia de puerto (cuando falla la resolución directa del UID) se redujo de 15-30 s a 500-800 ms, acotándola a la demora real de resolución en vez de cubrir una "sesión" completa. Reduce el riesgo de que tráfico de una app bloqueada pase como si fuera de una app permitida que usó el mismo puerto momentos antes.
- **Límite de conexiones TCP simultáneas:** subido de 128 a 512 para todo el dispositivo. Si igualmente se alcanza de forma sostenida, ahora queda un aviso en Seguridad → Eventos («Demasiadas conexiones activas») en vez de fallar en silencio.
- Cambios de una auditoría de seguridad en curso sobre el motor de red; no incluye todavía las fases de DNS/TLS/QUIC, motores de IA ni compatibilidad/performance.

## 3.4.0 (versionCode 30400)
- **Inicio con estado de salud:** tarjeta con anillo de puntaje (100 = todo en orden; baja si hay avisos pendientes o el firewall está apagado), título claro y chips (estado, bloqueos de hoy, avisos), más el botón **«Una app no funciona»**.
- **Asistente «Una app no funciona»:** Empezar → probás la app → Listo. Hydra muestra qué bloqueó en ese lapso, agrupado por app y clasificado como *Servicio*, *Rastreador* o *Desconocido*, con **Permitir app**, **Permitir 1 h** o **Ignorar**. Si no bloqueó nada, lo dice y sugiere dónde mirar.
- **Reglas:** cada app muestra un punto de color sobre el ícono (verde = Wi‑Fi y datos, ámbar = una sola red, rojo = bloqueada, azul = sin firewall).
- **Navegación:** la pestaña de Actividad muestra un badge con los bloqueos nuevos desde la última vez que la abriste.

## 3.3.0 (versionCode 30300)
- **Avisos «¿bloqueamos?»:** cuando una app de usuario se conecta a un destino conocido como amenaza, o a un dominio nuevo para ella (después de haber usado varios), Hydra avisa «La app X se conecta a Y» con un único botón **Bloquear** (y «Dejar»). Aparece como notificación y como tarjeta «Avisos» en Inicio. Límite: 1 aviso por app cada 10 min y 6 por hora (las amenazas conocidas no cuentan para el límite). El sistema Android no genera avisos.
- **Deshacer 5 s:** al tocar Bloquear el botón pasa a «Deshacer (5…1)»; si se toca en ese tiempo el bloqueo se revierte. La notificación también muestra «Deshacer» durante 5 s.
- **Reglas → «Destinos bloqueados»:** lista todo lo bloqueado por aviso o por IP manual; cada uno se puede **Desbloquear**, y ese botón también pasa a «Deshacer» durante 5 s.
- El bloqueo se aplica por IP de destino para todo el dispositivo.

## 3.2.0 (versionCode 30200)
- **Reglas agrupadas por UID:** las apps que comparten UID (Google, Samsung, apps de sistema…) comparten una sola regla Wi‑Fi/Datos en Android, así que ahora se muestran como una sola fila con un único par de interruptores («App principal +N»; el UID 1000 aparece como «Sistema Android · N»). Al abrir la fila se ven los paquetes que la integran. El modo (Personalizado / Permisivo / Sin firewall) se aplica a todo el grupo. La búsqueda encuentra cualquier paquete del grupo y los contadores «Usuario · N» y «Sistema · N» cuentan grupos.

## 3.1.2 (versionCode 30102)
- **Reglas, filtros:** botones «Todas» (usuario + sistema), «Usuario» (por defecto), «Sistema», «Sin reglas» (antes «Nuevas»: apps sin regla propia que quedan bloqueadas por defecto, de usuario o de sistema) y «Sin Internet». «Usuario» y «Sistema» muestran cuántas apps hay.

## 3.1.1 (versionCode 30101)
- **Reglas:** el botón «Todas» ahora muestra todas las apps, también las de sistema (antes en modo simple filtraba solo las de usuario, por eso no aparecían). Se agrega el botón «Sistema · N» junto a «Nuevas». La lista arranca en «Todas».
- **GitHub:** la release de cada etiqueta `v*` se publica como versión estable y se marca como «Latest» (antes salía como pre-release).

## 3.1.0 (versionCode 30100)
- **Apps de sistema:** la lista de apps se carga con una consulta más liviana (`getInstalledApplications` + permiso INTERNET) para que aparezcan también las de sistema; el filtro «Sistema» muestra cuántas hay y, si una vista queda vacía, ahora lo dice en pantalla.
- **Conexiones:** cada tarjeta muestra el motivo probable del bloqueo. «Permitir app» y «Permitir 1 h» confirman con un aviso; si la app ya está permitida, la tarjeta lo dice y explica que el bloqueo viene de otra regla (dominio de la lista, horario, IP o puerto) en vez de repetir botones que no cambian nada.
- **Apps no identificadas («?»):** la tarjeta lo indica y en Detalles aparece «¿Quién la inició?» con pistas: paquetes que comparten el UID, quién la instaló y qué apps estaban activas en ese momento. Son pistas; Android no informa qué app inició a otra.
- **Reglas, servicios que usa (opcional):** al abrir una app se listan sus servicios relacionados (Google Play Services, Services Framework, Google Drive, almacenamiento multimedia, descargas) con interruptores Wi‑Fi y Datos propios. Pensado para casos como la copia de seguridad de WhatsApp en Drive.

## 3.0.0 (versionCode 30000)
- **Rediseño de la interfaz:** nuevo estilo común con controles segmentados y tarjetas.
- **Pestañas de cada sección:** las pestañas internas (Reglas / IP y puertos / Perfiles, Conexiones / Stats / Analizador, Ajustes / Ayuda / Acerca de / Prueba) pasan a un selector segmentado de ancho completo, sin desplazamiento lateral.
- **Reglas:** cada app es una fila limpia (nombre, estado en una línea, interruptores Wi‑Fi y Datos). Al tocarla se abren el modo (Personalizado / Permisivo / Sin firewall), paquete y UID, Detalles, Horario y favorito. Los filtros pasan a botones redondeados.
- **Conexiones:** filtro Todo / Bloqueadas / Permitidas; cada grupo es una tarjeta con la app, el dominio (si se conoce), la etiqueta PERMITIDO / BLOQUEADO ×N y, para bloqueos por regla de app, los botones «Permitir app» y «Permitir 1 h». «¿Por qué? / Detalles» abre la explicación.
- **Estadísticas:** selector Hoy / 7 días con permitido, bloqueado y variación del bloqueo contra ayer; barras apiladas de los últimos 7 días; conexiones por red (Wi‑Fi, datos) según el historial reciente. El resto (tráfico en vivo, consumo por app) sigue debajo.

## 2.7.0 (versionCode 20700)
- **Inicio rediseñado («Actividad en vivo»):** fila de estado compacta con el interruptor del firewall, tarjeta de tráfico en vivo (permitido vs. bloqueado, bloqueos de hoy) y las últimas 6 decisiones con app, protocolo, destino y etiqueta permitido/bloqueado. «Ver todo» abre Conexiones. Pausa, Seguridad, resumen de 7 días y los interruptores siguen debajo.

## 2.6.0 (versionCode 20600)
- **Permitir una app por 1 hora:** en el detalle de una conexión bloqueada, «Permitir por 1 hora» abre la regla de esa app y la deja exactamente como estaba al terminar (incluso «sin regla»). Se controla con una alarma, al arrancar el teléfono y al abrir la app.
- **Copiar diagnóstico** (Ajustes → Copias y datos): texto con versión, Android, modo, estado de la VPN, lista de bloqueo y títulos de los últimos eventos de seguridad. No incluye destinos, dominios ni historial.
- **Error de actualización más claro:** si el APK descargado no es más nuevo, el cartel muestra las dos versiones y códigos (p. ej. «el APK es 2.5.1 (20501) y ya tenés la 2.5.2 (20502)»).

## 2.5.2 (versionCode 20502)
- Corrige la compilación de 2.5.1 (faltaban imports en `AppNames`). Sin cambios de funciones respecto de 2.5.1.

## 2.5.1 (versionCode 20501)
- **Vuelve «Actualizar lista» en Inicio:** «Amenazas + publicidad» muestra otra vez la fecha de la lista, los bloqueos de hoy y el botón para buscar/actualizar la lista, también en modo Normal (en 2.5.0 había quedado solo en Avanzado).
- **Nombres en vez de «UID 1234»:** el historial, las conexiones, las reglas y el uso por app resuelven el nombre de la app (aunque solo haya UID); si el UID es compartido muestra «App +N»; los UID fijos de Android se nombran (p. ej. «Sistema Android (1000)») y los desconocidos dicen «App desconocida o desinstalada (UID n)».

## 2.5.0 (versionCode 20500)
- **Inicio más corto:** en modo Normal queda el interruptor, la pausa, el estado de Seguridad, el resumen de 7 días y «Amenazas + publicidad». Las 3 cifras, el detalle de la lista, «Bloquear todo el tráfico» y «Detalles del sistema» pasan a Avanzado (si «Bloquear todo» está activo se sigue mostrando para poder apagarlo).
- **Ajustes en 5 bloques:** Protección, Notificaciones, Apariencia, Copias y datos, y Avanzado (con el interruptor de modo y todo lo técnico). Cada ajuste está en un solo lugar.
- **Avisos en dos niveles:** los que necesitan tu decisión (amenazas, cuarentena, parada inesperada, fin de pausa, pedidos de acceso, actualización lista para instalar) siguen sonando; los informativos (p. ej. «hay una actualización») van por un canal silencioso y se pueden apagar en Ajustes → Notificaciones.
- **Apps con filtros simples:** en modo Normal, Todas / Sin Internet / Nuevas (apps tuyas sin regla). La fila completa de filtros queda en Avanzado.
- **Seguridad → Herramientas:** en Avanzado, el analizador APK (experimental), la correlación de tráfico y Doze se agrupan bajo «Herramientas».
- **Textos:** se corrigió un texto en inglés que empezaba en español y se unificó «permitir» en lugar de «autorizar».

## 2.4.1 (versionCode 20401)
- **Estilo de tarjetas unificado:** todas las pantallas (Inicio, Apps, Actividad, Seguridad, Ayuda, Ajustes, avisos) usan el mismo componente `HydraCard`: esquinas de 16 dp, fondo de superficie, borde fino y sombra leve. Antes se mezclaban tarjetas de Material con otras hechas a mano.

## 2.4.0 (versionCode 20400)
- **Pausar Hydra 15 min / 1 h:** desde Inicio (o el atajo del panel de Android). Muestra cuenta regresiva, «Reanudar ahora» y se reactiva sola; sobrevive a reinicios y, si Android no deja arrancar en segundo plano, avisa con una notificación.
- **Atajo en el panel de Android (Quick Settings):** un toque pausa 15 min, reanuda o enciende Hydra.
- **Resumen de 7 días en Inicio:** intentos bloqueados, anuncios/rastreadores bloqueados, conexiones permitidas y apps con más bloqueos (solo contadores locales, sin destinos).
- **«¿Esta app no funciona?»:** en el detalle de una conexión bloqueada por regla de app/red, un botón «Permitir esta app».
- **Orden:** se quitó de Inicio el interruptor duplicado de modo Avanzado (queda en Ajustes). Las alarmas exactas ahora tienen alternativa si Android no concede el permiso.

## 2.3.0 (versionCode 20300)
- **Modo Normal más simple:**
  - **Seguridad es una sola pantalla:** estado, apps sospechosas (con el motivo en lenguaje simple), cuarentena, vigilancia de updates e historial de seguridad, más un botón «Activar modo Avanzado». El selector de secciones y la lista técnica de capas quedan solo en Avanzado.
  - **Aviso de primera conexión:** solo *Permitir* / *Bloquear*; «Más opciones» muestra Permisivo, Sin firewall, Personalizado, los interruptores Wi‑Fi/Móvil y Detalles (el modo Avanzado abre el aviso completo).
  - **Ajustes básicos:** el modo global, Wi‑Fi/móvil por defecto, DNS seguro, IPv6, roaming, pantalla apagada, rendimiento y apps permisivas pasan a Avanzado.
  - **Guía inicial de 3 pasos** (qué hace Hydra, qué significa Permitir/Bloquear, qué hacer cuando Seguridad marca algo); termina eligiendo modo Normal o Avanzado.
- **Se quitó lo que no servía:**
  - *Huella TLS (JA3):* se retiran su sección, su lista de huellas, sus filas de estado y el interruptor por app de Perfiles. La captura y el corte por huella conocida se apagan una vez al actualizar.
  - *Línea de tiempo:* pasa a «Historial de seguridad» (eventos del antivirus, ignoradas, cambios de firma y cuarentena) dentro de Seguridad.
- **Fusionado o renombrado:**
  - *Reglas* (limpieza de conflictos) pasa a Apps → IP y puertos → Limpieza.
  - *Parada inesperada* queda como la notificación de siempre más una tarjeta en Seguridad cuando ocurre.
  - *Comportamiento* se llama ahora «Correlación de tráfico», para no confundirla con los permisos delicados.
- **Analizador APK marcado como experimental:** cartel que aclara que el puntaje MH‑100K es orientativo, no un veredicto, hasta calibrarlo con más apps reales.
- **Documentación y ayuda (ES/EN) actualizadas** para reflejar todo lo anterior; sin menciones a pantallas que ya no existen.

## 2.2.5 (versionCode 20205)
- **Se ve que la actualización está en marcha:** en Seguridad → Actualización de Hydra aparece una barra con la fase actual: «Descargando 45 % (1,1 / 2,5 MB)», «Verificando la descarga y la firma…», «Instalando… Hydra se va a reiniciar sola y la VPN vuelve a arrancar», o «Android espera tu confirmación». También se muestra cuando la descarga empezó sola en segundo plano.
- **Aviso después del reinicio:** al volver a abrirse tras actualizarse, Hydra muestra «✅ Hydra se actualizó: 2.2.4 → 2.2.5» y la tarjeta de actualización lo recuerda unos minutos, para que el reinicio no parezca un cierre inesperado.

## 2.2.4 (versionCode 20204)
- **Menos falsos positivos del antivirus:** las reglas de patrón del pack (p. ej. «SMS + superposición + administrador» o «patrón de stalkerware») miran solo permisos del manifiesto y coincidían con apps legítimas (Servicios de Google Play, Galaxy Wearable, apps de domótica o de bolsa). Ahora, para apps de una tienda conocida o del sistema, una coincidencia solo de patrón ya no se informa como amenaza; un hash exacto de malware conocido se informa siempre, venga de donde venga. Las apps instaladas fuera de tienda siguen igual. Al actualizar se limpian los avisos viejos de ese tipo.
- **Última lista de escaneo con puntajes guardada:** los resultados de «Escanear apps instaladas» (con el puntaje de cada app y la fecha del último escaneo) se guardan y reaparecen al volver a abrir la app.

## 2.2.3 (versionCode 20203)
- **Reglas que volvían a preguntar:** al abrir la app, la cuarentena volvía a bloquear y a «marcar como sin decidir» a toda app que siguiera en su lista de pendientes, aunque ya le hubieras fijado una regla en Reglas; por eso Hydra preguntaba otra vez. Ahora, si la app ya tiene una regla tuya, se la saca de pendientes y no se toca la regla.
- **El escaneo de apps ya no se reinicia al cambiar de pantalla:** el progreso y los resultados de «Escanear apps instaladas» (analizador MH-100K) viven fuera de la pantalla; si salís de Seguridad y volvés, seguís viendo el mismo escaneo en curso.

## 2.2.2 (versionCode 20202)
- **Arreglo de la actualización desde la app:** el chequeo previo de firma fallaba con «la firma no coincide» aunque el APK del Release estuviera bien firmado (en algunos teléfonos Android no puede leer la firma de un APK que todavía no está instalado). Ahora, si no se puede leer, Hydra no bloquea y deja que Android decida (es quien realmente rechaza una firma distinta); si las firmas se pueden leer y no coinciden, el mensaje muestra las dos huellas (instalada → nueva) para diagnosticar. Nuevo test de la regla.

## 2.2.1 (versionCode 20201)
- **Más tests en el CI:** el actualizador (orden de versiones, selección del Release, archivo `.apk.sha256`, hash SHA-256 con vector conocido, rechazo de URLs no HTTPS) y la lógica de ignorar (decisión de cambio de firma, guardado y lectura de apps con permisos delicados, fecha de ignorado, datos corruptos). La decisión «¿cambió la firma?» pasó a una función pura (`signerChanged`) para poder probarla; el comportamiento es el mismo. Sin cambios visibles.

## 2.2.0 (versionCode 20200)
- **Más cobertura del antivirus (permisos delicados):** para apps instaladas fuera de una tienda conocida, Hydra marca combinaciones de permisos típicas de malware (accesibilidad + superposición + SMS, escucha de notificaciones + SMS, instalar paquetes, administrador de dispositivo, etc.). Son indicios, no pruebas: aparecen en una tarjeta aparte, sin notificaciones, con Google e Ignorar. Las apps de tienda y del sistema no se marcan.
- **Motivo en lenguaje simple:** cada hallazgo explica por qué se marcó («idéntico a malware conocido» o «patrón típico, puede ser falso positivo»); «Copiar datos» incluye el origen y los indicios.
- **Apps ignoradas con fecha y vigilancia de firma:** la lista muestra cuándo se ignoró cada app (amenazas y permisos delicados). Si una app ignorada cambia su firma de desarrollador, Hydra deja de ignorarla, registra un evento y avisa con una notificación.
- **Calibración del escáner MH-100K:** «Copiar resultados» ahora incluye versión, fecha y el origen de cada app (store/sideload/system). Nuevo `tools/analyze_scan_results.py` calcula la distribución de puntajes por origen y sugiere un umbral que marque a lo sumo el 1 % de las apps de tienda.
- MalwareBazaar (hashes de abuse.ch) sigue pendiente: requiere tu propia clave de abuse.ch.

## 2.1.0 (versionCode 20100)
- **Inicio más limpio:** el kill switch del sistema y el estado detallado (DNS, lista, integridad) pasan a una tarjeta plegable «Detalles del sistema». El selector Normal/Avanzado queda siempre visible debajo.
- **Mismo estilo en Apps, Actividad y Más:** filas de apps (Reglas), entradas del historial de conexiones, interruptores y bloques de reglas de Ajustes ahora son tarjetas redondeadas con más aire. Solo presentación.
- **Permisos revisados** (nuevo `docs/PERMISSIONS.md` y `docs/es/PERMISSIONS.md`, con textos sugeridos para las declaraciones de Google Play): `USE_FINGERPRINT` limitado a Android 9 o menos; tablas de permisos de los README completadas con `REQUEST_INSTALL_PACKAGES`. Se recomienda NO incluir `REQUEST_INSTALL_PACKAGES` ni el actualizador en un build de Google Play.

## 2.0.2 (versionCode 20002)
- Auditoría de 2.0.1 (revisión estática: llaves/paréntesis balanceados en los 100+ archivos Kotlin, YAML válido, tests de Python OK, dependencias de test de `org.json` presentes). Dos ajustes: la navegación ya no escribe un `mutableStateMapOf` durante la composición (ahora un `HashMap` simple, solo se lee al tocar), y la descarga automática de actualizaciones se omite en compilaciones debug/de prueba (nunca podrían instalarse por la firma distinta) para no gastar datos.

## 2.0.1 (versionCode 20001)
- **Inicio igual a la opción 1:** el Inicio se reordena como en el diseño elegido: primero la tarjeta grande del firewall (VPN), luego tres mosaicos (bloqueos hoy, dominios en la lista, amenazas), una tarjeta «Seguridad: protegido / N apps requieren atención / sin revisar» que lleva a Seguridad al tocarla, y los interruptores «Bloquear todo el tráfico» y «Amenazas + publicidad» como tarjetas. Se quitó el título «Controles básicos de protección»; el selector de modo Normal/Avanzado pasó más abajo. Solo cambia la presentación: todas las funciones siguen igual.

## 2.0.0 (versionCode 20000)
- **Navegación rehecha (opción 1: barra inferior):** 5 destinos — Inicio (firewall y protección básica), Apps (Reglas · IP y puertos · Perfiles), Actividad (Conexiones · Estadísticas · Analizador), Seguridad (antivirus, pack, actualizaciones, analizador de APK) y Más (Ajustes · Ayuda · Acerca de · Prueba). Donde un destino tiene varias pantallas, una fila de botones arriba cambia entre ellas; los destinos «Avanzados» siguen apareciendo solo en modo Avanzado. Reemplaza la fila de 11 pestañas con scroll.
- **Sin cambios de funcionamiento:** las pantallas y su lógica son las mismas; solo cambia dónde se llega a ellas. La sección Seguridad vuelve a ser un destino propio (ya no está dentro de Protección).
- Ayuda actualizada con la nueva navegación.

## 1.5.1 (versionCode 10501)
- Seguridad: mientras se descarga el pack o se revisan las apps (por ejemplo, justo después de instalar), la tarjeta de estado muestra «Preparando la protección…» con lo que está pasando («Descargando y verificando el pack…» / «Revisando tus apps: X de Y») y explica por qué «Revisar todo ahora» y «Revisar apps ahora» están deshabilitados; se activan cuando aparece «Estás protegido». Antes los botones quedaban apagados sin explicación hasta que terminaba la primera revisión automática.

## 1.5.0 (versionCode 10500)
- **Ignorar apps sospechosas:** cada hallazgo tiene «Ignorar (no es un problema)». La app pasa a una lista «Apps ignoradas» (con «Volver a vigilar»); deja de contar como amenaza y no se vuelve a notificar, salvo que luego coincida con reglas distintas. Queda un evento en la línea de tiempo. Tests.
- **Arreglo del botón «Revisar apps ahora» que no se activaba:** el estado «revisando» se leía una sola vez; si la revisión arrancaba sola en segundo plano (al abrir la app o tras actualizar el pack), el botón quedaba deshabilitado para siempre. Ahora sigue el estado real cada segundo, y la revisión se marca como terminada antes de avisar a la pantalla.

## 1.4.0 (versionCode 10400)
- **Seguridad dentro de Protección:** la pestaña SEGURIDAD desaparece de la barra; ahora es una sección de PROTECCIÓN (selector FIREWALL / SEGURIDAD arriba). Todo el control de protección está en un solo lugar y no hay controles repetidos: de «Control y actualizaciones» se quitaron las filas de VPN y listas (ya están en el selector FIREWALL; el estado de la VPN se ve en el encabezado).
- Tarjeta principal de la VPN rediseñada (más grande, esquinas redondeadas y fondo verde cuando está activa). Sin cambios de funcionamiento.

## 1.3.3 (versionCode 10303)
- **Aspecto moderno en TODA la app:** nueva paleta (violeta, superficies oscuras/claras más limpias) y esquinas más redondeadas aplicadas desde el tema, así que todas las pestañas (Protección, Reglas, Conexiones, Estadísticas, Ajustes, Ayuda…) lo reciben. Solo colores y formas: sin cambios de funcionamiento.
- **Sin botones repetidos entre pestañas:** el interruptor del firewall y los botones de actualizar listas viven solo en PROTECCIÓN; en Seguridad → Resumen ahora son solo estado (con la indicación de dónde se manejan). Quedan en Seguridad únicamente las acciones propias: pack de amenazas, antivirus y actualización de Hydra.

## 1.3.2 (versionCode 10302)
- Seguridad → Resumen, aspecto más moderno: encabezado con degradado y círculo de estado (✓ / ! / ?), chips (VPN, pack, versión), tarjetas redondeadas con más aire y una fila por capa. Mismas funciones.

## 1.3.1 (versionCode 10301)
- Seguridad → Resumen rediseñada: arriba el estado («Estás protegido» / «N apps requieren atención») con «Revisar todo ahora»; luego las apps con hallazgos (Desinstalar a ancho completo, Copiar datos y Buscar en Google debajo, lado a lado); luego una fila por capa (punto de estado + interruptor a la derecha + su botón). Los textos largos ya no empujan el interruptor fuera de la pantalla. Detalles del pack plegados («Ver detalles y actualizar»).
- Diagnóstico de la actualización: la tarjeta «Actualización de Hydra» ahora dice si esta instalación es de PRUEBA (debug) o release y muestra la huella de la firma; si la firma del APK nuevo no coincide, explica por qué no se puede actualizar y qué hacer.

## 1.3.0 (versionCode 10300)
- **Actualización de la propia app:** busca sola (una vez al día, solo descarga en redes sin datos medidos) y a mano con «Buscar actualización». Muestra «Ya está actualizado» cuando no hay versión nueva. Descarga el APK del último Release de GitHub y solo lo instala si el SHA‑256 coincide con el publicado (`.apk.sha256`, ahora adjunto en cada Release), es el mismo paquete, es más nuevo y está firmado con la misma clave; Android siempre pide confirmación. Nuevo permiso `REQUEST_INSTALL_PACKAGES`. Tests de versiones/parseo.
- **Una sola pestaña Seguridad sin repetidos:** la tarjeta «Control y actualizaciones» (Resumen) concentra Hydra, VPN, pack de amenazas (estado + actualizar manual, con «Ya está actualizado»), antivirus (con sus hallazgos) y listas de dominios. Se quitaron las copias: tarjeta de antivirus del Analizador APK, tarjeta suelta del pack en Resumen e interruptor de huella TLS duplicado (queda en su sección).
- **Apps sospechosas:** cada hallazgo tiene «Copiar datos» (paquete, versión, instalador, hash del APK, huella del certificado, permisos, reglas coincidentes), un botón chico «🔍 Google» (busca el paquete + familia de malware) y «Desinstalar…».

## 1.2.3 (versionCode 10203)
- Antivirus: la revisión de apps nuevas/modificadas ahora también corre al abrir Hydra y tras cada intento de actualización diaria del pack (aunque no haya pack nuevo o falle la red), así que funciona con el firewall apagado. La detección instantánea al instalar/actualizar una app sigue requiriendo el firewall (VPN) activo (Android no permite recibir esos avisos de otra forma). Ayuda actualizada.

## 1.2.2 (versionCode 10202)
- Documentación: README (EN/ES), docs/FEATURES.md y la ayuda dentro de la app (EN/ES) ahora explican la protección tipo antivirus y la tarjeta «Control y actualizaciones», con sus límites.

## 1.2.1 (versionCode 10201)
- Seguridad → Resumen: nueva tarjeta «Control y actualizaciones» con, en un solo lugar, el interruptor y/o el botón de actualizar de cada capa: Firewall (VPN), pack de amenazas, antivirus (revisión automática + revisar ahora), listas de dominios y huella TLS.

## 1.2.0 (versionCode 10200)
- **Protección tipo antivirus con el pack de amenazas:** nuevo `AppThreatScanner`. Revisa las apps contra el pack firmado (hashes SHA‑256 de malware conocido + reglas YARA‑Lite) automáticamente cuando una app se instala o se actualiza, y de nuevo para todas las apps cuando el pack se actualiza (incremental: omite las apps que no cambiaron con el mismo pack). Es liviano (sin modelo ni lectura de DEX), corre en segundo plano con prioridad mínima.
- Si encuentra algo: registra un evento de seguridad y envía una notificación. Hash exacto = «malware conocido»; solo patrón YARA = «sospechoso, puede ser falso positivo». Nunca borra ni bloquea nada por sí solo: el usuario decide.
- Seguridad → nueva tarjeta «Protección antivirus»: interruptor de revisión automática (activado por defecto), botón «Revisar todas las apps ahora», lista de hallazgos con botón «Desinstalar…».
- Límites honestos: solo detecta lo que está en el pack (amenazas conocidas); no es un antivirus completo ni reemplaza a Play Protect.

## 1.1.1 (versionCode 10101)
- Escáner MH‑100K: el resultado se muestra en **una sola escala, en un solo sentido**: 0–49 «Parece normal» (verde), 50–89 «Dudosa» (ámbar), 90–100 «Sospechosa» (rojo); más alto = más sospechosa. Si el análisis quedó incompleto o se vio muy poco código, el resultado es «Sin conclusión». Reemplaza las etiquetas «sospecha» y «confiabilidad» de la 1.1.0, que se contradecían entre sí. Test actualizado.

## 1.1.0 (versionCode 10100)
- **Versiones:** nuevo esquema MAYOR.MENOR.PARCHE en `version.properties` (patch = cambios pequeños 1.0.x, minor = medianos 1.x.0, major = grandes x.0.0). El `versionCode` se calcula solo (mayor×10000 + menor×100 + parche) y siempre crece. Herramienta `tools/bump_version.py` con tests. Guía en `docs/es/VERSIONING.md`.
- **Actualizar sin desinstalar:** el CI genera en cada push el artefacto `hydra-release-apk`, firmado con tu clave de release (si están los 4 secretos de firma), que Android instala como actualización. Los APK debug siguen siendo solo de prueba.
- Puntaje MH‑100K con resultado interpretado (ver 1.1.1, que lo simplificó).
- Escáner de apps: mucho más rápido para que las apps grandes terminen en vez de agotar el tiempo. El extractor MH‑100K calcula el nombre y el hash de cada método UNA vez (antes armaba un texto y lo hasheaba en cada instrucción de llamada, millones de veces), lee las cadenas del DEX sin streams intermedios y revisa el reloj cada 256 instrucciones. El análisis de pistas estáticas pasa el texto a minúsculas una vez y usa búsqueda directa (antes `contains(ignoreCase)` por pista y por bloque). Límites: extracción 30 s, DEX total 160 MB, 120 s por app en el escaneo masivo. La lista ahora muestra los segundos que tardó cada app.
- Escáner MH‑100K: corregido el error que dejaba **todas** las apps «sin puntaje». El lector de DEX acumulaba el índice de método a lo largo de las listas de métodos directos y virtuales (en el formato DEX cada lista empieza de nuevo en 0), se pasaba del final de la tabla y marcaba el análisis como incompleto. Verificado con un DEX de prueba. Además: las cadenas del DEX se leen una sola vez, el tiempo máximo de extracción sube de 5,5 s a 20 s, el límite por app del escaneo masivo pasa a 90 s y la lista muestra el motivo cuando una app no tiene puntaje.
- Seguridad → Escáner APK: nuevo botón «Escanear apps instaladas». Recorre las apps instaladas por el usuario (omite las del sistema), muestra el puntaje MH‑100K de cada una con un resumen (cuántas llegan a 50 y a 90), permite detenerlo y copiar los resultados. No guarda eventos ni sube nada.
- «Escanear apps instaladas»: cada app se escanea con un límite de 60 s; si una se cuelga se marca TIMEOUT y se sigue con la siguiente (se detiene tras 3). Muestra la app que se está escaneando en ese momento.
- Escáner MH‑100K: corregida la causa del cuelgue. La expresión regular que extraía el nombre del intent era cuadrática (100.000 caracteres en mayúscula tardaban ~47 s) y una cadena grande dentro de un DEX congelaba el escaneo; ahora es lineal (equivalente, con test). Además: los contadores de campos/métodos del DEX se validan (apps empaquetadas o corruptas), la lectura de cadenas está acotada, y el análisis de cadenas de ApkScanner y YARA‑Lite respetan un tiempo máximo.
- Escáner de APK (MH‑100K): corregido el tamaño de las instrucciones `move-wide/16` y `move-object/16` al leer DEX (se contaban como 1 unidad en vez de 3, lo que podía desalinear la lectura en métodos con más de 255 registros). Verificado que el formato de nombres de características (`APICall::Lclase.metodo()`, `Permission::X`, `Intent::X`) coincide con `feature_names.csv` del dataset y que las 2.048 características del modelo se resuelven por hash FNV‑1a‑64.
- Escáner de APK: el puntaje MH‑100K ahora muestra una etiqueta (indicio débil 50–89, sospecha alta 90+, muy alta 95+) en vez de presentar puntajes medios como alarma. Test agregado.
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
