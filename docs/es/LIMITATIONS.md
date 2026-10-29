# Alcance y límites (leer antes de confiar)

**Hydra es un firewall por app con filtrado DNS/SNI. No es un antivirus.**

## Lo que hace bien
- Decidir qué apps salen a internet y por qué red.
- Cortar anuncios, rastreadores y dominios/IPs maliciosos conocidos que usen el DNS del sistema, SNI o IPs en el pack.
- Avisar de apps nuevas y mostrar adónde se conecta cada app.

## Lo que NO garantiza
- **Detección de malware.** El escáner de APK es estático y heurístico; el modelo MH‑100K es una señal secundaria que avisa y nunca bloquea (en su informe: con umbral 0,5 la precisión es ~64 % y el 5,6 % de apps legítimas dan falso positivo). El "AI Lite" se entrenó con datos sintéticos y no es evidencia de detección real.
- **Tráfico cifrado.** No descifra HTTPS: bloquea por nombre de dominio (SNI) o IP. Apps con su propio DoH/ECH o con IPs directas pueden esquivar el filtro por dominio. QUIC/HTTP3 se cubre solo de forma indirecta.
- **Apps en modo Esencial / Sin firewall** quedan fuera del filtrado de la VPN en la medida que se configuren así.
- **"Bloquear todo" no es un corte total.** Solo bloquea el tráfico que entra al túnel: Hydra misma y las apps excluidas / "Sin firewall" quedan fuera. Para un corte duro usá VPN siempre activa + "Bloquear conexiones sin VPN" de Android.
- **Otra VPN.** Android permite una VPN activa a la vez.
- **Malware con privilegios de sistema/root** puede ignorar la VPN.

## Rendimiento y compatibilidad
- El reenvío TCP/UDP se hace en espacio de usuario: más consumo de batería y algo de latencia que un firewall nativo.
- Límite nominal de 768 sesiones simultáneas (TCP 128+128, UDP 256+256). IPv6 sin paridad total (ESP y cabeceras no soportadas se rechazan).
- Android 7–9 identifica la app dueña de cada conexión leyendo `/proc/net`; puede fallar de forma transitoria (en ese caso la conexión se descarta, "fail closed").
- Si no se identifica la app dueña de una conexión, se descarta: Hydra no infiere la identidad por la IP de destino.
- Las apps nuevas arrancan bloqueadas: al principio vas a ver apps sin internet hasta aprobarlas.

## Privacidad
- No hay telemetría. Las únicas conexiones propias son: listas de bloqueo (GitHub/OISD), DNS cifrado y, si lo activás, el feed de amenazas.
- Permisos sensibles: `QUERY_ALL_PACKAGES` (nombre/ícono de apps) y `PACKAGE_USAGE_STATS` (estadísticas locales). `allowBackup=false`.
