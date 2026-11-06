# Permisos: para qué sirve cada uno

Revisión de todos los permisos de `AndroidManifest.xml` (versión 2.5.2). No se pide nada «por si acaso».

| Permiso | Para qué | ¿Sensible en Google Play? | Notas |
|---|---|---|---|
| `INTERNET`, `ACCESS_NETWORK_STATE` | Reenviar el tráfico permitido; pack de amenazas, listas y búsqueda de actualizaciones; distinguir Wi‑Fi de datos | No | |
| `BIND_VPN_SERVICE` (servicio) | El firewall en sí (VPN local, sin servidor remoto) | Sí: las apps VPN deben completar la declaración de VpnService | La VPN es solo local; el tráfico nunca se envía a un servidor de Hydra |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` | Mantener vivo el servicio VPN | Declaración del tipo de servicio en primer plano | `systemExempted` corresponde a apps VPN |
| `POST_NOTIFICATIONS` | Avisos de primera conexión, antivirus y actualizaciones | No | |
| `RECEIVE_BOOT_COMPLETED` | Restaurar el firewall tras reiniciar | No | |
| `USE_BIOMETRIC` | Desbloqueo con huella | No | `USE_FINGERPRINT` se limita a Android 9 o menos (`maxSdkVersion=28`) |
| `QUERY_ALL_PACKAGES` | Las reglas por app necesitan la lista completa de apps instaladas (nombre, ícono, UID); el antivirus revisa todas | **Sí**: exige declaración | Es el propósito central de un firewall/antivirus. Declaración sugerida: «Hydra Firewall aplica reglas de red por cada app instalada y analiza las apps instaladas contra un pack de firmas de malware; no puede funcionar sin ver todas las apps instaladas». |
| `PACKAGE_USAGE_STATS` | Estadísticas de uso locales (opcional; el usuario lo concede en ajustes del sistema) | Acceso especial | Opcional: la app funciona sin él |
| `REQUEST_INSTALL_PACKAGES` | Instalar una actualización de Hydra descargada por el actualizador de la app (solo APK de GitHub) | **Sí**: Play lo restringe, y auto‑actualizarse fuera de Play infringe su política | **No incluir este permiso ni el actualizador en el build de Google Play.** Dejarlos solo en el APK de GitHub |

## Recomendación para un build de Google Play

1. Compilar el bundle de Play sin `REQUEST_INSTALL_PACKAGES` y con el actualizador desactivado (Play actualiza la app).
2. Completar las declaraciones de VpnService, servicio en primer plano y `QUERY_ALL_PACKAGES` con los textos de arriba.
3. Mantener el APK de GitHub (con actualizador) como canal de descarga directa.
