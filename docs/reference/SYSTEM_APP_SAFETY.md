# HYDRA FIREWALL — evaluación de aplicaciones del sistema

HYDRA marca aplicaciones del sistema con una evaluación conservadora. Android indica que `ApplicationInfo.FLAG_SYSTEM` significa que una app está instalada en la imagen del sistema, pero Android advierte explícitamente que ese flag **no debe usarse por sí solo para decisiones de seguridad**; la identificación real depende también de firma, permisos y del dispositivo.

## Alto riesgo — no se recomienda bloquear sin una prueba concreta

| Paquete conocido | Motivo |
|---|---|
| `com.android.systemui` | Interfaz y funciones esenciales de sistema |
| `com.android.settings` | Ajustes del dispositivo |
| `com.android.phone` | Telefonía |
| `com.android.providers.telephony` | Proveedor de datos de telefonía |
| `com.android.providers.settings` | Proveedor de ajustes |
| `com.android.packageinstaller` | Instalación de paquetes en Android 7-era |
| `com.android.permissioncontroller` | Control de permisos en versiones que lo usan |
| `com.google.android.gms` | Servicios de Google; bloquearlos puede afectar muchas funciones |
| `com.google.android.gsf` | Google Services Framework; dependencia de servicios Google |

## Precaución

Otros `com.android.providers.*`, componentes de conectividad/telephony y paquetes del fabricante deben revisarse individualmente. Android dice que el conjunto de paquetes de sistema visibles y las funciones que proporcionan dependen del dispositivo.

### Regla de UX

HYDRA **no debe afirmar que un paquete es seguro de bloquear solamente por ser una app del sistema**. Debe mostrar:

- **ALTO RIESGO**: componente crítico conocido.
- **PRECAUCIÓN**: parece proveedor/componente central, revisar.
- **RIESGO NO DETERMINADO**: no identificado como crítico, pero no se garantiza seguridad.

La evaluación es orientativa; no sustituye una prueba del usuario sobre ese dispositivo concreto.
