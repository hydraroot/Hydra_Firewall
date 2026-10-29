# Política de seguridad

Hydra Firewall es una app que intercepta todo el tráfico de red del teléfono
(VPN local, sin root) y toma decisiones de bloqueo. Tomamos en serio
cualquier falla que pueda:

- dejar pasar tráfico que debería bloquearse (fuga por fuera de la VPN,
  bypass de reglas, DNS/SNI/QUIC sin filtrar cuando debería filtrarse);
- exponer datos del usuario (reglas, historial, estadísticas, PIN) a otra
  app o a un proceso sin permisos;
- permitir que un pack de amenazas o una actualización de listas no
  firmada/manipulada sea aceptada por `ThreatSignatureVerifier`;
- comprometer la firma de la app o la keystore de release.

## Cómo reportar una vulnerabilidad

**No abras un issue público para vulnerabilidades.** Un issue público es
visible para cualquiera antes de que exista una corrección, incluida gente
con intención de explotarla.

Opciones, de preferida a alternativa:

1. **GitHub Security Advisories** (preferido): desde la pestaña *Security*
   del repositorio → *Report a vulnerability*. Esto abre un reporte privado
   visible solo para los mantenedores, con su propio hilo de discusión.
2. Si no podés usar Security Advisories, abrí un issue vacío pidiendo un
   canal de contacto privado, sin describir el problema, y seguimos por ahí.

Incluí, si lo tenés:

- Versión de la app (tag o commit) y versión de Android donde lo probaste.
- Pasos para reproducir, o un PoC mínimo.
- Qué esperabas que pasara y qué pasó en realidad.
- Impacto estimado (fuga de tráfico, bypass de reglas, fuga de datos, etc.).

## Qué esperar

- Confirmación de recepción en un plazo razonable.
- Una vez confirmada la falla, trabajamos en una corrección antes de hacer
  cualquier mención pública (divulgación coordinada). Si querés, te damos
  crédito en el `CHANGELOG` al publicar el fix.
- Para fallas de bajo impacto o que ya son de conocimiento público, un issue
  normal está bien.

## Alcance

Dentro de alcance: el código de la app (`app/`), los scripts de firma y
generación de packs (`tools/`), y los workflows de CI (`.github/workflows/`).

Fuera de alcance: vulnerabilidades en dependencias de terceros ya conocidas
y sin parche disponible aguas arriba (reportalas directamente al proyecto
correspondiente), e ingeniería social contra usuarios individuales.
