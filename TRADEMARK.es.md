# Política de marca y nombre

🇬🇧 [English version](TRADEMARK.md)

El **código fuente** de Hydra Firewall es software libre bajo la
[GPL‑3.0‑or‑later](LICENSE). Puedes usarlo, estudiarlo, modificarlo y redistribuirlo bajo esa licencia,
incluso crear tu propio fork.

Los **nombres y logos** no forman parte de esa cesión. Con los términos adicionales que permite la
sección 7 de la GPL‑3.0, no se concede ningún derecho a usarlos salvo en lo que se describe abajo.

## Nombres y signos protegidos

- **Hydra Firewall**™
- **Hydraroot**™
- El logo de Hydra y los íconos de la app (por ejemplo `app/src/main/res/drawable-nodpi/hydra_tree.png`,
  `app/src/main/res/drawable-nodpi/ic_header_logo.png` y los archivos `ic_launcher*` de
  `app/src/main/res/mipmap-*`).

Identifican al proyecto oficial y a las versiones publicadas por su mantenedor (Hydraroot / WDS657).
Esta política no es una marca registrada: los nombres se usan como marcas de uso, y el mantenedor puede
registrarlos en el futuro.

## Lo que sí puedes hacer

- **Referirte al proyecto con exactitud**: "basado en Hydra Firewall", "fork de Hydra Firewall", "compatible con Hydra Firewall", o enlazar al repositorio.
- **Redistribuir las versiones oficiales sin modificar** (los APK publicados en los Releases del repositorio oficial) con su nombre e ícono intactos y conservando la licencia y los avisos.
- **Escribir, reseñar o hablar** del proyecto usando su nombre.
- **Compilarlo para ti o para tus pruebas** con el nombre original, siempre que no distribuyas esa versión a otras personas.

## Lo que no puedes hacer

- Distribuir una **versión modificada** (un fork) con el nombre *Hydra Firewall* o *Hydraroot*, ni con nombres que puedan confundirse con ellos.
- Usar el **logo o los íconos** en un fork, en la ficha de una tienda, en un sitio web o en un producto.
- Dar a entender que tu producto, servicio o sitio es **oficial, respaldado o patrocinado** por el proyecto cuando no lo es.
- Usar los nombres en un **dominio, `applicationId`, ficha de tienda o cuenta de redes sociales** de forma que pueda engañar a los usuarios.
- Usar los nombres para vender o promocionar un producto, o para recibir donaciones, como si fueras el proyecto oficial.

## Si haces un fork

1. Elige un **nombre distinto** y un **logo e ícono distintos**.
2. Cambiá `applicationId` en `app/build.gradle.kts` por un identificador propio y único para que tu versión derivada no reemplace ni entre en conflicto con otra app.
3. Conserva los avisos de copyright y de licencia que exige la GPL‑3.0, e indica claramente que tu proyecto deriva de Hydra Firewall.
4. Publica tu código fuente bajo la GPL‑3.0‑or‑later.

## Por qué existe esta política

Hydra es un firewall: la gente le confía todo su tráfico de red. Una versión modificada que parezca
oficial podría usarse para dañar a los usuarios. Esta política permite que cualquiera reutilice el
código y, a la vez, ayuda a distinguir la app oficial de las copias.

## Cómo denunciar un mal uso

Si encuentras una app, ficha de tienda o sitio web que use estos nombres o logos de forma engañosa,
abre un issue en este repositorio (sin publicar datos personales) o usa el formulario privado de
avisos de seguridad del repositorio si hay riesgo para los usuarios.

## Permisos

Si quieres usar el nombre o el logo de una forma no cubierta arriba, pídelo antes al mantenedor. Un
permiso solo es válido si el mantenedor lo da por escrito.

*Este documento es una política del proyecto, no asesoría legal. Los derechos de marca dependen de tu país.*
