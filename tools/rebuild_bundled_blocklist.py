#!/usr/bin/env python3
"""Regenera el blocklist de anuncios/trackers EMPAQUETADO en el APK
(app/src/main/assets/blocklist.txt.gz) desde las fuentes listadas en la
sección 1 de THIRD_PARTY_NOTICES.md.

Solo usa fuentes con licencia permisiva o CC0/CC BY (MIT, CC0-1.0, CC BY 3.0,
CC BY 4.0), porque empaquetar un archivo de otro autor dentro de un APK
GPL-3.0 es redistribuirlo y esas licencias sí lo permiten. Deliberadamente
NO toca HaGeZi ni 1Hosts (los descarga BlocklistUpdater en tiempo de
ejecución, no van empaquetados) ni ninguna fuente no comercial o sin
licencia declarada (MVPS, Dan Pollock, KADhosts, pgl.yoyo.org) — ver la
sección "Deliberadamente excluidas" de THIRD_PARTY_NOTICES.md.

Uso:
    python3 tools/rebuild_bundled_blocklist.py
    python3 tools/rebuild_bundled_blocklist.py --dry-run
    python3 tools/rebuild_bundled_blocklist.py --offline fuente.txt=cache/fuente.txt

Salida:
    app/src/main/assets/blocklist.txt.gz   (una línea por dominio, orden alfabético)
    app/src/main/assets/blocklist_meta.json

El resultado se puede reproducir y auditar: cada fuente es una raw URL pública
de GitHub, listada abajo junto con su licencia y el formato en que hay que
interpretarla.
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_GZ = REPO_ROOT / "app/src/main/assets/blocklist.txt.gz"
OUTPUT_META = REPO_ROOT / "app/src/main/assets/blocklist_meta.json"

USER_AGENT = "hydra-firewall-blocklist-builder/1.0 (+https://github.com/)"

# formato de cada fuente:
#   "hosts"  -> líneas "0.0.0.0 dominio" / "127.0.0.1 dominio" (se descarta localhost)
#   "plain"  -> un dominio por línea, sin prefijo
FORMAT_HOSTS = "hosts"
FORMAT_PLAIN = "plain"


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    license: str
    fmt: str


# Misma tabla que la sección 1 de THIRD_PARTY_NOTICES.md. Si agregás o sacás
# una fuente acá, actualizá esa tabla también.
SOURCES: list[Source] = [
    Source(
        "Steven Black's ad-hoc list",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
        "MIT",
        FORMAT_HOSTS,
    ),
    Source(
        "AdAway",
        "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
        "CC BY 3.0",
        FORMAT_HOSTS,
    ),
    Source(
        "add.2o7Net (FadeMind hosts.extras)",
        "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
        "MIT",
        FORMAT_HOSTS,
    ),
    Source(
        "add.Dead (FadeMind hosts.extras)",
        "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Dead/hosts",
        "MIT",
        FORMAT_HOSTS,
    ),
    Source(
        "add.Risk (FadeMind hosts.extras)",
        "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
        "MIT",
        FORMAT_HOSTS,
    ),
    Source(
        "add.Spam (FadeMind hosts.extras)",
        "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
        "MIT",
        FORMAT_HOSTS,
    ),
    Source(
        "UncheckyAds (FadeMind hosts.extras)",
        "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
        "MIT",
        FORMAT_HOSTS,
    ),
    Source(
        "Mitchell Krog's Badd Boyz Hosts",
        "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts",
        "MIT",
        FORMAT_HOSTS,
    ),
    Source(
        "hostsVN",
        "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
        "MIT",
        FORMAT_HOSTS,
    ),
    Source(
        "minecraft-hosts (tracking list)",
        "https://raw.githubusercontent.com/jamiemansfield/minecraft-hosts/master/lists/tracking.txt",
        "CC0-1.0",
        FORMAT_PLAIN,
    ),
    Source(
        "Tiuxo hostlist - ads",
        "https://raw.githubusercontent.com/tiuxo/hosts/master/ads",
        "CC BY 4.0",
        FORMAT_PLAIN,
    ),
]

HOSTS_LINE_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+)")
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
IGNORED_HOSTNAMES = {"localhost", "localhost.localdomain", "broadcasthost", "local", "ip6-localhost",
                      "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters"}


def fetch(url: str, timeout: int = 30) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:  # nosec - fuentes fijas, raw.githubusercontent.com
        return resp.read().decode("utf-8", errors="replace")


def normalize_domain(value: str) -> str | None:
    d = value.strip().strip(".").lower()
    if not d or d in IGNORED_HOSTNAMES:
        return None
    if not DOMAIN_RE.match(d):
        return None
    return d


def parse_hosts(text: str) -> set[str]:
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = HOSTS_LINE_RE.match(line)
        if not m:
            continue
        d = normalize_domain(m.group(1))
        if d:
            domains.add(d)
    return domains


def parse_plain(text: str) -> set[str]:
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        # algunas listas "plain" igual traen un prefijo de IP; lo toleramos
        m = HOSTS_LINE_RE.match(line)
        candidate = m.group(1) if m else line.split()[0]
        d = normalize_domain(candidate)
        if d:
            domains.add(d)
    return domains


def parse_source(source: Source, text: str) -> set[str]:
    if source.fmt == FORMAT_HOSTS:
        return parse_hosts(text)
    if source.fmt == FORMAT_PLAIN:
        return parse_plain(text)
    raise ValueError(f"Formato desconocido: {source.fmt}")


def build(offline_map: dict[str, Path], dry_run: bool) -> tuple[set[str], str]:
    all_domains: set[str] = set()
    names = []
    for source in SOURCES:
        if source.name in offline_map:
            text = offline_map[source.name].read_text(encoding="utf-8", errors="replace")
        else:
            print(f"-> descargando: {source.name} ({source.license})", file=sys.stderr)
            text = fetch(source.url)
        found = parse_source(source, text)
        print(f"   {len(found)} dominios", file=sys.stderr)
        all_domains |= found
        names.append(source.name)

    label = (
        "Hydra license-compatible bundle (" + " + ".join(
            n.split(" (")[0] for n in names
        ) + ")"
    )
    return all_domains, label


def write_outputs(domains: set[str], label: str, dry_run: bool) -> None:
    ordered = sorted(domains)
    meta = {
        "source": label,
        "sourceUrl": "https://github.com/StevenBlack/hosts",
        "license": "Mixed: MIT, CC0-1.0, CC BY 3.0, CC BY 4.0 (see THIRD_PARTY_NOTICES.md section 1)",
        "listDate": time.strftime("%Y-%m-%d", time.gmtime()),
        "domainCount": len(ordered),
        "note": (
            "Regenerated to drop StevenBlack's unified list and exclude MVPS (CC BY-NC-SA, "
            "non-commercial), Dan Pollock/someonewhocares (non-commercial with attribution), "
            "KADhosts (CC BY-SA 4.0, share-alike) and pgl.yoyo.org (no declared license), none "
            "of which are redistributable inside a GPL-3.0 APK. HaGeZi and 1Hosts are still "
            "fetched at runtime by BlocklistUpdater, not bundled."
        ),
    }

    print(f"Total de dominios combinados: {len(ordered)}", file=sys.stderr)

    if dry_run:
        print("--dry-run: no se escribió ningún archivo.", file=sys.stderr)
        print(json.dumps(meta, ensure_ascii=False, indent=2))
        return

    OUTPUT_GZ.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(OUTPUT_GZ, "wt", encoding="utf-8") as fh:
        fh.write("\n".join(ordered) + "\n")

    OUTPUT_META.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Escrito: {OUTPUT_GZ}", file=sys.stderr)
    print(f"Escrito: {OUTPUT_META}", file=sys.stderr)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--offline",
        action="append",
        default=[],
        metavar="NOMBRE_FUENTE=ruta/archivo.txt",
        help="usar un archivo local en vez de descargar esa fuente (podés repetir la opción)",
    )
    p.add_argument("--dry-run", action="store_true", help="no escribir archivos; solo mostrar el resumen")
    args = p.parse_args()

    offline_map: dict[str, Path] = {}
    for item in args.offline:
        if "=" not in item:
            p.error(f"--offline espera NOMBRE_FUENTE=ruta, recibí: {item}")
        name, _, path = item.partition("=")
        known_names = {s.name for s in SOURCES}
        if name not in known_names:
            p.error(f"fuente desconocida para --offline: {name!r}. Fuentes válidas: {sorted(known_names)}")
        offline_map[name] = Path(path)

    domains, label = build(offline_map, args.dry_run)
    write_outputs(domains, label, args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
