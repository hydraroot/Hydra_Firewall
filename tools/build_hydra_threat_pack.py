#!/usr/bin/env python3
"""Build and sign a Hydra Threat Signatures v1 envelope.

Feeds en vivo (sin tocar la app): --feodo (sin clave), --urlhaus-api, --threatfox-api
(abuse.ch pide una Auth-Key gratuita en https://auth.abuse.ch/ -> variable ABUSECH_AUTH_KEY).

Accepted inputs:
  * ThreatFox JSON/CSV exports
  * URLhaus JSON/CSV exports
  * directories/files containing YARA rules

For live ThreatFox/URLhaus bulk feeds, use your own abuse.ch auth keys. Do not
embed an API key in the Android application.
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import subprocess
import re
import sys
import tempfile
import time
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def now() -> int:
    return int(time.time() * 1000)


def normalize(value: str) -> str:
    return value.strip().strip('.').lower()


def add_indicator(store: dict[str, dict], value: str, *, name: str, family: str | None,
                  source: str, severity: int, confidence: int, detail: str = "") -> None:
    v = normalize(value)
    if not v:
        return
    current = store.get(v)
    candidate = {
        "value": v,
        "name": name[:120],
        "family": family,
        "source": source,
        "severity": max(0, min(100, int(severity))),
        "confidence": max(0, min(100, int(confidence))),
        "detail": detail[:300] if detail else "Threat intelligence match",
    }
    if current is None or candidate["confidence"] > current["confidence"]:
        store[v] = candidate


def load_structured(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in {".json", ".js"} or text.lstrip().startswith("{"):
        return json.loads(text)
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(line for line in f if not line.startswith("#")))


def ingest_threatfox(data, domains, ips, urls, hashes):
    rows = data.get("data", []) if isinstance(data, dict) else data
    for row in rows or []:
        ioc = str(row.get("ioc", "")).strip()
        if not ioc:
            continue
        typ = str(row.get("ioc_type", "")).lower()
        family = row.get("malware_printable") or row.get("malware") or row.get("malware_alias")
        threat = row.get("threat_type_desc") or row.get("threat_type") or "ThreatFox IOC"
        severity = 95 if "botnet" in str(row.get("threat_type", "")).lower() or "payload" in str(row.get("threat_type", "")).lower() else 85
        conf = int(row.get("confidence_level") or 80)
        detail = f"ThreatFox • {threat}"
        if "domain" in typ:
            add_indicator(domains, ioc, name="ThreatFox domain", family=family, source="ThreatFox", severity=severity, confidence=conf, detail=detail)
        elif typ.startswith("ip"):
            add_indicator(ips, ioc.split(":", 1)[0], name="ThreatFox IP", family=family, source="ThreatFox", severity=severity, confidence=conf, detail=detail)
        elif "url" in typ:
            add_indicator(urls, ioc, name="ThreatFox URL", family=family, source="ThreatFox", severity=severity, confidence=conf, detail=detail)
        elif "sha256" in typ or row.get("sha256_hash"):
            h = str(row.get("sha256_hash") or ioc).lower().strip()
            if len(h) == 64:
                add_indicator(hashes, h, name="ThreatFox SHA-256", family=family, source="ThreatFox", severity=95, confidence=conf, detail=detail)


def ingest_urlhaus(data, domains, ips, urls, hashes):
    rows = data.get("data", []) if isinstance(data, dict) else data
    for row in rows or []:
        url = str(row.get("url", "")).strip()
        host = str(row.get("host", "")).strip()
        sha = str(row.get("sha256_hash") or row.get("sha256") or "").strip().lower()
        tags = str(row.get("tags", "")).strip()
        threat = str(row.get("threat", "malware distribution"))
        detail = f"URLhaus • {threat}" + (f" • {tags}" if tags else "")
        if url:
            add_indicator(urls, url, name="URLhaus malware URL", family=tags or None, source="URLhaus", severity=95, confidence=95, detail=detail)
        if host:
            add_indicator(domains, host, name="URLhaus malware host", family=tags or None, source="URLhaus", severity=90, confidence=95, detail=detail)
        if sha and len(sha) == 64:
            add_indicator(hashes, sha, name="URLhaus payload SHA-256", family=tags or None, source="URLhaus", severity=95, confidence=95, detail=detail)


# Dominios que NUNCA deben entrar como "amenaza" aunque un feed los liste (alojan contenido legítimo:
# los feeds de malware a menudo reportan URLs puntuales dentro de ellos). Bloquear el dominio entero
# rompería apps comunes, y la app trata las coincidencias de amenaza como autoridad máxima.
SAFE_DOMAIN_SUFFIXES = {
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
    "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "gvt1.com", "youtube.com",
    "dropbox.com", "dropboxusercontent.com", "onedrive.live.com", "live.com", "microsoft.com",
    "windows.net", "azureedge.net", "amazonaws.com", "cloudfront.net", "cloudflare.com", "workers.dev",
    "pages.dev", "herokuapp.com", "netlify.app", "vercel.app", "firebaseapp.com", "web.app",
    "discord.com", "discordapp.com", "discordapp.net", "telegram.org", "t.me", "whatsapp.com",
    "mediafire.com", "mega.nz", "mega.io", "wetransfer.com", "box.com", "pastebin.com",
    "apple.com", "icloud.com", "mozilla.org", "wikipedia.org", "archive.org", "bit.ly", "tinyurl.com",
    "facebook.com", "fbcdn.net", "instagram.com", "twitter.com", "x.com", "twimg.com", "cdn.jsdelivr.net",
    "jsdelivr.net", "unpkg.com", "mercadolibre.com", "mercadopago.com", "mercadolibre.com.ar",
}

MAX_DOMAINS = 150_000
MAX_IPS = 60_000


def is_safe_domain(host: str) -> bool:
    h = host.lower().strip(".")
    return any(h == d or h.endswith("." + d) for d in SAFE_DOMAIN_SUFFIXES)


def is_ip_literal(value: str) -> bool:
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    try:
        ip = ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified)


def ingest_feodo(data, domains, ips, urls, hashes):
    """Feodo Tracker ipblocklist.json (C2 de botnets: Emotet, QakBot, Dridex...). Sin API key."""
    rows = data if isinstance(data, list) else data.get("blocklist", data.get("data", []))
    for row in rows or []:
        ip = str(row.get("ip_address", "")).strip()
        if not is_public_ip(ip):
            continue
        family = row.get("malware") or "botnet C2"
        add_indicator(ips, ip, name="Feodo Tracker C2", family=family, source="Feodo Tracker",
                      severity=95, confidence=95, detail=f"Feodo Tracker • botnet C2 • {family}")


def ingest_urlhaus_text(text: str, domains, ips, urls, hashes):
    """URLhaus text_online: una URL por linea. Solo se usa el HOST (la app filtra por dominio/IP)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            host = (urlsplit(line).hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        if is_ip_literal(host):
            if not is_public_ip(host):
                continue
            add_indicator(ips, host, name="URLhaus malware host", family=None, source="URLhaus",
                          severity=90, confidence=85, detail="URLhaus • host distribuyendo malware")
        elif "." in host and not is_safe_domain(host):
            add_indicator(domains, host, name="URLhaus malware host", family=None, source="URLhaus",
                          severity=90, confidence=85, detail="URLhaus • host distribuyendo malware")


def fetch_post_json(url: str, payload: dict, auth_key: str | None = None):
    req = Request(url, data=json.dumps(payload).encode(), method="POST",
                  headers={"User-Agent": "Hydra-Threat-Pack-Builder/1.1", "Content-Type": "application/json"})
    if auth_key:
        req.add_header("Auth-Key", auth_key)
    with urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def sanitize(domains: dict, ips: dict) -> None:
    """Quita dominios seguros / IPs no publicas que se hayan colado por exports manuales."""
    for k in [k for k in domains if is_safe_domain(k) or "." not in k or is_ip_literal(k)]:
        del domains[k]
    for k in [k for k in ips if not is_public_ip(k)]:
        del ips[k]


def cap(store: dict, limit: int) -> dict:
    if len(store) <= limit:
        return store
    keep = sorted(store.values(), key=lambda x: (-x["confidence"], -x["severity"], x["value"]))[:limit]
    return {x["value"]: x for x in keep}


def collect_yara(paths: list[Path]):
    out = []
    for base in paths:
        if base.is_dir():
            files = [p for p in base.rglob("*") if p.is_file() and p.suffix.lower() in {".yar", ".yara"}]
        else:
            files = [base]
        for p in files:
            source = p.read_text(encoding="utf-8", errors="replace")
            if source.strip():
                out.append({"source": source})
    return out


def fetch_url(url: str, auth_key: str | None = None) -> str:
    req = Request(url, headers={"User-Agent": "Hydra-Threat-Pack-Builder/1.0"})
    if auth_key:
        req.add_header("Auth-Key", auth_key)
    with urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="replace")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True, help="signed envelope output JSON")
    p.add_argument("--private-key", required=True, help="P-256 PEM private key")
    p.add_argument("--threatfox-export", action="append", default=[])
    p.add_argument("--urlhaus-export", action="append", default=[])
    p.add_argument("--yara", action="append", default=[], help="YARA file or directory")
    p.add_argument("--threatfox-api", action="store_true", help="ThreatFox (requiere THREATFOX_AUTH_KEY)")
    p.add_argument("--threatfox-days", type=int, default=7)
    p.add_argument("--urlhaus-api", action="store_true", help="URLhaus text_online (URLHAUS_AUTH_KEY opcional)")
    p.add_argument("--feodo", action="store_true", help="Feodo Tracker ipblocklist (sin clave)")
    p.add_argument("--feodo-file", action="append", default=[], help="ipblocklist.json descargado a mano")
    p.add_argument("--urlhaus-text-file", action="append", default=[], help="text_online descargado a mano")
    p.add_argument("--min-indicators", type=int, default=0,
                   help="Falla si el pack tiene menos de N indicadores (evita publicar un pack vacio por un feed caido)")
    p.add_argument("--expires-days", type=int, default=30, help="Days until pack expiry; 0 creates a non-expiring seed pack")
    return p.parse_args()


def sign_payload(payload: bytes, private_key: str) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(payload)
        payload_path = f.name
    with tempfile.NamedTemporaryFile(delete=False) as f:
        sig_path = f.name
    try:
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", private_key, "-out", sig_path, payload_path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return Path(sig_path).read_bytes()
    finally:
        for p in (payload_path, sig_path):
            try: os.unlink(p)
            except OSError: pass


def main() -> None:
    args = parse_args()
    domains: dict[str, dict] = {}
    ips: dict[str, dict] = {}
    urls: dict[str, dict] = {}
    hashes: dict[str, dict] = {}
    sources = []

    for raw in args.threatfox_export:
        ingest_threatfox(load_structured(Path(raw)), domains, ips, urls, hashes)
        sources.append("ThreatFox")
    for raw in args.urlhaus_export:
        ingest_urlhaus(load_structured(Path(raw)), domains, ips, urls, hashes)
        sources.append("URLhaus")

    for raw in args.feodo_file:
        ingest_feodo(json.loads(Path(raw).read_text(encoding="utf-8")), domains, ips, urls, hashes)
        sources.append("Feodo Tracker")
    for raw in args.urlhaus_text_file:
        ingest_urlhaus_text(Path(raw).read_text(encoding="utf-8", errors="replace"), domains, ips, urls, hashes)
        sources.append("URLhaus")

    def run_feed(label, fn):
        try:
            fn()
            sources.append(label)
            print(f"[ok] {label}", file=sys.stderr)
        except Exception as exc:  # un feed caido no debe tirar todo el pack
            print(f"[WARN] {label} fallo: {exc}", file=sys.stderr)

    if args.feodo:
        run_feed("Feodo Tracker", lambda: ingest_feodo(
            json.loads(fetch_url("https://feodotracker.abuse.ch/downloads/ipblocklist.json", os.environ.get("ABUSECH_AUTH_KEY"))),
            domains, ips, urls, hashes))
    if args.urlhaus_api:
        run_feed("URLhaus", lambda: ingest_urlhaus_text(
            fetch_url("https://urlhaus.abuse.ch/downloads/text_online/", os.environ.get("URLHAUS_AUTH_KEY") or os.environ.get("ABUSECH_AUTH_KEY")),
            domains, ips, urls, hashes))
    if args.threatfox_api:
        key = os.environ.get("THREATFOX_AUTH_KEY") or os.environ.get("ABUSECH_AUTH_KEY")
        if not key:
            print("[WARN] ThreatFox omitido: falta THREATFOX_AUTH_KEY", file=sys.stderr)
        else:
            run_feed("ThreatFox", lambda: ingest_threatfox(
                fetch_post_json("https://threatfox-api.abuse.ch/api/v1/", {"query": "get_iocs", "days": max(1, min(7, args.threatfox_days))}, key),
                domains, ips, urls, hashes))

    sanitize(domains, ips)
    domains = cap(domains, MAX_DOMAINS)
    ips = cap(ips, MAX_IPS)

    total = len(domains) + len(ips) + len(urls) + len(hashes)
    if total < args.min_indicators:
        raise SystemExit(f"Pack rechazado: {total} indicadores < minimo {args.min_indicators} (feeds caidos?)")

    yara_paths = [Path(x) for x in args.yara]
    yara_rules = collect_yara(yara_paths)
    if yara_rules:
        sources.append("YARA rule sources (license metadata must be preserved by the pack distributor)")

    timestamp = now()
    payload = {
        "schema": 1,
        "pack_version": time.strftime("%Y.%m.%d.%H%M", time.gmtime(timestamp / 1000)),
        "generated_at": timestamp,
        "expires_at": 0 if args.expires_days <= 0 else timestamp + args.expires_days * 86400000,
        "sources": sorted(set(sources)) or ["Hydra local seed"],
        "sha256": sorted(hashes.values(), key=lambda x: x["value"]),
        "domains": sorted(domains.values(), key=lambda x: x["value"]),
        "ips": sorted(ips.values(), key=lambda x: x["value"]),
        "urls": sorted(urls.values(), key=lambda x: x["value"]),
        "yara_rules": yara_rules,
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = sign_payload(payload_bytes, args.private_key)
    envelope = {
        "schema": 1,
        "algorithm": "SHA256withECDSA",
        "payload_base64": base64.b64encode(payload_bytes).decode("ascii"),
        "signature_base64": base64.b64encode(sig).decode("ascii"),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(out),
        "sha256": len(payload["sha256"]),
        "domains": len(payload["domains"]),
        "ips": len(payload["ips"]),
        "urls": len(payload["urls"]),
        "yara_rules": len(payload["yara_rules"]),
        "sources": payload["sources"],
    }, indent=2))


if __name__ == "__main__":
    main()
