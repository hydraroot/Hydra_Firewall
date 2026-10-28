#!/usr/bin/env python3
"""Verifica la firma ECDSA P-256/SHA-256 de un pack de amenazas de Hydra.

Uso:
  pip install cryptography
  python tools/verify_threat_pack.py hydra_threat_pack.json
  python tools/verify_threat_pack.py https://raw.githubusercontent.com/hydraroot/Hydra_Firewall/threat-pack/hydra_threat_pack.json

Sin --key usa la clave publica de app/build.gradle.kts. Sale con codigo 0 si la firma es valida.
"""
import argparse, base64, json, re, sys, urllib.request
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parent.parent


def default_key() -> str:
    text = (ROOT / "app" / "build.gradle.kts").read_text(encoding="utf-8")
    m = re.search(r'"(MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE[A-Za-z0-9+/=]+)"', text)
    if not m:
        sys.exit("No se encontro la clave por defecto en app/build.gradle.kts")
    return m.group(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pack", help="ruta o URL https del pack")
    ap.add_argument("--key", help="clave publica X.509 DER en Base64 (opcional)")
    a = ap.parse_args()
    if a.pack.startswith("https://"):
        with urllib.request.urlopen(a.pack, timeout=30) as r:
            raw = r.read().decode("utf-8")
    else:
        raw = Path(a.pack).read_text(encoding="utf-8")
    env = json.loads(raw)
    payload = base64.b64decode(env["payload_base64"])
    sig = base64.b64decode(env["signature_base64"])
    key = serialization.load_der_public_key(base64.b64decode(a.key or default_key()))
    try:
        key.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
    except Exception:
        print("FIRMA INVALIDA para esa clave")
        return 1
    print("FIRMA VALIDA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
