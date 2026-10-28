#!/usr/bin/env bash
# Regenera el pack de amenazas INCLUIDO en la app (assets/hydra_threat_pack_v1.json) desde
# assets/hydra_threat_seed.yar, firmado con TU clave privada. Necesario si cambiás HYDRA_THREAT_PUBLIC_KEY
# (el pack original está firmado con otra clave y la app lo rechazaría).
#   ./tools/rebuild_bundled_pack.sh [ruta/clave_privada.pem]
set -euo pipefail
cd "$(dirname "$0")/.."
KEY="${1:-secrets/hydra_threat_signing_key.pem}"
[ -f "$KEY" ] || { echo "No encuentro la clave privada: $KEY (generala con tools/generate_signing_key.sh)" >&2; exit 1; }
python3 tools/build_hydra_threat_pack.py \
  --output app/src/main/assets/hydra_threat_pack_v1.json \
  --private-key "$KEY" \
  --yara app/src/main/assets/hydra_threat_seed.yar \
  --expires-days 0
