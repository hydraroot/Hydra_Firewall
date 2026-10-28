#!/usr/bin/env bash
# Genera el par de claves P-256 con el que firmás los packs de amenazas.
#   - secrets/hydra_threat_signing_key.pem  -> PRIVADA. Nunca la subas (va como secret HYDRA_THREAT_SIGNING_KEY).
#   - secrets/hydra_threat_public_key.b64   -> pública (Base64 DER). Va en HYDRA_THREAT_PUBLIC_KEY.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p secrets
[ -f secrets/hydra_threat_signing_key.pem ] && { echo "Ya existe secrets/hydra_threat_signing_key.pem (no lo piso)."; exit 1; }
openssl ecparam -name prime256v1 -genkey -noout -out secrets/hydra_threat_signing_key.pem
openssl ec -in secrets/hydra_threat_signing_key.pem -pubout -outform DER 2>/dev/null | base64 -w0 > secrets/hydra_threat_public_key.b64
echo
echo "Clave privada : secrets/hydra_threat_signing_key.pem  (GUARDALA, hacé backup)"
echo "Clave pública : $(cat secrets/hydra_threat_public_key.b64)"
echo "Poné la pública en local.properties como HYDRA_THREAT_PUBLIC_KEY=... y corré tools/rebuild_bundled_pack.sh"
