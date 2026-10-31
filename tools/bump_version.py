#!/usr/bin/env python3
"""Sube la versión de Hydra Firewall en version.properties.

Uso:  python tools/bump_version.py patch|minor|major [--dry-run]

  patch  1.0.4 -> 1.0.5   cambios pequeños
  minor  1.0.5 -> 1.1.0   cambios medianos (el parche vuelve a 0)
  major  1.4.2 -> 2.0.0   cambios grandes (menor y parche vuelven a 0)

versionCode = mayor*10000 + menor*100 + parche (así siempre crece al subir la versión).
"""
import re
import sys
from pathlib import Path

FILE = Path(__file__).resolve().parent.parent / "version.properties"


def parse(text: str):
    m = re.search(r"^VERSION_NAME=(\d+)\.(\d+)\.(\d+)\s*$", text, re.M)
    if not m:
        raise SystemExit("version.properties no tiene VERSION_NAME=MAYOR.MENOR.PARCHE")
    return tuple(int(x) for x in m.groups())


def bump(version, kind):
    major, minor, patch = version
    if kind == "patch":
        patch += 1
    elif kind == "minor":
        minor, patch = minor + 1, 0
    elif kind == "major":
        major, minor, patch = major + 1, 0, 0
    else:
        raise SystemExit("Tipo inválido: usá patch, minor o major")
    if minor > 99 or patch > 99:
        raise SystemExit("menor y parche deben ser <= 99 (el versionCode usa 2 dígitos para cada uno)")
    return major, minor, patch


def version_code(v):
    return v[0] * 10000 + v[1] * 100 + v[2]


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        raise SystemExit(__doc__)
    text = FILE.read_text(encoding="utf-8")
    old = parse(text)
    new = bump(old, args[0])
    name = ".".join(map(str, new))
    print(f"{'.'.join(map(str, old))} (code {version_code(old)}) -> {name} (code {version_code(new)})")
    if "--dry-run" not in argv:
        FILE.write_text(re.sub(r"^VERSION_NAME=.*$", f"VERSION_NAME={name}", text, flags=re.M), encoding="utf-8")
        print("version.properties actualizado. Recordá agregar la entrada en CHANGELOG.md y, para publicar, crear la etiqueta v" + name)


if __name__ == "__main__":
    main(sys.argv)
