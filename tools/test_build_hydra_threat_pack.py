#!/usr/bin/env python3
"""Tests del generador de packs de amenazas. Ejecutar: python3 -m unittest discover -s tools -v"""
import base64
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import build_hydra_threat_pack as b  # noqa: E402

HAS_OPENSSL = shutil.which("openssl") is not None


class Ingest(unittest.TestCase):
    def setUp(self):
        self.d, self.i, self.u, self.h = {}, {}, {}, {}

    def test_urlhaus_keeps_ip_hosts_and_unknown_domains_only(self):
        text = "\n".join([
            "# comentario",
            "http://evil-payload.example.ru/a.apk",
            "https://raw.githubusercontent.com/x/y/z.apk",
            "http://cdn.discordapp.com/attachments/1.apk",
            "http://203.0.113.9:8080/bot",      # TEST-NET: no publica
            "http://8.8.4.4/bot",
            "http://127.0.0.1/x",
            "",
        ])
        b.ingest_urlhaus_text(text, self.d, self.i, self.u, self.h)
        self.assertEqual(sorted(self.d), ["evil-payload.example.ru"])
        self.assertEqual(sorted(self.i), ["8.8.4.4"])

    def test_feodo_drops_private_ips(self):
        data = [{"ip_address": "45.77.10.20", "malware": "QakBot"},
                {"ip_address": "10.0.0.5"}, {"ip_address": "192.168.1.1"}, {"ip_address": "no-es-ip"}]
        b.ingest_feodo(data, self.d, self.i, self.u, self.h)
        self.assertEqual(list(self.i), ["45.77.10.20"])
        self.assertEqual(self.i["45.77.10.20"]["family"], "QakBot")

    def test_sanitize_removes_safe_domains_and_ip_literals_from_manual_exports(self):
        for v in ["github.com", "objects.githubusercontent.com", "ok-malware.cn", "1.2.3.4", "localhost"]:
            b.add_indicator(self.d, v, name="x", family=None, source="t", severity=90, confidence=90)
        b.add_indicator(self.i, "192.168.0.9", name="x", family=None, source="t", severity=90, confidence=90)
        b.sanitize(self.d, self.i)
        self.assertEqual(sorted(self.d), ["ok-malware.cn"])
        self.assertEqual(self.i, {})

    def test_safe_domain_matches_suffix_not_substring(self):
        self.assertTrue(b.is_safe_domain("a.b.github.com"))
        self.assertFalse(b.is_safe_domain("notgithub.com"))
        self.assertFalse(b.is_safe_domain("github.com.evil.ru"))

    def test_cap_keeps_highest_confidence(self):
        store = {}
        for n in range(10):
            b.add_indicator(store, f"h{n}.bad", name="x", family=None, source="t", severity=50, confidence=n * 10)
        kept = b.cap(store, 3)
        self.assertEqual(sorted(kept), ["h7.bad", "h8.bad", "h9.bad"])


@unittest.skipUnless(HAS_OPENSSL, "requiere openssl")
class EndToEnd(unittest.TestCase):
    def test_signed_pack_verifies_and_min_indicators_guard(self):
        tmp = Path(tempfile.mkdtemp())
        key = tmp / "k.pem"
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)], check=True, capture_output=True)
        (tmp / "feodo.json").write_text(json.dumps([{"ip_address": "45.77.10.20", "malware": "QakBot"}]))
        script = str(Path(__file__).parent / "build_hydra_threat_pack.py")
        out = tmp / "pack.json"
        ok = subprocess.run([sys.executable, script, "--output", str(out), "--private-key", str(key),
                             "--feodo-file", str(tmp / "feodo.json"), "--min-indicators", "1"], capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        env = json.loads(out.read_text())
        payload = base64.b64decode(env["payload_base64"])
        (tmp / "p.bin").write_bytes(payload)
        (tmp / "s.bin").write_bytes(base64.b64decode(env["signature_base64"]))
        pub = subprocess.run(["openssl", "ec", "-in", str(key), "-pubout"], capture_output=True, check=True).stdout
        (tmp / "pub.pem").write_bytes(pub)
        v = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(tmp / "pub.pem"), "-signature", str(tmp / "s.bin"), str(tmp / "p.bin")], capture_output=True, text=True)
        self.assertIn("Verified OK", v.stdout)
        self.assertEqual([x["value"] for x in json.loads(payload)["ips"]], ["45.77.10.20"])

        bad = subprocess.run([sys.executable, script, "--output", str(tmp / "empty.json"), "--private-key", str(key),
                              "--min-indicators", "5"], capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertFalse((tmp / "empty.json").exists())
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
