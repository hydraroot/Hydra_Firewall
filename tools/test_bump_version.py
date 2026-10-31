import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("bump_version", Path(__file__).with_name("bump_version.py"))
bv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bv)


class BumpVersionTest(unittest.TestCase):
    def test_patch_minor_major(self):
        self.assertEqual(bv.bump((1, 1, 0), "patch"), (1, 1, 1))
        self.assertEqual(bv.bump((1, 1, 7), "minor"), (1, 2, 0))
        self.assertEqual(bv.bump((1, 4, 2), "major"), (2, 0, 0))

    def test_version_code_always_grows(self):
        seq = [(1, 0, 0), (1, 0, 1), (1, 1, 0), (1, 1, 1), (2, 0, 0)]
        codes = [bv.version_code(v) for v in seq]
        self.assertEqual(codes, sorted(set(codes)))
        self.assertGreater(codes[0], 164)  # la versión instalada antes de este esquema

    def test_rejects_overflow(self):
        with self.assertRaises(SystemExit):
            bv.bump((1, 99, 0), "minor")
        with self.assertRaises(SystemExit):
            bv.bump((1, 0, 99), "patch")

    def test_parse(self):
        self.assertEqual(bv.parse("# x\nVERSION_NAME=2.3.4\n"), (2, 3, 4))
        with self.assertRaises(SystemExit):
            bv.parse("VERSION_NAME=1.2\n")


if __name__ == "__main__":
    unittest.main()
