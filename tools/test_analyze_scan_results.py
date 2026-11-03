import unittest
import analyze_scan_results as a

SAMPLE = "# Hydra MH-100K scan | v2.2.0\n# score\tlabel\tpackage\tsource\n" + "\n".join(
    [f"{s}\tApp{i}\tp.a{i}\tstore\trisk=1\t1s\tOK\t" for i, s in enumerate([5] * 98 + [60, 95])]
    + ["99\tBad\tp.bad\tsideload\trisk=9\t1s\tHIGH\t", "-\tBig\tp.big\tstore\trisk=0\t120s\t\tTIMEOUT", "40\tOld\tp.old"]
)


class T(unittest.TestCase):
    def test_parse(self):
        rows = a.parse(SAMPLE)
        self.assertEqual(len(rows), 103)
        self.assertEqual(rows[-1]["source"], "unknown")
        self.assertIsNone(rows[-2]["score"])

    def test_distribution(self):
        d = a.distribution(a.parse(SAMPLE))
        self.assertEqual(d["store"]["0-24"], 98)
        self.assertEqual(d["sideload"]["90-100"], 1)

    def test_threshold(self):
        rows = a.parse(SAMPLE)
        # 100 scored store apps, 2 are >= 60: 1% allows only 1 -> threshold above 60
        self.assertEqual(a.suggest_threshold(rows, 1.0), 61)
        self.assertIsNone(a.suggest_threshold(a.parse("99\tX\tp\tsideload"), 1.0))


if __name__ == "__main__":
    unittest.main()
