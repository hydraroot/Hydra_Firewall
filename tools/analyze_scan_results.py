#!/usr/bin/env python3
"""Analyze the bulk-scan results copied from Hydra Firewall (Security > MH-100K scanner > "Copy results").

Usage:  python tools/analyze_scan_results.py results.txt [--max-store-flag-pct 1.0]

Input is tab-separated: score, label, package, source (store/sideload/system/unknown), risk, seconds, verdict, note.
Lines starting with '#' are headers. Older copies without the source column are also accepted.

It prints how scores are distributed per app source and suggests the lowest score threshold that flags at most
--max-store-flag-pct percent of the apps installed from a store (those are mostly legitimate, so flags there are
mostly false positives). It is a calibration aid, not proof: apps from stores can still be malicious.
"""
import argparse
import sys

SOURCES = ("store", "sideload", "system", "unknown")
BUCKETS = [(0, 24), (25, 49), (50, 74), (75, 89), (90, 100)]


def parse(text):
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        p = line.split("\t")
        if len(p) < 3:
            continue
        score = int(p[0]) if p[0].strip().lstrip("-").isdigit() else None
        has_src = len(p) >= 4 and p[3].strip() in SOURCES
        rows.append({"score": score, "label": p[1], "pkg": p[2], "source": p[3].strip() if has_src else "unknown"})
    return rows


def bucket_of(score):
    for lo, hi in BUCKETS:
        if lo <= score <= hi:
            return f"{lo}-{hi}"
    return "?"


def distribution(rows):
    out = {}
    for r in rows:
        if r["score"] is None:
            continue
        out.setdefault(r["source"], {})
        b = bucket_of(r["score"])
        out[r["source"]][b] = out[r["source"]].get(b, 0) + 1
    return out


def suggest_threshold(rows, max_store_flag_pct=1.0):
    """Lowest threshold T (0-100) such that at most max_store_flag_pct % of store apps have score >= T."""
    store = [r["score"] for r in rows if r["source"] == "store" and r["score"] is not None]
    if not store:
        return None
    for t in range(0, 101):
        if 100.0 * sum(1 for s in store if s >= t) / len(store) <= max_store_flag_pct:
            return t
    return 100


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--max-store-flag-pct", type=float, default=1.0)
    a = ap.parse_args(argv)
    rows = parse(open(a.file, encoding="utf-8").read())
    scored = [r for r in rows if r["score"] is not None]
    print(f"Apps: {len(rows)} | with score: {len(scored)} | without score: {len(rows) - len(scored)}")
    dist = distribution(rows)
    for src in SOURCES:
        if src not in dist:
            continue
        total = sum(dist[src].values())
        print(f"\n[{src}] {total} apps")
        for lo, hi in BUCKETS:
            n = dist[src].get(f"{lo}-{hi}", 0)
            print(f"  {lo:>3}-{hi:<3} {n:>4}  {100.0 * n / total:5.1f}%")
    t = suggest_threshold(rows, a.max_store_flag_pct)
    if t is None:
        print("\nNo store-installed apps with score: cannot suggest a threshold.")
    else:
        print(f"\nSuggested threshold: {t} (flags <= {a.max_store_flag_pct}% of store apps).")
        for r in sorted(scored, key=lambda r: -r["score"])[:10]:
            print(f"  top: {r['score']:>3} {r['source']:<8} {r['label']} ({r['pkg']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
