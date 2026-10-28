#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Validate three paired benchmark boots and preserve every raw CSV row."""
import argparse
import csv
import io
import json
import statistics
from pathlib import Path


def block(text, begin, end):
    if text.count(begin) != 1 or text.count(end) != 1:
        raise ValueError(f"missing/duplicate CSV marker: {begin}")
    return list(csv.DictReader(io.StringIO(text.split(begin)[1].split(end)[0].strip())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("logs", nargs=6, type=Path, metavar="LOG",
                        help="six logs in A1 B1 A2 B2 A3 B3 order")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    groups = {}
    raw = []
    for index, path in enumerate(args.logs):
        text = path.read_text(errors="replace").replace("\r", "")
        if "LUA_LSM_RUN_END mode=perf status=0" not in text:
            raise ValueError(f"guest failed: {path}")
        if "LUA-LSM-SHDICT-BENCH: ALL PASS" not in text or "LUA-LSM-MANAGE-BENCH: ALL PASS" not in text:
            raise ValueError(f"benchmark failed: {path}")
        pair, version = index // 2 + 1, "AB"[index % 2]
        scalar = block(text, "BENCH_CSV_BEGIN", "BENCH_CSV_END")
        management = block(text, "MANAGE_CSV_BEGIN", "MANAGE_CSV_END")
        if len(scalar) != 125 or len(management) != 30:
            raise ValueError(f"wrong row count: {path}")
        seen = set()
        for kind, rows in (("scalar", scalar), ("management", management)):
            for row in rows:
                if int(row["errors"]) or float(row["ops_s"]) <= 0:
                    raise ValueError(f"invalid row: {path}: {row}")
                key = (kind, row["op"], row.get("bytes", ""), row["threads"], row.get("layout", ""))
                identity = (key, row["repeat"])
                if identity in seen:
                    raise ValueError(f"duplicate row: {path}: {identity}")
                seen.add(identity)
                expected = 10000 if kind == "scalar" else 1000 * int(row["threads"])
                if int(row["requests"]) != expected or int(row["repeat"]) not in range(1, 6):
                    raise ValueError(f"invalid samples: {path}: {row}")
                groups.setdefault((pair, version, key), []).append(row)
                raw.append({"pair": pair, "version": version, "kind": kind, **row})
    summaries = []
    keys = sorted({key for _, _, key in groups})
    for key in keys:
        changes = []
        pairs = []
        for pair in range(1, 4):
            medians = {}
            for version in "AB":
                rows = groups[(pair, version, key)]
                if len(rows) != 5:
                    raise ValueError(f"not five repeats: {pair} {version} {key}")
                medians[version] = {
                    field: statistics.median(float(row[field]) for row in rows)
                    for field in ("ops_s", "mean_us", "p50_us", "p95_us", "p99_us")
                }
            change = (medians["B"]["ops_s"] / medians["A"]["ops_s"] - 1) * 100
            changes.append(change)
            pairs.append({"pair": pair, **medians, "throughput_change_percent": change})
        summaries.append({"scenario": key, "pairs": pairs,
                          "median_change_percent": statistics.median(changes),
                          "consistent_regression_over_10_percent": all(x < -10 for x in changes)})
    fields = list(dict.fromkeys(field for row in raw for field in row))
    with (args.output / "raw.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(raw)
    result = {"boot_logs": [str(p) for p in args.logs], "raw_rows": len(raw),
              "scalar_requests": sum(int(r["requests"]) for r in raw if r["kind"] == "scalar"),
              "management_requests": sum(int(r["requests"]) for r in raw if r["kind"] == "management"),
              "scenarios": summaries}
    (args.output / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    regressions = [s for s in summaries if s["consistent_regression_over_10_percent"]]
    print(json.dumps({"rows": len(raw), "scenarios": len(keys),
                      "scalar_requests": result["scalar_requests"],
                      "management_requests": result["management_requests"],
                      "consistent_regressions": [s["scenario"] for s in regressions]}, ensure_ascii=False))
    return bool(regressions)


if __name__ == "__main__":
    raise SystemExit(main())
