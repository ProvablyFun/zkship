#!/usr/bin/env python3
"""Markdown summary of a P0 results directory (stdlib only).

Percentiles are nearest-rank, matching zkb-bench's own summaries.
"""
import csv
import json
import math
import sys
from collections import defaultdict
from pathlib import Path


def rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def pct(xs, p):
    s = sorted(xs)
    return s[max(1, math.ceil(p * len(s))) - 1]


def med(xs):
    return pct(xs, 0.5)


def fmt_ms(x):
    if x >= 100:
        return f"{x:.0f}"
    if x >= 10:
        return f"{x:.1f}"
    if x >= 0.1:
        return f"{x:.2f}"
    return f"{x * 1000:.1f} µs".replace(" µs", "&nbsp;µs")


def table(header, body):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in body]
    return "\n".join(out)


def main(d):
    d = Path(d)
    env = json.loads((d / "env.json").read_text())
    print("# zkship P0 results\n")
    print(
        f"{env['cpu']}, {env['logical_cpus']} logical CPUs, governor {env['governor']}, "
        f"{env['kernel']}; {env['rustc']}; commit `{env['commit'][:12]}`"
        f"{' (dirty)' if env['dirty'] else ''}; single-threaded runs pinned with `{env['pin_single']}`. "
        f"Load at start: {env['load_at_start'].split()[0]}.\n"
    )

    print("## Message sizes (bytes)\n")
    body = [[r["message"], r["crypto_bytes"], r["payload_bytes"], r["frame_bytes"]] for r in rows(d / "sizes.csv")]
    print(table(["message", "cryptographic payload", "message (with tag)", "signed frame"], body))
    print(
        "\nCryptographic payload is what the abstract counts: group elements and scalars (for a "
        "sink announcement, not the ship index and cell list). Messages add a 1-byte tag; frames add "
        "a 78-byte header and a 64-byte Ed25519 signature. The Hello precedes framing.\n"
    )

    print("## Per-operation timings (ms, median / p95)\n")
    ops = rows(d / "ops_summary.csv")
    body = []
    for r in ops:
        body.append([r["op"], r["rules"], r["variant"], r["bytes"], r["n"],
                     fmt_ms(float(r["median_ms"])), fmt_ms(float(r["p95_ms"]))])
    print(table(["operation", "rules", "case", "bytes", "n", "median", "p95"], body))

    cold = defaultdict(list)
    for r in rows(d / "cold_init.csv"):
        cold[r["rules"]].append(float(r["ms"]))
    rss = {r["rules"]: int(r["max_rss_kb"]) for r in rows(d / "rss.csv")}
    print("\n## First use and memory\n")
    body = [[k, fmt_ms(med(v)), fmt_ms(pct(v, 0.95)), f"{rss.get(k, 0) / 1024:.1f}"] for k, v in cold.items()]
    print(table(["rules", "profile init median (ms)", "p95", "peak RSS, one prove+verify (MiB)"], body))

    print("\n## Complete games, in-process (per player; medians over games)\n")
    games = rows(d / "games.csv")
    groups = defaultdict(list)
    for r in games:
        groups[(r["rules"], r["strategy"])].append(r)
    body = []
    for (rules, strategy), rs in groups.items():
        n_games = len({r["game"] for r in rs})
        winners = [r for r in rs if r["winner"] == "1"]
        body.append([
            rules, strategy, n_games,
            med([int(r["shots"]) for r in winners]),
            med([int(r["bytes_sent"]) for r in rs]),
            max(int(r["bytes_sent"]) for r in rs),
            med([int(r["payload_sent"]) for r in rs]),
            fmt_ms(med([float(r["cpu_ms"]) for r in rs])),
            fmt_ms(med([float(r["setup_cpu_ms"]) for r in rs])),
        ])
    print(table(["rules", "shooter", "games", "winner's shots", "bytes sent", "max bytes sent",
                 "payload sent", "CPU (ms)", "of which setup (ms)"], body))

    frames = rows(d / "game_frames.csv")
    per_msg = defaultdict(lambda: ([], []))
    for r in frames:
        if r["rules"] != "standard":
            continue
        p, a = per_msg[r["message"]]
        p.append(float(r["produce_ms"]))
        a.append(float(r["accept_ms"]))
    print("\n### Per-message cost inside games (standard rules, all strategies)\n")
    body = []
    for msg, (p, a) in sorted(per_msg.items()):
        accept = fmt_ms(med(a)) if msg != "shot" else "(with answer)"
        body.append([msg, len(p), fmt_ms(med(p)), fmt_ms(pct(p, 0.95)), accept])
    print(table(["message", "count", "produce median", "produce p95", "receive+verify median"], body))
    print(
        "\n`produce` for an answer is the defender's whole handling of the incoming shot "
        "(frame check, answer, signing); `receive+verify` is the shooter's frame and answer check.\n"
    )

    net = rows(d / "net_games.csv")
    if net:
        print("## Networked games (TCP via delay proxy, hunt-target shooters)\n")
        groups = defaultdict(list)
        for r in net:
            groups[(r["rtt_ms"], r["mbps"])].append(r)
        turns = defaultdict(list)
        for r in rows(d / "net_turns.csv"):
            turns[(r["rtt_ms"], r["mbps"])].append(float(r["shot_to_verified_ms"]))
        body = []
        for (rtt, mbps), rs in groups.items():
            t = turns[(rtt, mbps)]
            body.append([rtt, "unlimited" if float(mbps) == 0 else mbps, len(rs) // 2,
                         fmt_ms(med([float(r["setup_ms"]) for r in rs])),
                         fmt_ms(med([float(r["total_ms"]) for r in rs])),
                         fmt_ms(med(t)), fmt_ms(pct(t, 0.95))])
        print(table(["RTT (ms)", "link (Mbit/s)", "games", "setup to first shot (ms)",
                     "whole game (ms)", "shot→verified median", "p95"], body))
        print(
            "\nSetup covers both commits (proving and verifying) and the coin flip. The proxy adds "
            "the stated delay one way per direction; bandwidth-limited runs serialize each chunk.\n"
        )


if __name__ == "__main__":
    main(sys.argv[1])
