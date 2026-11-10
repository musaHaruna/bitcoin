#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Read-only prospective fee-estimator comparison.

Collection never submits a transaction. Analysis uses only quotes captured BEFORE
an observation starts, and retains unknown outcomes. Results are descriptive;
passive observations do not identify what a different fee would have achieved.
"""

import argparse
import bisect
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
import statistics
import subprocess
import time


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def rpc(cli, datadir, method, *params):
    command = [cli, f"-datadir={datadir}", method]
    command.extend(json.dumps(p, separators=(",", ":")) if not isinstance(p, str) else p for p in params)
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
    return json.loads(result.stdout)


def collect(args):
    nodes = dict(item.split("=", 1) for item in args.node)
    targets = [int(item) for item in args.targets.split(",")]
    last_tip = {}
    with args.output.open("a", encoding="utf-8") as output:
        while True:
            for label, datadir in nodes.items():
                try:
                    before = rpc(args.cli, datadir, "getblockchaininfo")
                    if before["initialblockdownload"] or before["blocks"] != before["headers"]:
                        continue
                    if last_tip.get(label) == before["bestblockhash"]:
                        continue
                    quotes = {}
                    for target in targets:
                        quotes[str(target)] = {
                            "raw": rpc(args.cli, datadir, "estimaterawfee", target, .95),
                            "smart": rpc(args.cli, datadir, "estimatesmartfee", target, "economical",
                                         {"fee_rate_estimator": "block_policy"}),
                        }
                    mempool = rpc(args.cli, datadir, "getmempoolinfo")
                    network = rpc(args.cli, datadir, "getnetworkinfo")
                    after = rpc(args.cli, datadir, "getblockchaininfo")
                    if before["bestblockhash"] != after["bestblockhash"]:
                        continue  # Do not mix targets sampled across different tips.
                    record = {
                        "format": 1, "node": label,
                        "captured_at": datetime.now(timezone.utc).isoformat(),
                        "height": after["blocks"], "tip": after["bestblockhash"],
                        "chain": after["chain"], "version": network["subversion"],
                        "connections": network["connections"], "mempool": mempool,
                        "quotes": quotes,
                    }
                    output.write(json.dumps(record, separators=(",", ":")) + "\n")
                    output.flush()
                    last_tip[label] = after["bestblockhash"]
                    print(f"{label}: captured height {after['blocks']}", flush=True)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
                    # No RPC credentials are in the command or output records.
                    print(f"{label}: collection failed ({type(error).__name__})", flush=True)
            if args.once:
                return
            time.sleep(args.poll)


def read_events(path):
    episodes = []
    active = {}
    session = 0
    height = 0
    epoch_start = float("-inf")
    audit = Counter()
    with path.open(encoding="utf-8") as source:
        for line in source:
            match = re.search(r"PKGFEE (session|start|end|reset|block)\b(.*)", line)
            if not match:
                continue
            when = timestamp(line.split()[0])
            event, values = match.groups()
            fields = dict(re.findall(r"(\w+)=([^\s]+)", values))
            if event == "session":
                epoch_start = when
                # A crash may leave no explicit end. Keep last known misses,
                # and regard its unobserved future as unknown after restart.
                for episode in active.values():
                    episode["reason"] = "observation_lost"
                active.clear()
                session += 1
                audit["sessions"] += 1
            elif event == "reset":
                epoch_start = when
                # No block-hash journal is available in this log. Exclude the
                # preceding evaluation history rather than pretending to undo it.
                for episode in episodes:
                    episode["reorg_discarded"] = True
                active.clear()
                height = int(fields["height"])
                audit["resets"] += 1
            elif event == "start":
                height = int(fields["height"])
                key = (session, int(fields["id"]))
                if key in active:
                    raise ValueError("duplicate observation id; use one complete observer log")
                episode = {
                    "start": height, "time": when, "rate": int(fields["fee"]) / int(fields["vsize"]),
                    "epoch_start": epoch_start,
                    "vsize": int(fields["vsize"]), "members": int(fields["members"]),
                    "known_through": height, "reason": None, "end": None,
                }
                active[key] = episode
                episodes.append(episode)
            elif event == "end":
                episode = active.pop((session, int(fields["id"])), None)
                if episode is None:
                    audit["unmatched_ends"] += 1
                    continue
                episode.update(end=int(fields["height"]), known_through=int(fields["known_through"]), reason=fields["reason"])
            elif event == "block":
                height = int(fields["height"])
                # In a gap the estimator emits observation_lost endings before
                # this boundary. Remaining active observations began after it.
                for episode in active.values():
                    episode["known_through"] = height
    return episodes, height, audit


def outcome(episode, target, height):
    if episode.get("reorg_discarded") or episode["end"] == episode["start"]:
        return None
    deadline = episode["start"] + target
    if height < deadline:
        return None
    if episode["reason"] == "confirmed" and episode["end"] <= deadline:
        return "success"
    if episode["known_through"] >= deadline:
        return "failure"
    return "unknown"


def horizon_for(target):
    return "short" if target <= 12 else "medium" if target <= 48 else "long"


def summarize(counts):
    total = sum(counts[k] for k in ("success", "failure", "unknown"))
    return {
        **{k: counts[k] for k in ("success", "failure", "unknown")},
        "total": total,
        "lower": counts["success"] / total if total else None,
        "upper": (counts["success"] + counts["unknown"]) / total if total else None,
    }


def analyze(args):
    records = [json.loads(line) for line in args.quotes.read_text().splitlines() if line.strip()]
    episodes, log_height, audit = read_events(args.events)
    observer_records = [r for r in records if r["node"] == args.observer]
    if not observer_records:
        raise ValueError("no snapshots for observer node")
    # Quotes select offers; the event log supplies their later outcomes. In
    # particular, collecting quotes can stop before the follow-up period ends.
    final_height = log_height if args.evaluation_height is None else args.evaluation_height
    start_height = 0 if args.start_height is None else args.start_height
    end_height = final_height if args.end_height is None else args.end_height
    if not 0 <= start_height <= end_height <= final_height <= log_height:
        raise ValueError("require 0 <= start-height <= end-height <= evaluation-height <= final event-log height")

    def in_scoring_interval(height):
        return start_height <= height <= end_height

    indexed = defaultdict(list)
    rates = defaultdict(list)
    availability = defaultdict(Counter)
    for record in records:
        indexed[(record["node"], record["height"])].append((timestamp(record["captured_at"]), record))
        if not in_scoring_interval(record["height"]):
            continue
        for target, estimates in record["quotes"].items():
            raw = estimates["raw"].get(horizon_for(int(target)), {})
            availability[(record["node"], target)]["snapshots"] += 1
            if "feerate" in raw:
                availability[(record["node"], target)]["available"] += 1
                rates[(record["node"], target)].append(float(raw["feerate"]) * 100_000)
    times = {}
    for key, values in indexed.items():
        values.sort(key=lambda v: v[0])
        times[key] = [v[0] for v in values]

    def preceding(node, episode):
        key = (node, episode["start"])
        index = bisect.bisect_left(times.get(key, []), episode["time"]) - 1
        # A reused height after a reset can otherwise match two mutually
        # consistent quotes from an abandoned tip. Keep the boundary on each
        # episode so a restart does not invalidate earlier valid comparisons.
        if index < 0 or times[key][index] <= episode["epoch_start"]:
            return None
        return indexed[key][index][1]

    nodes = sorted({r["node"] for r in records})
    groups = defaultdict(Counter)
    support = defaultdict(Counter)
    for episode in episodes:
        if episode.get("reorg_discarded"):
            audit["episodes_discarded_after_reorg"] += 1
            continue
        if not in_scoring_interval(episode["start"]):
            audit["episodes_outside_scoring_interval"] += 1
            continue
        observer = preceding(args.observer, episode)
        if observer is None:
            audit["episodes_without_prior_observer_snapshot"] += 1
            continue
        shape = "package" if episode["members"] > 1 else "singleton"
        for node in nodes:
            record = preceding(node, episode)
            if record is None:
                audit[f"{node}:missing_prior_snapshot"] += 1
                continue
            if record["tip"] != observer["tip"]:
                audit[f"{node}:tip_mismatch"] += 1
                continue
            for target_text, estimates in record["quotes"].items():
                requested = int(target_text)
                raw = estimates["raw"].get(horizon_for(requested), {})
                # Old builds do not return target; their horizon scale determines it.
                scale = int(raw.get("scale", 1))
                target = int(raw.get("target", (requested + scale - 1) // scale * scale))
                label = outcome(episode, target, final_height)
                if label is None:
                    continue
                key = (node, target_text, shape)
                support[key]["eligible_observations"] += 1
                if "feerate" not in raw:
                    support[key]["no_quote"] += 1
                    continue
                quote = float(raw["feerate"]) * 100_000
                if quote <= 0:
                    continue
                ratio = episode["rate"] / quote
                if ratio >= 1:
                    groups[(*key, "at_or_above_quote")][label] += 1
                if 1 <= ratio <= 1 + args.band:
                    groups[(*key, "near_quote")][label] += 1
    result = {
        "format": 1, "evaluation_height": final_height, "audit": dict(audit),
        "scoring_start_height": start_height, "scoring_end_height": end_height,
        "interpretation": "Descriptive observational bounds, not causal estimates or confidence intervals. Compare coverage and package mix as well as success.",
        "availability": [{"node": n, "target": t, **counts,
                          "median_quote_sat_vb": statistics.median(rates[(n, t)]) if rates[(n, t)] else None}
                         for (n, t), counts in sorted(availability.items())],
        "support": [{"node": n, "target": t, "shape": s, **counts} for (n, t, s), counts in sorted(support.items())],
        "outcomes": [{"node": n, "target": t, "shape": s, "selection": selection, **summarize(counts)}
                     for (n, t, s, selection), counts in sorted(groups.items())],
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("--cli", default="bitcoin-cli")
    collect_parser.add_argument("--node", action="append", required=True, help="label=/absolute/datadir; repeat for each node")
    collect_parser.add_argument("--targets", default="2,6,12,24,48,144")
    collect_parser.add_argument("--poll", type=float, default=5)
    collect_parser.add_argument("--once", action="store_true")
    collect_parser.add_argument("--output", type=Path, required=True)
    analyze_parser = sub.add_parser("analyze")
    analyze_parser.add_argument("--quotes", type=Path, required=True)
    analyze_parser.add_argument("--events", type=Path, required=True)
    analyze_parser.add_argument("--observer", default="candidate")
    analyze_parser.add_argument("--band", type=float, default=.10, help="near-quote band: 1 <= actual/quote <= 1+band")
    analyze_parser.add_argument("--start-height", type=int, help="first observation-start height to score (inclusive; default: 0)")
    analyze_parser.add_argument("--end-height", type=int, help="last observation-start height to score (inclusive; default: evaluation height)")
    analyze_parser.add_argument("--evaluation-height", type=int, help="outcome cutoff, no later than the final event-log height (default: final event-log height)")
    analyze_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "collect":
        if not math.isfinite(args.poll) or args.poll <= 0 or any(not 1 <= int(t) <= 1008 for t in args.targets.split(",")):
            parser.error("positive poll interval and targets in [1,1008] required")
        collect(args)
    else:
        if not math.isfinite(args.band) or args.band < 0:
            parser.error("band must be nonnegative")
        try:
            analyze(args)
        except ValueError as error:
            parser.error(str(error))


if __name__ == "__main__":
    main()
