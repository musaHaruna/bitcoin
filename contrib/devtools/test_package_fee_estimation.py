#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

import argparse
import json
from pathlib import Path
import tempfile
import unittest

import package_fee_estimation as study


def snapshot(when, height, rate=.0001, node="candidate", tip=None, targets=(2,)):
    return {"node": node, "height": height, "tip": str(height) if tip is None else tip,
            "captured_at": when,
            "quotes": {str(target): {"raw": {"short": {"feerate": rate, "scale": 1, "target": target}}}
                       for target in targets}}


class PackageFeeStudyTest(unittest.TestCase):
    def analyze_files(self, path, **bounds):
        args = argparse.Namespace(quotes=path / "quotes.jsonl", events=path / "debug.log",
                                  observer="candidate", band=.1, output=path / "result.json",
                                  start_height=None, end_height=None, evaluation_height=None)
        vars(args).update(bounds)
        study.analyze(args)
        return json.loads(args.output.read_text())

    def test_target_outcomes(self):
        episode = {"start": 100, "end": 101, "reason": "replaced", "known_through": 101}
        self.assertEqual(study.outcome(episode, 1, 110), "failure")
        self.assertEqual(study.outcome(episode, 6, 110), "unknown")
        self.assertIsNone(study.outcome(episode, 6, 105))
        episode.update(end=110, reason="confirmed", known_through=109)
        self.assertEqual(study.outcome(episode, 1, 110), "failure")
        self.assertEqual(study.outcome(episode, 10, 110), "success")
        episode.update(end=100, known_through=100)
        self.assertIsNone(study.outcome(episode, 1, 110))

    def test_unknown_bounds(self):
        result = study.summarize({"success": 100, "failure": 0, "unknown": 900})
        self.assertEqual(result["lower"], .1)
        self.assertEqual(result["upper"], 1)

    def test_prospective_quotes_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            log = path / "debug.log"
            log.write_text(
                "2026-11-10T00:00:00Z [estimatefee] PKGFEE session format=1\n"
                "2026-11-10T00:00:01Z [estimatefee] PKGFEE start id=1 height=100 fee=1000 vsize=100 members=2 hash=abc\n"
                "2026-11-10T00:01:00Z [estimatefee] PKGFEE block height=101 continuous=1\n"
                "2026-11-10T00:02:00Z [estimatefee] PKGFEE end id=1 height=102 known_through=101 reason=confirmed\n"
                "2026-11-10T00:02:00Z [estimatefee] PKGFEE block height=102 continuous=1\n"
            )
            quotes = path / "quotes.jsonl"
            quotes.write_text("\n".join(json.dumps(r) for r in [
                snapshot("2026-11-10T00:00:00.500Z", 100, .0001),  # 10 sat/vB, BEFORE offer
                snapshot("2026-11-10T00:00:01Z", 100, .001),      # Same timestamp does not establish BEFORE.
                snapshot("2026-11-10T00:00:02Z", 100, .001),      # 100 sat/vB, AFTER offer
                snapshot("2026-11-10T00:02:01Z", 102, .0001),
                {**snapshot("2026-11-10T00:00:00.500Z", 100, .0001), "node": "fork", "tip": "another_tip"},
                {**snapshot("2026-11-10T00:00:02Z", 100, .0001), "node": "late"},
            ]))
            result = self.analyze_files(path)
            rows = result["outcomes"]
            near = next(row for row in rows if row["selection"] == "near_quote")
            self.assertEqual(near["success"], 1)
            self.assertEqual(near["shape"], "package")
            self.assertEqual(result["audit"]["fork:tip_mismatch"], 1)
            self.assertEqual(result["audit"]["late:missing_prior_snapshot"], 1)

    def test_reorg_and_crash_do_not_invent_outcomes(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "debug.log"
            log.write_text(
                "2026-11-10T00:00:00Z PKGFEE session format=1\n"
                "2026-11-10T00:00:01Z PKGFEE start id=1 height=100 fee=1000 vsize=100 members=1 hash=abc\n"
                "2026-11-10T00:01:00Z PKGFEE block height=101 continuous=1\n"
                "2026-11-10T00:02:00Z PKGFEE session format=1\n"
                "2026-11-10T00:02:01Z PKGFEE block height=106 continuous=0\n"
            )
            episodes, height, _ = study.read_events(log)
            self.assertEqual(study.outcome(episodes[0], 1, height), "failure")
            self.assertEqual(study.outcome(episodes[0], 6, height), "unknown")
            with log.open("a") as output:
                output.write("2026-11-10T00:03:00Z PKGFEE reset height=105\n")
            episodes, height, _ = study.read_events(log)
            self.assertIsNone(study.outcome(episodes[0], 1, height))

    def test_reorg_requires_new_quotes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "debug.log").write_text(
                "2026-11-10T00:00:00Z PKGFEE session format=1\n"
                "2026-11-10T00:01:00Z PKGFEE reset height=100\n"
                "2026-11-10T00:01:01Z PKGFEE start id=1 height=100 fee=1000 vsize=100 members=1 hash=abc\n"
                "2026-11-10T00:02:00Z PKGFEE block height=101 continuous=1\n"
                "2026-11-10T00:03:00Z PKGFEE end id=1 height=102 known_through=101 reason=confirmed\n"
                "2026-11-10T00:03:00Z PKGFEE block height=102 continuous=1\n"
            )
            quotes = path / "quotes.jsonl"
            records = [snapshot("2026-11-10T00:00:30Z", 100, node=node, tip="abandoned")
                       for node in ("candidate", "control")]
            # Equal timestamps cannot establish that a quote followed the reset.
            records.extend(snapshot("2026-11-10T00:01:00Z", 100, node=node, tip="abandoned")
                           for node in ("candidate", "control"))
            quotes.write_text("\n".join(json.dumps(r) for r in records))
            result = self.analyze_files(path)
            self.assertEqual(result["outcomes"], [])
            self.assertEqual(result["audit"]["episodes_without_prior_observer_snapshot"], 1)

            # A new observer snapshot permits its own comparison, but must not
            # make a control snapshot from before the reset usable.
            records.append(snapshot("2026-11-10T00:01:00.500Z", 100, tip="new_tip"))
            quotes.write_text("\n".join(json.dumps(r) for r in records))
            result = self.analyze_files(path)
            self.assertEqual(len(result["outcomes"]), 2)
            self.assertTrue(all(row["node"] == "candidate" and row["success"] == 1 for row in result["outcomes"]))
            self.assertEqual(result["audit"]["control:missing_prior_snapshot"], 1)

    def test_restart_preserves_earlier_valid_comparisons(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "debug.log").write_text(
                "2026-11-10T00:00:00Z PKGFEE session format=1\n"
                "2026-11-10T00:00:02Z PKGFEE start id=1 height=100 fee=1000 vsize=100 members=1 hash=abc\n"
                "2026-11-10T00:01:00Z PKGFEE block height=101 continuous=1\n"
                "2026-11-10T00:02:00Z PKGFEE end id=1 height=102 known_through=101 reason=confirmed\n"
                "2026-11-10T00:02:00Z PKGFEE block height=102 continuous=1\n"
                "2026-11-10T00:03:00Z PKGFEE session format=1\n"
                "2026-11-10T00:03:01Z PKGFEE start id=1 height=102 fee=1000 vsize=100 members=1 hash=def\n"
                "2026-11-10T00:04:00Z PKGFEE block height=103 continuous=1\n"
                "2026-11-10T00:05:00Z PKGFEE end id=1 height=104 known_through=103 reason=confirmed\n"
                "2026-11-10T00:05:00Z PKGFEE block height=104 continuous=1\n"
            )
            quotes = path / "quotes.jsonl"
            records = [snapshot("2026-11-10T00:00:01Z", 100),
                       snapshot("2026-11-10T00:02:30Z", 102),
                       snapshot("2026-11-10T00:03:00Z", 102)]  # Same time as the new session.
            quotes.write_text("\n".join(json.dumps(r) for r in records))
            result = self.analyze_files(path)
            self.assertEqual(len(result["outcomes"]), 2)
            self.assertTrue(all(row["success"] == row["total"] == 1 for row in result["outcomes"]))
            self.assertEqual(result["audit"]["episodes_without_prior_observer_snapshot"], 1)

            records.append(snapshot("2026-11-10T00:03:00.500Z", 102))
            quotes.write_text("\n".join(json.dumps(r) for r in records))
            result = self.analyze_files(path)
            self.assertTrue(all(row["success"] == row["total"] == 2 for row in result["outcomes"]))

    def test_scoring_interval_has_independent_follow_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "debug.log").write_text(
                "2026-11-10T00:00:00Z PKGFEE session format=1\n"
                "2026-11-10T00:00:02Z PKGFEE start id=1 height=99 fee=1000 vsize=100 members=1 hash=abc\n"
                "2026-11-10T00:01:00Z PKGFEE block height=100 continuous=1\n"
                "2026-11-10T00:01:02Z PKGFEE start id=2 height=100 fee=1000 vsize=100 members=1 hash=def\n"
                "2026-11-10T00:02:00Z PKGFEE block height=101 continuous=1\n"
                "2026-11-10T00:02:02Z PKGFEE start id=3 height=101 fee=1000 vsize=100 members=1 hash=ghi\n"
                "2026-11-10T00:03:00Z PKGFEE end id=1 height=102 known_through=101 reason=confirmed\n"
                "2026-11-10T00:03:00Z PKGFEE end id=2 height=102 known_through=101 reason=confirmed\n"
                "2026-11-10T00:03:00Z PKGFEE block height=102 continuous=1\n"
                "2026-11-10T00:04:00Z PKGFEE end id=3 height=103 known_through=102 reason=confirmed\n"
                "2026-11-10T00:04:00Z PKGFEE block height=103 continuous=1\n"
                "2026-11-10T00:05:00Z PKGFEE block height=104 continuous=1\n"
            )
            records = [snapshot(when, height, targets=(2, 4)) for when, height in (
                ("2026-11-10T00:00:01Z", 99),
                ("2026-11-10T00:01:01Z", 100),
                ("2026-11-10T00:02:01Z", 101),
            )]
            quotes = path / "quotes.jsonl"
            quotes.write_text("\n".join(json.dumps(r) for r in records))
            result = self.analyze_files(path, start_height=100, end_height=100)
            self.assertEqual(result["evaluation_height"], 104)
            self.assertEqual(result["scoring_start_height"], 100)
            self.assertEqual(result["scoring_end_height"], 100)
            self.assertEqual(result["audit"]["episodes_outside_scoring_interval"], 2)
            self.assertEqual(len(result["outcomes"]), 4)
            self.assertTrue(all(row["success"] == row["total"] == 1 for row in result["outcomes"]))
            self.assertTrue(all(row["snapshots"] == 1 for row in result["availability"]))

            # Stop quote collection at the scoring boundary; later log evidence
            # must still resolve both targets for the one admitted observation.
            quotes.write_text(json.dumps(records[1]))
            self.assertEqual(self.analyze_files(path, start_height=100, end_height=100)["outcomes"], result["outcomes"])
            early = self.analyze_files(path, start_height=100, end_height=100, evaluation_height=102)
            self.assertEqual(len(early["outcomes"]), 2)
            self.assertTrue(all(row["target"] == "2" for row in early["outcomes"]))

    def test_invalid_scoring_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "debug.log").write_text("2026-11-10T00:00:00Z PKGFEE block height=106 continuous=1\n")
            (path / "quotes.jsonl").write_text(json.dumps(snapshot("2026-11-10T00:00:00Z", 100)))
            for bounds in ({"start_height": -1}, {"end_height": -1}, {"evaluation_height": -1},
                           {"start_height": 101, "end_height": 100}, {"end_height": 107},
                           {"evaluation_height": 107}, {"end_height": 105, "evaluation_height": 104}):
                with self.subTest(bounds=bounds), self.assertRaisesRegex(ValueError, "start-height <= end-height"):
                    self.analyze_files(path, **bounds)


if __name__ == "__main__":
    unittest.main()
