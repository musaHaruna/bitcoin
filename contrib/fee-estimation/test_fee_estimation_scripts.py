#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Focused tests for the standalone fee-estimation experiment scripts."""

from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
COLLECTOR = SCRIPT_DIR / "collect_fee_estimates.py"
ANALYZER = SCRIPT_DIR / "analyze_fee_estimates.py"


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def block_hash(number: int) -> str:
    return f"{number:064x}"


def append_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")


class CollectorHelpersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.collector = load_script("fee_study_collector", COLLECTOR)

    def test_duration_and_target_parsing(self) -> None:
        self.assertEqual(self.collector.parse_duration("30s"), 30)
        self.assertEqual(self.collector.parse_duration("1.5h"), 5400)
        self.assertEqual(self.collector.parse_targets("1,2,2,6"), (1, 2, 6))
        self.assertEqual(
            self.collector.parse_modes("economical,conservative"),
            ("economical", "conservative"),
        )
        for invalid in ("nan", "inf", "-1s"):
            with self.assertRaises(Exception):
                self.collector.parse_duration(invalid)

    def test_logged_urls_do_not_contain_credentials_or_queries(self) -> None:
        self.assertEqual(
            self.collector.rpc_url_for_log(
                "https://alice:secret@example.com:8443/api/fees?token=hidden#fragment"
            ),
            "https://example.com:8443/api/fees",
        )


class AnalyzerHelpersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.analyzer = load_script("fee_study_analyzer", ANALYZER)

    def test_provider_shapes_and_units(self) -> None:
        blockstream = self.analyzer.provider_points(
            {"json": {"1": 1.25, "6": 0.75}}
        )
        self.assertEqual(
            [(label, target, str(rate)) for label, target, rate, _ in blockstream],
            [("target_1", 1, "1250.00"), ("target_6", 6, "750.00")],
        )
        mempool_space = self.analyzer.provider_points(
            {"json": {"fastestFee": 5, "halfHourFee": 3, "hourFee": 2}}
        )
        self.assertEqual(
            [(target, str(rate)) for _, target, rate, _ in mempool_space],
            [(1, "5000"), (3, "3000"), (6, "2000")],
        )

    def test_exact_rate_is_preferred_to_rounded_rpc_value(self) -> None:
        rate, fee, vsize, source = self.analyzer.component_rate(
            {
                "feerate_fee_sats": 1,
                "feerate_vsize": 3,
                "feerate_before_rpc_floor": 0.00000333,
            }
        )
        self.assertEqual((fee, vsize, source), (1, 3, "exact_fraction"))
        self.assertEqual(
            rate,
            self.analyzer.DECIMAL_CONTEXT.divide(
                self.analyzer.decimal.Decimal(1000),
                self.analyzer.decimal.Decimal(3),
            ),
        )


class AnalyzerEndToEndTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.input_dir = self.root / "run"
        self.output_dir = self.root / "analysis"
        self.input_dir.mkdir()
        experiment_id = "experiment-test"
        manifest = {
            "schema_version": 1,
            "experiment_id": experiment_id,
            "created_utc": "2026-01-01T00:00:00Z",
            "collection": {
                "targets": [1, 2],
                "modes": ["economical"],
            },
        }
        (self.input_dir / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        (self.input_dir / "run_state.json").write_text(
            json.dumps({"schema_version": 1, "phase": "stopped"}), encoding="utf-8"
        )
        for name in (
            "estimates.jsonl",
            "node_samples.jsonl",
            "blocks.jsonl",
            "provider_samples.jsonl",
            "errors.jsonl",
        ):
            (self.input_dir / name).touch()
        self.experiment_id = experiment_id

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def base(self, record_type: str) -> dict:
        return {
            "schema_version": 1,
            "record_type": record_type,
            "experiment_id": self.experiment_id,
            "run_id": "run-test",
        }

    def estimate(self, sample_id: str, batch_id: str, tip: str, height: int, target: int) -> dict:
        record = self.base("fee_estimate")
        record.update(
            {
                "sample_id": sample_id,
                "batch_id": batch_id,
                "batch_sequence": 0,
                "request_order": 0,
                "scheduled_utc": "2026-01-01T00:01:00Z",
                "request_started_utc": "2026-01-01T00:01:00Z",
                "response_received_utc": "2026-01-01T00:01:00.010Z",
                "mode": "economical",
                "requested_target": target,
                "rpc_error": None,
                "result": {
                    "feerate": 0.00003000,
                    "estimator": "mempool_policy",
                    "blocks": 2,
                    "diagnostics": {
                        "requested_target": target,
                        "estimate_mode": "economical",
                        "requested_estimator": "none",
                        "tip_hash_before": tip,
                        "tip_height_before": height,
                        "tip_hash_after": tip,
                        "tip_height_after": height,
                        "tip_consistent": True,
                        "mempool_consistent": True,
                        "snapshot_consistent": True,
                        "mempool_sequence_before": 10,
                        "mempool_sequence_after": 10,
                        "block_policy": {
                            "success": True,
                            "blocks": target,
                            "feerate_fee_sats": 5000,
                            "feerate_vsize": 1000,
                        },
                        "mempool_policy": {
                            "success": True,
                            "blocks": 2,
                            "feerate_fee_sats": 3000,
                            "feerate_vsize": 1000,
                        },
                        "selection": {
                            "success": True,
                            "reason": "mempool_policy_lower",
                            "estimator": "mempool_policy",
                            "blocks": 2,
                            "feerate_fee_sats": 3000,
                            "feerate_vsize": 1000,
                            "feerate_after_rpc_floor": 0.00003000,
                            "fee_floor_applied": False,
                        },
                        "fee_floor": {
                            "mempool_min": 0.00001000,
                            "min_relay": 0.00001000,
                            "effective": 0.00001000,
                        },
                        "mempool_health": {
                            "status": "healthy",
                            "tracked_blocks": 6,
                            "required_blocks": 6,
                            "coverage_ratio": 0.95,
                        },
                    },
                },
            }
        )
        return record

    def node_sample(self, batch_id: str, tip: str, height: int) -> dict:
        record = self.base("node_sample")
        record.update(
            {
                "batch_id": batch_id,
                "scheduled_utc": "2026-01-01T00:01:00Z",
                "rpc": {
                    "chain": {
                        "result": {
                            "chain": "main",
                            "blocks": height,
                            "headers": height,
                            "bestblockhash": tip,
                            "initialblockdownload": False,
                            "pruned": True,
                        },
                        "error": None,
                    },
                    "mempool": {
                        "result": {
                            "loaded": True,
                            "size": 100,
                            "bytes": 50_000,
                            "usage": 100_000,
                            "maxmempool": 300_000_000,
                            "mempoolminfee": 0.00001000,
                        },
                        "error": None,
                    },
                    "network": {
                        "result": {"connections": 10, "networkactive": True},
                        "error": None,
                    },
                },
            }
        )
        return record

    def block(self, height: int, current: str, previous: str) -> dict:
        record = self.base("block_observation")
        record.update(
            {
                "observed_utc": f"2026-01-01T00:0{height - 99}:00Z",
                "block_hash": current,
                "height": height,
                "previous_block_hash": previous,
                "header": {
                    "hash": current,
                    "height": height,
                    "previousblockhash": previous,
                    "time": 1767225600 + height * 600,
                },
                "block_stats": {
                    "blockhash": current,
                    "height": height,
                    "feerate_percentiles": [2, 3, 4, 5, 6],
                    "avgfeerate": 4,
                    "minfeerate": 1,
                    "maxfeerate": 10,
                    "total_weight": 3_000_000,
                    "totalfee": 1_000_000,
                    "txs": 2000,
                },
            }
        )
        return record

    def test_exact_rates_reorg_maturity_and_provider(self) -> None:
        h99, h100, h101, h102, h103 = (block_hash(value) for value in range(99, 104))
        stale101 = "f" * 64
        append_jsonl(
            self.input_dir / "estimates.jsonl",
            [
                self.estimate("canonical-sample", "batch-good", h100, 100, 2),
                self.estimate("stale-sample", "batch-stale", stale101, 101, 1),
            ],
        )
        append_jsonl(
            self.input_dir / "node_samples.jsonl",
            [
                self.node_sample("batch-good", h100, 100),
                self.node_sample("batch-stale", stale101, 101),
            ],
        )
        blocks = [
            self.block(100, h100, h99),
            self.block(101, h101, h100),
            self.block(102, h102, h101),
            self.block(103, h103, h102),
            self.block(101, stale101, h100),
        ]
        for source, tip, height, previous in (
            ("startup", h100, 100, None),
            ("waitfornewblock", stale101, 101, h100),
            ("waitfornewblock", h103, 103, stale101),
            ("shutdown", h103, 103, h103),
        ):
            event = self.base("tip_event")
            event.update(
                {
                    "observed_utc": "2026-01-01T00:10:00Z",
                    "source": source,
                    "tip_hash": tip,
                    "tip_height": height,
                    "previous_observed_tip_hash": previous,
                }
            )
            blocks.append(event)
        append_jsonl(self.input_dir / "blocks.jsonl", blocks)
        provider = self.base("provider_sample")
        provider.update(
            {
                "provider": "blockstream",
                "batch_id": "batch-good",
                "scheduled_utc": "2026-01-01T00:01:01Z",
                "http_status": 200,
                "json": {"2": 4.5},
                "error": None,
            }
        )
        append_jsonl(self.input_dir / "provider_samples.jsonl", [provider])
        # A crash may leave one unterminated final line; normal mode must retain
        # every preceding record and report the issue instead of failing.
        (self.input_dir / "errors.jsonl").write_text('{"schema_version":1', encoding="utf-8")

        completed = subprocess.run(
            [
                sys.executable,
                str(ANALYZER),
                str(self.input_dir),
                "--output-dir",
                str(self.output_dir),
                "--charts",
                "off",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        with (self.output_dir / "normalized_estimates.csv").open(
            encoding="utf-8", newline=""
        ) as handle:
            normalized = list(csv.DictReader(handle))
        canonical = next(row for row in normalized if row["sample_id"] == "canonical-sample")
        self.assertEqual(canonical["block_policy_estimate_raw_sat_kvb"], "5000")
        self.assertEqual(canonical["mempool_policy_estimate_raw_sat_kvb"], "3000")
        self.assertEqual(canonical["selected_raw_sat_kvb"], "3000")
        self.assertEqual(canonical["returned_estimate_sat_kvb"], "3000")

        with (self.output_dir / "scores.csv").open(encoding="utf-8", newline="") as handle:
            scores = list(csv.DictReader(handle))
        selected = next(
            row
            for row in scores
            if row["sample_id"] == "canonical-sample"
            and row["output"] == "selected_raw"
            and row["evaluation_scope"] == "requested_target"
        )
        self.assertEqual(selected["analysis_status"], "eligible")
        self.assertEqual(selected["primary_classification"], "within_band")
        self.assertEqual(selected["point_signed_error_sat_kvb"], "-1000")
        stale = next(
            row
            for row in scores
            if row["sample_id"] == "stale-sample"
            and row["output"] == "selected_raw"
            and row["evaluation_scope"] == "requested_target"
        )
        self.assertEqual(stale["analysis_status"], "reorged_anchor")
        self.assertEqual(stale["analysis_included"], "false")

        with (self.output_dir / "provider_estimates.csv").open(
            encoding="utf-8", newline=""
        ) as handle:
            providers = list(csv.DictReader(handle))
        self.assertEqual(len(providers), 1)
        self.assertEqual(providers[0]["estimate_sat_kvb"], "4500")

        with (self.output_dir / "data_quality.csv").open(
            encoding="utf-8", newline=""
        ) as handle:
            quality = {row["metric"]: row["count"] for row in csv.DictReader(handle)}
        self.assertEqual(quality["input.truncated_final_lines"], "1")

        analysis_manifest = json.loads(
            (self.output_dir / "analysis_manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(analysis_manifest["chain"]["reorg_events"], 1)


if __name__ == "__main__":
    unittest.main()
