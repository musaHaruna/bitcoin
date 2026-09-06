#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Analyze JSONL produced by collect_fee_estimates.py.

The core analysis deliberately uses only Python's standard library.  If
matplotlib is installed, a small set of charts can also be generated.

The important distinction made by this program is between availability,
validity, and maturity.  An estimate can be returned by the RPC but still be
unsuitable for analysis (for example, because its snapshot crossed a mempool
update), and a valid estimate cannot be scored until its own returned target
has matured on the final canonical chain.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import datetime as dt
import decimal
import hashlib
import json
import math
import os
import statistics
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ANALYZER_SCHEMA_VERSION = 1
SUPPORTED_INPUT_SCHEMA_VERSIONS = {1, "1", "1.0"}
EXPECTED_INPUT_FILES = (
    "estimates.jsonl",
    "node_samples.jsonl",
    "blocks.jsonl",
    "provider_samples.jsonl",
    "errors.jsonl",
)
SATOSHIS_PER_BTC = decimal.Decimal(100_000_000)
KVBYTE = decimal.Decimal(1000)
DECIMAL_CONTEXT = decimal.Context(prec=40)
WARMUP_WORDS = (
    "insufficient data",
    "not enough data",
    "no feerate found",
    "not initialized",
    "warming",
    "warmup",
    "initial block download",
)


@dataclass
class Issue:
    category: str
    source: str
    line: int | None = None
    detail: str = ""


@dataclass
class SourceRecord:
    value: dict[str, Any]
    source: str
    line: int
    ordinal: int


@dataclass
class LoadResult:
    records: dict[str, list[SourceRecord]] = field(default_factory=dict)
    issues: list[Issue] = field(default_factory=list)
    counters: Counter[str] = field(default_factory=Counter)
    paths: list[Path] = field(default_factory=list)


class AnalysisError(RuntimeError):
    """A user-facing analysis error."""


def nested(value: Any, *paths: str, default: Any = None) -> Any:
    """Return the first non-None value found at one of several dotted paths."""
    for path in paths:
        current = value
        found = True
        for part in path.split("."):
            if not isinstance(current, Mapping) or part not in current:
                found = False
                break
            current = current[part]
        if found and current is not None:
            return current
    return default


def mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result


def as_decimal(value: Any) -> decimal.Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        result = DECIMAL_CONTEXT.create_decimal(str(value))
    except (decimal.InvalidOperation, ValueError, TypeError):
        return None
    return result if result.is_finite() else None


def as_float(value: Any) -> float | None:
    number = as_decimal(value)
    return float(number) if number is not None else None


def clean_hash(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    result = value.strip().lower()
    if len(result) != 64:
        return None
    try:
        int(result, 16)
    except ValueError:
        return None
    return result


def timestamp_epoch(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        result = float(value)
        # Accommodate millisecond timestamps without silently accepting other
        # arbitrary scales.
        if result > 100_000_000_000:
            result /= 1000.0
        return result if math.isfinite(result) else None
    text = str(value).strip()
    if not text:
        return None
    try:
        numeric = float(text)
    except ValueError:
        numeric = None
    if numeric is not None:
        return timestamp_epoch(numeric)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp()


def timestamp_text(epoch: float | None, original: Any = None) -> str:
    if epoch is not None:
        return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return "" if original is None else str(original)


def decimal_text(value: decimal.Decimal | float | int | None) -> str:
    if value is None:
        return ""
    number = value if isinstance(value, decimal.Decimal) else as_decimal(value)
    if number is None:
        return ""
    text = format(number, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def float_text(value: float | None) -> str:
    if value is None or not math.isfinite(value):
        return ""
    return format(value, ".12g")


def bool_text(value: bool | None) -> str:
    if value is None:
        return ""
    return "true" if value else "false"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def record_schema(record: Mapping[str, Any]) -> Any:
    return nested(record, "schema_version", "schema.version", "version")


def read_jsonl(path: Path, result: LoadResult, ordinal_start: int) -> int:
    """Read one JSONL file, tolerating a partially-written final line."""
    raw = path.read_bytes()
    lines = raw.splitlines(keepends=True)
    ordinal = ordinal_start
    seen_serialized: set[str] = set()
    output: list[SourceRecord] = []
    for index, raw_line in enumerate(lines, start=1):
        result.counters["physical_lines"] += 1
        if not raw_line.strip():
            result.counters["blank_lines"] += 1
            continue
        is_unterminated_last = index == len(lines) and not raw_line.endswith((b"\n", b"\r"))
        try:
            text = raw_line.decode("utf-8")
            value = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            category = "truncated_final_lines" if is_unterminated_last else "malformed_lines"
            result.counters[category] += 1
            result.issues.append(Issue(category, path.name, index, str(exc)))
            continue
        if not isinstance(value, dict):
            result.counters["non_object_records"] += 1
            result.issues.append(Issue("non_object_record", path.name, index, type(value).__name__))
            continue
        schema = record_schema(value)
        if schema is not None and schema not in SUPPORTED_INPUT_SCHEMA_VERSIONS:
            result.counters["unsupported_schema_records"] += 1
            result.issues.append(Issue("unsupported_schema", path.name, index, str(schema)))
            continue
        if schema is None:
            result.counters["missing_schema_records"] += 1
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if canonical in seen_serialized:
            result.counters["exact_duplicate_records"] += 1
            continue
        seen_serialized.add(canonical)
        output.append(SourceRecord(value, path.name, index, ordinal))
        ordinal += 1
        result.counters["accepted_records"] += 1
    result.records[path.name] = output
    return ordinal


def load_inputs(input_path: Path, strict: bool) -> LoadResult:
    if not input_path.exists():
        raise AnalysisError(f"input does not exist: {input_path}")
    result = LoadResult()
    if input_path.is_file():
        paths = [input_path]
    else:
        paths = [input_path / name for name in EXPECTED_INPUT_FILES if (input_path / name).is_file()]
    if not paths:
        raise AnalysisError(
            f"no JSONL input found in {input_path}; expected at least estimates.jsonl"
        )
    ordinal = 0
    for path in paths:
        result.paths.append(path)
        ordinal = read_jsonl(path, result, ordinal)
    if strict and (result.counters["malformed_lines"] or result.counters["truncated_final_lines"] or result.counters["unsupported_schema_records"]):
        raise AnalysisError("strict input validation failed; see malformed/truncated/schema counters")
    return result


def record_type(record: Mapping[str, Any], fallback: str = "") -> str:
    value = nested(record, "record_type", "type", "kind", "event_type", default=fallback)
    return str(value).strip().lower().replace("-", "_") if value is not None else fallback


def record_timestamp(record: Mapping[str, Any]) -> tuple[float | None, str]:
    original = nested(
        record,
        "timestamp_utc",
        "timestamp",
        "scheduled_utc",
        "request_started_utc",
        "response_received_utc",
        "observed_utc",
        "observed_at",
        "collected_at",
        "sample_time",
        "sample_started_at",
        "request_started_at",
        "timing.started_at",
    )
    epoch = timestamp_epoch(original)
    return epoch, timestamp_text(epoch, original)


def non_null_score(value: Any) -> int:
    if isinstance(value, Mapping):
        return sum(non_null_score(child) for child in value.values())
    if isinstance(value, list):
        return sum(non_null_score(child) for child in value)
    return int(value is not None and value != "")


def semantic_dedupe(
    records: Sequence[SourceRecord],
    key_function: Any,
    counters: Counter[str],
    category: str,
) -> list[SourceRecord]:
    """Deduplicate logical rows, retaining the richest/latest conflicting row."""
    chosen: dict[Any, SourceRecord] = {}
    unkeyed: list[SourceRecord] = []
    for record in records:
        key = key_function(record)
        if key is None:
            unkeyed.append(record)
            continue
        previous = chosen.get(key)
        if previous is None:
            chosen[key] = record
            continue
        counters[f"{category}_semantic_duplicates"] += 1
        if previous.value != record.value:
            counters[f"{category}_duplicate_conflicts"] += 1
        previous_score = non_null_score(previous.value)
        current_score = non_null_score(record.value)
        if current_score >= previous_score:
            chosen[key] = record
    return sorted([*chosen.values(), *unkeyed], key=lambda row: row.ordinal)


def estimate_key(source: SourceRecord) -> Any:
    value = source.value
    sample_id = nested(value, "sample_id", "id")
    if sample_id is not None:
        return ("id", str(sample_id))
    stamp, _ = record_timestamp(value)
    mode = nested(value, "mode", "estimate_mode", "request.mode", "request.estimate_mode")
    target = nested(value, "requested_target", "target", "conf_target", "request.target")
    order = nested(value, "order", "request_order", "batch_order")
    if stamp is None and mode is None and target is None:
        return None
    return ("fields", stamp, str(mode), as_int(target), order)


def rate_from_exact(component: Mapping[str, Any], prefix: str = "feerate") -> tuple[decimal.Decimal | None, int | None, int | None, str]:
    fee = as_int(nested(component, f"{prefix}_fee_sats", "fee_sats", "fee", "numerator_sats"))
    vsize = as_int(nested(component, f"{prefix}_vsize", "vsize", "size", "denominator_vbytes"))
    if fee is not None and vsize is not None and vsize > 0:
        return DECIMAL_CONTEXT.divide(DECIMAL_CONTEXT.multiply(decimal.Decimal(fee), KVBYTE), decimal.Decimal(vsize)), fee, vsize, "exact_fraction"
    return None, fee, vsize, ""


def rate_btc_kvb(value: Any) -> decimal.Decimal | None:
    amount = as_decimal(value)
    if amount is None:
        return None
    return DECIMAL_CONTEXT.multiply(amount, SATOSHIS_PER_BTC)


def rate_sat_vb(value: Any) -> decimal.Decimal | None:
    amount = as_decimal(value)
    if amount is None:
        return None
    return DECIMAL_CONTEXT.multiply(amount, KVBYTE)


def component_rate(component: Mapping[str, Any], before_floor: bool = True) -> tuple[decimal.Decimal | None, int | None, int | None, str]:
    rate, fee, vsize, source = rate_from_exact(component)
    if rate is not None:
        return rate, fee, vsize, source
    # estimatesmartfee monetary JSON values use BTC/kvB.  Explicitly-labelled
    # satoshi fields are accepted too, which makes the analyzer useful with
    # normalized or hand-built fixtures without guessing units.
    sat_kvb = nested(component, "feerate_sat_kvb", "rate_sat_kvb", "sat_per_kvb")
    if sat_kvb is not None:
        return as_decimal(sat_kvb), fee, vsize, "sat_kvb"
    sat_vb = nested(component, "feerate_sat_vb", "rate_sat_vb", "sat_per_vb")
    if sat_vb is not None:
        return rate_sat_vb(sat_vb), fee, vsize, "sat_vb"
    rpc_field = "feerate_before_rpc_floor" if before_floor else "feerate_after_rpc_floor"
    btc_value = nested(component, rpc_field, "feerate_btc_kvb", "rate_btc_kvb")
    if btc_value is not None:
        return rate_btc_kvb(btc_value), fee, vsize, "rounded_rpc_btc_kvb"
    return None, fee, vsize, ""


def is_warmup_error(error: Any) -> bool:
    lowered = str(error or "").lower()
    return any(word in lowered for word in WARMUP_WORDS)


def extract_estimate_records(load: LoadResult) -> list[SourceRecord]:
    if "estimates.jsonl" in load.records:
        candidates = load.records["estimates.jsonl"]
    else:
        candidates = [record for records in load.records.values() for record in records]
    candidates = [
        row for row in candidates
        if record_type(row.value, "estimate") in {"estimate", "fee_estimate", "estimate_sample", "sample", "rpc_estimate"}
        or "result" in row.value
        or "diagnostics" in row.value
    ]
    return semantic_dedupe(candidates, estimate_key, load.counters, "estimate")


def normalize_estimate(source: SourceRecord) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    record = source.value
    result = mapping(nested(record, "result", "rpc_result", "response", default={}))
    # Some fixtures contain the raw estimatesmartfee response at top level.
    if not result and any(key in record for key in ("feerate", "diagnostics", "errors")):
        result = record
    diagnostics = mapping(nested(result, "diagnostics", default=nested(record, "diagnostics", default={})))
    block = mapping(nested(diagnostics, "block_policy", "estimators.block_policy", default=nested(record, "block_policy", default={})))
    mempool = mapping(nested(diagnostics, "mempool_policy", "estimators.mempool_policy", default=nested(record, "mempool_policy", default={})))
    selection = mapping(nested(diagnostics, "selection", default=nested(record, "selection", default={})))
    fee_floor = mapping(nested(diagnostics, "fee_floor", default=nested(record, "fee_floor", default={})))
    template = mapping(nested(diagnostics, "mempool_template", default=nested(record, "mempool_template", default={})))
    health = mapping(nested(diagnostics, "mempool_health", default=nested(record, "mempool_health", default={})))

    epoch, stamp = record_timestamp(record)
    sample_id = str(nested(record, "sample_id", "id", default=f"{source.source}:{source.line}"))
    mode = str(nested(record, "mode", "estimate_mode", "request.mode", "request.estimate_mode", default=nested(diagnostics, "estimate_mode", default="unknown"))).lower()
    requested_target = as_int(nested(record, "requested_target", "target", "conf_target", "request.target", "request.conf_target", default=nested(diagnostics, "requested_target")))
    requested_estimator = str(nested(record, "requested_estimator", "request.fee_rate_estimator", default=nested(diagnostics, "requested_estimator", default="none")))
    tip_hash_before = clean_hash(nested(diagnostics, "tip_hash_before", default=nested(record, "tip_hash", "chain.tip_hash", "node.bestblockhash")))
    tip_hash_after = clean_hash(nested(diagnostics, "tip_hash_after"))
    tip_height_before = as_int(nested(diagnostics, "tip_height_before", default=nested(record, "tip_height", "chain.tip_height", "node.blocks")))
    tip_height_after = as_int(nested(diagnostics, "tip_height_after"))
    tip_consistent = as_bool(nested(diagnostics, "tip_consistent", default=nested(record, "tip_consistent")))
    mempool_consistent = as_bool(nested(diagnostics, "mempool_consistent", default=nested(record, "mempool_consistent")))
    snapshot_consistent = as_bool(nested(diagnostics, "snapshot_consistent", default=nested(record, "snapshot_consistent")))
    if tip_consistent is None and tip_hash_before and tip_hash_after:
        tip_consistent = tip_hash_before == tip_hash_after
    if snapshot_consistent is None and tip_consistent is not None and mempool_consistent is not None:
        snapshot_consistent = tip_consistent and mempool_consistent
    rpc_error = nested(record, "rpc_error", "error")
    if isinstance(rpc_error, Mapping):
        rpc_error = nested(rpc_error, "message", "error", default=json.dumps(rpc_error, sort_keys=True))
    root_errors = nested(result, "errors", default=[])
    if isinstance(root_errors, list):
        returned_error = "; ".join(str(item) for item in root_errors)
    else:
        returned_error = str(root_errors or "")
    if rpc_error:
        returned_error = f"{returned_error}; {rpc_error}".strip("; ")

    block_rate, block_fee, block_vsize, block_rate_source = component_rate(block)
    mempool_rate, mempool_fee, mempool_vsize, mempool_rate_source = component_rate(mempool)
    selected_rate, selected_fee, selected_vsize, selected_rate_source = component_rate(selection)
    fee_floor_applied = as_bool(
        nested(selection, "fee_floor_applied", default=nested(record, "fee_floor_applied"))
    )
    # When no floor was applied the exact selected fraction is also the exact
    # returned value. Prefer it to the formatted eight-decimal BTC/kvB field.
    if selected_rate is not None and fee_floor_applied is False:
        returned_rate = selected_rate
        returned_rate_source = selected_rate_source
        returned_fee = selected_fee
        returned_vsize = selected_vsize
    else:
        returned_rate = rate_btc_kvb(nested(result, "feerate"))
        returned_rate_source = "rounded_rpc_btc_kvb" if returned_rate is not None else ""
        returned_fee = None
        returned_vsize = None
    if block_rate is None:
        block_rate = as_decimal(nested(record, "block_policy_estimate_raw_sat_kvb"))
        block_rate_source = "collector_normalized_sat_kvb" if block_rate is not None else block_rate_source
    if mempool_rate is None:
        mempool_rate = as_decimal(nested(record, "mempool_estimate_raw_sat_kvb", "mempool_policy_estimate_raw_sat_kvb"))
        mempool_rate_source = "collector_normalized_sat_kvb" if mempool_rate is not None else mempool_rate_source
    if selected_rate is None:
        selected_rate = as_decimal(nested(record, "selected_raw_sat_kvb"))
        selected_rate_source = "collector_normalized_sat_kvb" if selected_rate is not None else selected_rate_source
    if returned_rate is None:
        returned_rate = as_decimal(nested(record, "returned_estimate_sat_kvb"))
        returned_rate_source = "collector_normalized_sat_kvb" if returned_rate is not None else returned_rate_source
    if returned_rate is None:
        returned_rate, _, _, returned_rate_source = component_rate(selection, before_floor=False)

    def rpc_money(container: Mapping[str, Any], *names: str) -> decimal.Decimal | None:
        value = nested(container, *names)
        return rate_btc_kvb(value) if value is not None else None

    template_p50, template_p50_fee, template_p50_vsize, template_p50_source = rate_from_exact(template, "p50")
    if template_p50 is None:
        template_p50 = rpc_money(template, "p50")
        template_p50_source = "rounded_rpc_btc_kvb" if template_p50 is not None else ""
    template_p75, template_p75_fee, template_p75_vsize, template_p75_source = rate_from_exact(template, "p75")
    if template_p75 is None:
        template_p75 = rpc_money(template, "p75")
        template_p75_source = "rounded_rpc_btc_kvb" if template_p75 is not None else ""

    selected_estimator = str(nested(selection, "estimator", default=nested(record, "selected_estimator", default=nested(result, "estimator", default=""))))
    selection_reason = str(nested(selection, "reason", default=nested(record, "selection_reason", default="")))
    block_success = as_bool(nested(block, "success"))
    mempool_success = as_bool(nested(mempool, "success"))
    selection_success = as_bool(nested(selection, "success"))
    if block_success is None:
        block_success = block_rate is not None
    if mempool_success is None:
        mempool_success = mempool_rate is not None
    if selection_success is None:
        selection_success = selected_rate is not None

    block_error = str(nested(block, "error", default=nested(record, "block_policy_estimator_error", default="")))
    mempool_error = str(nested(mempool, "error", default=nested(record, "mempool_estimator_error", default="")))
    health_status = str(nested(health, "status", default=""))
    node_ibd = as_bool(nested(record, "initialblockdownload", "node.initialblockdownload", "chain.initialblockdownload"))
    common = {
        "experiment_id": nested(record, "experiment_id", default=""),
        "run_id": nested(record, "run_id", default=""),
        "sample_id": sample_id,
        "batch_id": nested(record, "batch_id", "batch.id", default=""),
        "batch_sequence": as_int(nested(record, "batch_sequence")),
        "request_order": as_int(nested(record, "request_order", "order")),
        "trigger": nested(record, "trigger", default=""),
        "timestamp_utc": stamp,
        "timestamp_epoch": epoch,
        "scheduled_utc": nested(record, "scheduled_utc", default=""),
        "request_started_utc": nested(record, "request_started_utc", default=""),
        "response_received_utc": nested(record, "response_received_utc", default=""),
        "source_file": source.source,
        "source_line": source.line,
        "mode": mode,
        "requested_target": requested_target,
        "requested_estimator": requested_estimator,
        "tip_hash": tip_hash_before,
        "tip_height": tip_height_before,
        "tip_hash_after": tip_hash_after,
        "tip_height_after": tip_height_after,
        "tip_consistent": tip_consistent,
        "mempool_consistent": mempool_consistent,
        "snapshot_consistent": snapshot_consistent,
        "diagnostics_present": bool(diagnostics),
        "mempool_sequence_before": as_int(nested(diagnostics, "mempool_sequence_before")),
        "mempool_sequence_after": as_int(nested(diagnostics, "mempool_sequence_after")),
        "seconds_since_tip_seen": as_float(nested(record, "seconds_since_tip_seen")),
        "schedule_lag_ms": as_float(nested(record, "schedule_lag_ms")),
        "rpc_duration_ms": as_float(nested(record, "rpc_latency_ms", "rpc_duration_ms", "duration_ms", "timing.duration_ms")),
        "rpc_error": str(rpc_error or ""),
        "returned_error": returned_error,
        "selected_estimator": selected_estimator,
        "selection_reason": selection_reason,
        "selection_success": selection_success,
        "fee_floor_applied": fee_floor_applied,
        "node_fee_floor_sat_kvb": as_decimal(nested(record, "node_fee_floor_sat_kvb")) or rpc_money(fee_floor, "effective"),
        "mempool_min_fee_sat_kvb": rpc_money(fee_floor, "mempool_min"),
        "min_relay_fee_sat_kvb": rpc_money(fee_floor, "min_relay"),
        "mempool_template_p50_sat_kvb": template_p50,
        "mempool_template_p50_fee_sats": template_p50_fee,
        "mempool_template_p50_vsize": template_p50_vsize,
        "mempool_template_p50_rate_source": template_p50_source,
        "mempool_template_p75_sat_kvb": template_p75,
        "mempool_template_p75_fee_sats": template_p75_fee,
        "mempool_template_p75_vsize": template_p75_vsize,
        "mempool_template_p75_rate_source": template_p75_source,
        "mempool_template_p50_used_fee_floor": as_bool(nested(template, "p50_used_fee_floor")),
        "mempool_template_p75_used_fee_floor": as_bool(nested(template, "p75_used_fee_floor")),
        "mempool_template_cache_hit": as_bool(nested(template, "cache_hit")),
        "mempool_template_cache_age_ms": as_int(nested(template, "cache_age_ms")),
        "mempool_template_cache_lifetime_ms": as_int(
            nested(template, "cache_lifetime_ms")
        ),
        "mempool_template_tip_hash": clean_hash(nested(template, "tip_hash")),
        "mempool_health_status": health_status,
        "mempool_health_tracked_blocks": as_int(nested(health, "tracked_blocks")),
        "mempool_health_required_blocks": as_int(nested(health, "required_blocks")),
        "mempool_health_coverage_ratio": as_float(nested(health, "coverage_ratio")),
        "mempool_health_required_coverage_ratio": as_float(nested(health, "required_coverage_ratio")),
        "mempool_health_window_tip_hash": clean_hash(
            nested(health, "window_tip_hash")
        ),
        "mempool_health_total_block_weight": as_int(nested(health, "total_block_weight")),
        "mempool_health_mempool_txs_weight": as_int(nested(health, "mempool_txs_weight")),
        "mempool_health_minimum_representative_window_weight": as_int(
            nested(health, "minimum_representative_window_weight")
        ),
        "mempool_health_low_activity_bypass": as_bool(nested(health, "low_activity_bypass")),
        "node_initialblockdownload": node_ibd,
    }

    if block_rate is not None and mempool_rate is not None:
        recomputed_reason = (
            "block_policy_lower" if block_rate < mempool_rate else
            "mempool_policy_lower" if mempool_rate < block_rate else
            "block_policy_tie"
        )
    elif block_rate is None and mempool_rate is None:
        recomputed_reason = "both_estimators_error"
    elif block_rate is None:
        recomputed_reason = "block_policy_error"
    else:
        recomputed_reason = "mempool_policy_error"
    common["selection_recomputed_reason"] = recomputed_reason
    common["selection_diagnostics_consistent"] = selection_reason == recomputed_reason if selection_reason else None
    expected_selected_rate = (
        min(block_rate, mempool_rate)
        if block_rate is not None and mempool_rate is not None
        else None
    )
    expected_selected_estimator = (
        "block_policy"
        if block_rate is not None and mempool_rate is not None and block_rate <= mempool_rate
        else "mempool_policy"
        if block_rate is not None and mempool_rate is not None
        else ""
    )
    common["selection_rate_consistent"] = (
        selected_rate == expected_selected_rate
        if selection_success and expected_selected_rate is not None
        else None
    )
    common["selection_estimator_consistent"] = (
        selected_estimator == expected_selected_estimator
        if selection_success and expected_selected_estimator
        else None
    )

    wide = dict(common)
    wide.update({
        "block_policy_estimate_raw_sat_kvb": block_rate,
        "block_policy_fee_sats": block_fee,
        "block_policy_vsize": block_vsize,
        "block_policy_rate_source": block_rate_source,
        "block_policy_returned_target": as_int(nested(block, "blocks", default=nested(record, "block_policy_returned_target"))),
        "block_policy_error": block_error,
        "mempool_policy_estimate_raw_sat_kvb": mempool_rate,
        "mempool_policy_fee_sats": mempool_fee,
        "mempool_policy_vsize": mempool_vsize,
        "mempool_policy_rate_source": mempool_rate_source,
        "mempool_policy_returned_target": as_int(nested(mempool, "blocks", default=nested(record, "mempool_policy_returned_target"))),
        "mempool_policy_error": mempool_error,
        "selected_raw_sat_kvb": selected_rate,
        "selected_fee_sats": selected_fee,
        "selected_vsize": selected_vsize,
        "selected_rate_source": selected_rate_source,
        "selected_returned_target": as_int(nested(selection, "blocks", default=nested(record, "returned_target"))),
        "returned_estimate_sat_kvb": returned_rate,
        "returned_rate_source": returned_rate_source,
        "returned_target": as_int(nested(result, "blocks", default=nested(record, "returned_target", default=nested(selection, "blocks")))),
    })

    health_warmup = health_status.lower() == "insufficient_data"
    ibd_warmup = node_ibd is True
    collector_warmup = as_bool(nested(record, "warmup")) is True
    collector_warmup_reason = str(nested(record, "warmup_reason", default=""))
    outputs_spec = [
        ("block_policy_raw", "block_policy", block_success, block_rate, block_fee, block_vsize, block_rate_source, as_int(nested(block, "blocks", default=nested(record, "block_policy_returned_target"))), block_error, tip_consistent),
        ("mempool_policy_raw", "mempool_policy", mempool_success, mempool_rate, mempool_fee, mempool_vsize, mempool_rate_source, as_int(nested(mempool, "blocks", default=nested(record, "mempool_policy_returned_target"))), mempool_error, snapshot_consistent),
        ("selected_raw", selected_estimator, selection_success, selected_rate, selected_fee, selected_vsize, selected_rate_source, as_int(nested(selection, "blocks", default=nested(record, "returned_target"))), selection_reason if not selection_success else "", snapshot_consistent),
        ("returned_after_floor", selected_estimator or requested_estimator, returned_rate is not None, returned_rate, returned_fee, returned_vsize, returned_rate_source, as_int(nested(result, "blocks", default=nested(record, "returned_target", default=nested(selection, "blocks")))), returned_error, snapshot_consistent),
    ]
    outputs: list[dict[str, Any]] = []
    for output_name, estimator, success, rate, fee, vsize, rate_source, returned_target, error, consistent in outputs_spec:
        if returned_target is None:
            returned_target = requested_target
        warmup_parts: list[str] = []
        if ibd_warmup:
            warmup_parts.append("initial_block_download")
        if collector_warmup:
            warmup_parts.append(collector_warmup_reason or "collector_marked_warmup")
        if is_warmup_error(error):
            warmup_parts.append("estimator_error")
        if output_name in {"selected_raw", "returned_after_floor"}:
            if selection_reason in {"block_policy_error", "both_estimators_error"} and is_warmup_error(block_error):
                warmup_parts.append("block_policy_warmup")
            if selection_reason in {"mempool_policy_error", "both_estimators_error"} and is_warmup_error(mempool_error):
                warmup_parts.append("mempool_policy_warmup")
        if output_name in {"mempool_policy_raw", "selected_raw", "returned_after_floor"} and health_warmup:
            warmup_parts.append("mempool_health_insufficient_data")
        warmup = bool(warmup_parts)
        available = bool(success and rate is not None and rate >= 0)
        exact_fraction_valid = (
            rate_source != "exact_fraction"
            or (fee is not None and vsize is not None and vsize > 0)
        )
        invalid_reasons: list[str] = []
        if not available:
            invalid_reasons.append("unavailable")
        if rate is not None and rate < 0:
            invalid_reasons.append("negative_rate")
        if not exact_fraction_valid:
            invalid_reasons.append("invalid_exact_fraction")
        if consistent is not True:
            invalid_reasons.append("snapshot_inconsistent" if consistent is False else "snapshot_consistency_unknown")
        if warmup:
            invalid_reasons.append("warmup")
        output = dict(common)
        output.update({
            "output": output_name,
            "estimator": estimator,
            "returned_target": returned_target,
            "estimate_sat_kvb": rate,
            "estimate_sat_vb": DECIMAL_CONTEXT.divide(rate, KVBYTE) if rate is not None else None,
            "estimate_fee_sats": fee,
            "estimate_vsize": vsize,
            "rate_source": rate_source,
            "available": available,
            "output_consistent": consistent,
            "warmup": warmup,
            "warmup_reason": ";".join(warmup_parts),
            "valid_strict": not invalid_reasons,
            "invalid_reason": ";".join(invalid_reasons),
            "estimator_error": str(error or ""),
        })
        outputs.append(output)
    validity_names = {
        "block_policy_raw": "block_policy_valid_strict",
        "mempool_policy_raw": "mempool_policy_valid_strict",
        "selected_raw": "selected_valid_strict",
        "returned_after_floor": "returned_valid_strict",
    }
    for output in outputs:
        wide[validity_names[output["output"]]] = output["valid_strict"]
    wide["sample_snapshot_valid"] = bool(
        diagnostics and snapshot_consistent is True and not rpc_error
    )
    wide["sample_valid_strict"] = wide["selected_valid_strict"]
    wide["warmup"] = any(row["warmup"] for row in outputs)
    return wide, outputs


def extract_block_parts(record: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    block = mapping(nested(record, "block", "data.block", default=record))
    header = mapping(nested(block, "header", default=nested(record, "header", default=block)))
    stats = mapping(
        nested(
            block,
            "stats",
            "blockstats",
            "block_stats",
            default=nested(record, "stats", "blockstats", "block_stats", default={}),
        )
    )
    return header, stats


def block_percentile(stats: Mapping[str, Any], percentile: int) -> decimal.Decimal | None:
    direct = nested(
        stats,
        f"p{percentile}_sat_kvb",
        f"feerate_p{percentile}_sat_kvb",
        f"fee_rate_p{percentile}_sat_kvb",
    )
    if direct is not None:
        return as_decimal(direct)
    direct_vb = nested(stats, f"p{percentile}_sat_vb", f"feerate_p{percentile}_sat_vb")
    if direct_vb is not None:
        return rate_sat_vb(direct_vb)
    percentiles = nested(stats, "feerate_percentiles", "fee_rate_percentiles")
    if isinstance(percentiles, Sequence) and not isinstance(percentiles, (str, bytes)):
        positions = {10: 0, 25: 1, 50: 2, 75: 3, 90: 4}
        position = positions.get(percentile)
        if position is not None and len(percentiles) > position:
            # Bitcoin Core getblockstats reports these values in sat/vB.
            return rate_sat_vb(percentiles[position])
    if isinstance(percentiles, Mapping):
        item = nested(percentiles, str(percentile), f"p{percentile}")
        unit = str(nested(stats, "feerate_percentiles_unit", default="sat/vb")).lower()
        return as_decimal(item) if "kvb" in unit else rate_sat_vb(item)
    return None


def normalize_block(source: SourceRecord) -> dict[str, Any] | None:
    record = source.value
    header, stats = extract_block_parts(record)
    block_hash = clean_hash(nested(header, "hash", "blockhash", default=nested(record, "block_hash", "hash", "blockhash")))
    if not block_hash:
        return None
    previous_hash = clean_hash(nested(header, "previousblockhash", "previous_block_hash", "prev_hash", default=nested(record, "previous_block_hash", "prev_hash")))
    height = as_int(nested(header, "height", default=nested(record, "block_height", "height")))
    observed_epoch, observed_text = record_timestamp(record)
    discovery_raw = nested(record, "discovery_utc", "first_seen_utc")
    discovery_epoch = timestamp_epoch(discovery_raw)
    block_time_raw = nested(header, "time", "timestamp", default=nested(record, "block_time", "block_time_utc"))
    block_epoch = timestamp_epoch(block_time_raw)
    if block_epoch is None and isinstance(block_time_raw, (int, float)):
        block_epoch = float(block_time_raw)
    avg_direct = nested(stats, "average_feerate_sat_kvb", "avg_feerate_sat_kvb", "avgfeerate_sat_kvb")
    avg_rate = as_decimal(avg_direct) if avg_direct is not None else rate_sat_vb(nested(stats, "avgfeerate", "average_feerate_sat_vb"))
    min_direct = nested(stats, "min_feerate_sat_kvb", "minfeerate_sat_kvb")
    min_rate = as_decimal(min_direct) if min_direct is not None else rate_sat_vb(nested(stats, "minfeerate", "min_feerate_sat_vb"))
    max_direct = nested(stats, "max_feerate_sat_kvb", "maxfeerate_sat_kvb")
    max_rate = as_decimal(max_direct) if max_direct is not None else rate_sat_vb(nested(stats, "maxfeerate", "max_feerate_sat_vb"))
    total_weight = as_int(nested(stats, "total_weight", "totalweight"))
    return {
        "block_hash": block_hash,
        "previous_block_hash": previous_hash,
        "height": height,
        "block_time_epoch": block_epoch,
        "block_time_utc": timestamp_text(block_epoch, block_time_raw),
        "observed_epoch": observed_epoch,
        "observed_at_utc": observed_text,
        "discovery_epoch": discovery_epoch,
        "discovery_utc": timestamp_text(discovery_epoch, discovery_raw),
        "discovery_is_exact": as_bool(nested(record, "discovery_is_exact")),
        "observation_source": nested(record, "source", default=""),
        "p10_sat_kvb": block_percentile(stats, 10),
        "p25_sat_kvb": block_percentile(stats, 25),
        "p50_sat_kvb": block_percentile(stats, 50),
        "p75_sat_kvb": block_percentile(stats, 75),
        "p90_sat_kvb": block_percentile(stats, 90),
        "average_sat_kvb": avg_rate,
        "minimum_sat_kvb": min_rate,
        "maximum_sat_kvb": max_rate,
        "tx_count": as_int(nested(stats, "txs", "tx_count")),
        "total_fee_sats": as_int(nested(stats, "totalfee", "total_fee_sats")),
        "total_weight": total_weight,
        "non_coinbase_weight_fraction_of_4m": (
            total_weight / 4_000_000 if total_weight is not None else None
        ),
        "source_file": source.source,
        "source_line": source.line,
        "ordinal": source.ordinal,
        "is_canonical": None,
    }


def block_record_candidates(load: LoadResult) -> list[SourceRecord]:
    if "blocks.jsonl" in load.records:
        return load.records["blocks.jsonl"]
    return [record for records in load.records.values() for record in records if "block" in record_type(record.value)]


def normalize_tip_event(source: SourceRecord) -> dict[str, Any] | None:
    record = source.value
    kind = record_type(record)
    event = mapping(nested(record, "event", "tip_event", default=record))
    new_tip = nested(event, "new_tip", "tip", default={})
    old_tip = nested(event, "old_tip", default={})
    new_map = mapping(new_tip)
    old_map = mapping(old_tip)
    new_hash = clean_hash(
        nested(new_map, "hash", "block_hash", default=new_tip if isinstance(new_tip, str) else nested(event, "new_tip_hash", "tip_hash", "bestblockhash", "block_hash"))
    )
    old_hash = clean_hash(
        nested(
            old_map,
            "hash",
            "block_hash",
            default=old_tip
            if isinstance(old_tip, str)
            else nested(event, "old_tip_hash", "previous_observed_tip_hash"),
        )
    )
    new_height = as_int(nested(new_map, "height", default=nested(event, "new_tip_height", "tip_height", "height")))
    old_height = as_int(
        nested(old_map, "height", default=nested(event, "old_tip_height", "previous_observed_tip_height"))
    )
    if not new_hash and "tip" not in kind and kind not in {"reorg", "chain_tip", "block_connected", "block_disconnected"}:
        return None
    epoch, stamp = record_timestamp(record)
    disconnected = nested(event, "disconnected", "disconnected_blocks", default=[])
    connected = nested(event, "connected", "connected_blocks", default=[])
    return {
        "event_type": kind,
        "timestamp_epoch": epoch,
        "timestamp_utc": stamp,
        "new_tip_hash": new_hash,
        "new_tip_height": new_height,
        "old_tip_hash": old_hash,
        "old_tip_height": old_height,
        "disconnected_count": len(disconnected) if isinstance(disconnected, list) else 0,
        "connected_count": len(connected) if isinstance(connected, list) else 0,
        "ordinal": source.ordinal,
    }


def build_chain(
    load: LoadResult,
    estimate_wide: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[int, str], list[dict[str, Any]], dict[str, Any]]:
    candidates = block_record_candidates(load)
    blocks: dict[str, dict[str, Any]] = {}
    tip_events: list[dict[str, Any]] = []
    for source in candidates:
        kind = record_type(source.value)
        if kind in {"tip_event", "chain_tip", "reorg", "block_connected", "block_disconnected", "tip"}:
            event = normalize_tip_event(source)
            if event:
                tip_events.append(event)
            # A tip event may also carry a full block observation.
        block = normalize_block(source)
        if block:
            previous = blocks.get(block["block_hash"])
            if previous is None:
                blocks[block["block_hash"]] = block
            else:
                load.counters["block_semantic_duplicates"] += 1
                if previous != block:
                    load.counters["block_duplicate_conflicts"] += 1
                if non_null_score(block) >= non_null_score(previous):
                    blocks[block["block_hash"]] = block

    # Add hash/height-only nodes from tips and estimator samples.  They are
    # useful for identifying whether the estimate's own tip survived a reorg.
    sparse_nodes: dict[str, dict[str, Any]] = {}
    for event in tip_events:
        if event["new_tip_hash"]:
            sparse_nodes[event["new_tip_hash"]] = {
                "block_hash": event["new_tip_hash"],
                "height": event["new_tip_height"],
                "previous_block_hash": None,
            }
    for sample in estimate_wide:
        if sample.get("tip_hash"):
            sparse_nodes[str(sample["tip_hash"])] = {
                "block_hash": sample["tip_hash"],
                "height": sample.get("tip_height"),
                "previous_block_hash": None,
            }

    # JSONL append order is the durable chain-observation order. It remains
    # authoritative if the host clock is corrected backwards during a long
    # run; timestamps are retained for reporting, not final-tip selection.
    tip_events.sort(key=lambda event: event["ordinal"])
    final_hash: str | None = None
    final_height: int | None = None
    for event in tip_events:
        if event["new_tip_hash"]:
            final_hash = event["new_tip_hash"]
            final_height = event["new_tip_height"]
    if final_hash is None:
        timed_samples = [row for row in estimate_wide if row.get("tip_hash")]
        if timed_samples:
            latest = max(timed_samples, key=lambda row: (row.get("timestamp_epoch") if row.get("timestamp_epoch") is not None else -1, row.get("source_line", -1)))
            final_hash = str(latest["tip_hash"])
            final_height = as_int(latest.get("tip_height"))
    if final_hash is None and blocks:
        latest_block = max(blocks.values(), key=lambda block: (block.get("height") if block.get("height") is not None else -1, block.get("observed_epoch") if block.get("observed_epoch") is not None else -1))
        final_hash = str(latest_block["block_hash"])
        final_height = as_int(latest_block.get("height"))

    canonical_by_height: dict[int, str] = {}
    walked: set[str] = set()
    cursor = final_hash
    inferred_height = final_height
    chain_cycle = False
    while cursor:
        if cursor in walked:
            chain_cycle = True
            break
        walked.add(cursor)
        node = blocks.get(cursor) or sparse_nodes.get(cursor)
        if node is None:
            break
        height = as_int(node.get("height"))
        if height is None:
            height = inferred_height
        if height is not None:
            canonical_by_height[height] = cursor
            inferred_height = height - 1
        previous_hash = clean_hash(node.get("previous_block_hash"))
        if not previous_hash:
            break
        # Record a known predecessor even when its full observation is just
        # outside the capture window.
        if inferred_height is not None and previous_hash not in blocks and previous_hash not in sparse_nodes:
            canonical_by_height[inferred_height] = previous_hash
            walked.add(previous_hash)
            break
        cursor = previous_hash

    for block_hash, block in blocks.items():
        height = block.get("height")
        block["is_canonical"] = bool(height is not None and canonical_by_height.get(height) == block_hash)
    stale_count = sum(1 for block in blocks.values() if block["is_canonical"] is False)

    def old_tip_is_ancestor(event: Mapping[str, Any]) -> bool | None:
        old_hash = clean_hash(event.get("old_tip_hash"))
        cursor = clean_hash(event.get("new_tip_hash"))
        old_height = as_int(event.get("old_tip_height"))
        if old_height is None and old_hash in blocks:
            old_height = as_int(blocks[old_hash].get("height"))
        if not old_hash or not cursor or old_hash == cursor:
            return True
        walked_hashes: set[str] = set()
        while cursor and cursor not in walked_hashes:
            if cursor == old_hash:
                return True
            walked_hashes.add(cursor)
            node = blocks.get(cursor)
            if node is None:
                return None
            node_height = as_int(node.get("height"))
            if old_height is not None and node_height is not None and node_height <= old_height:
                return False
            cursor = clean_hash(node.get("previous_block_hash"))
        return None

    reorg_events = sum(
        1 for event in tip_events
        if event["event_type"] in {"reorg", "block_disconnected"}
        or event["disconnected_count"] > 0
        or old_tip_is_ancestor(event) is False
        or (event["old_tip_hash"] and event["new_tip_hash"] and event["old_tip_hash"] != event["new_tip_hash"] and event["new_tip_height"] is not None and event["old_tip_height"] is not None and event["new_tip_height"] <= event["old_tip_height"])
    )
    metadata = {
        "final_tip_hash": final_hash,
        "final_tip_height": final_height,
        "canonical_start_height": min(canonical_by_height) if canonical_by_height else None,
        "canonical_end_height": max(canonical_by_height) if canonical_by_height else None,
        "canonical_heights": len(canonical_by_height),
        "observed_blocks": len(blocks),
        "stale_blocks": stale_count,
        "tip_events": len(tip_events),
        "reorg_events": reorg_events,
        "chain_cycle_detected": chain_cycle,
    }
    return blocks, canonical_by_height, tip_events, metadata


def canonical_tip_status(row: Mapping[str, Any], canonical_by_height: Mapping[int, str]) -> str:
    height = as_int(row.get("tip_height"))
    tip_hash = clean_hash(row.get("tip_hash"))
    if height is None or not tip_hash:
        return "unknown"
    canonical_hash = canonical_by_height.get(height)
    if canonical_hash is None:
        return "unknown"
    return "canonical" if canonical_hash == tip_hash else "stale"


def classify_band(estimate: decimal.Decimal, low: decimal.Decimal, high: decimal.Decimal) -> tuple[str, decimal.Decimal, float | None]:
    if estimate < low:
        distance = estimate - low
        relative = float(DECIMAL_CONTEXT.multiply(DECIMAL_CONTEXT.divide(distance, low), decimal.Decimal(100))) if low > 0 else None
        return "underestimate", distance, relative
    if estimate > high:
        distance = estimate - high
        relative = float(DECIMAL_CONTEXT.multiply(DECIMAL_CONTEXT.divide(distance, high), decimal.Decimal(100))) if high > 0 else None
        return "overestimate", distance, relative
    return "within_band", decimal.Decimal(0), 0.0


def score_output(
    row: dict[str, Any],
    blocks: Mapping[str, Mapping[str, Any]],
    canonical_by_height: Mapping[int, str],
    chain_metadata: Mapping[str, Any],
    include_warmup: bool,
    include_inconsistent: bool,
    *,
    evaluation_scope: str = "native_target",
    evaluation_target: int | None = None,
) -> dict[str, Any]:
    output = dict(row)
    tip_height = as_int(row.get("tip_height"))
    returned_target = as_int(row.get("returned_target"))
    if evaluation_target is None:
        evaluation_target = returned_target
    output["evaluation_scope"] = evaluation_scope
    output["native_returned_target"] = returned_target
    tip_status = canonical_tip_status(row, canonical_by_height)
    output["canonical_tip_status"] = tip_status
    target_height = tip_height + evaluation_target if tip_height is not None and evaluation_target is not None and evaluation_target > 0 else None
    output["evaluation_horizon_blocks"] = evaluation_target
    output["target_block_height"] = target_height
    target_hash = canonical_by_height.get(target_height) if target_height is not None else None
    output["target_block_hash"] = target_hash
    final_height = as_int(chain_metadata.get("final_tip_height"))
    mature = bool(target_height is not None and final_height is not None and target_height <= final_height)
    output["mature"] = mature
    target = blocks.get(target_hash or "", {})
    outcome_available = bool(
        target
        and target.get("p10_sat_kvb") is not None
        and target.get("p50_sat_kvb") is not None
        and target.get("p75_sat_kvb") is not None
    )
    output["outcome_available"] = outcome_available
    output["target_block_time_utc"] = target.get("block_time_utc", "")
    output["target_block_observed_at_utc"] = target.get("observed_at_utc", "")
    output["target_block_discovery_utc"] = target.get("discovery_utc", "")
    output["target_block_discovery_is_exact"] = target.get("discovery_is_exact")
    sample_epoch = row.get("timestamp_epoch")
    block_epoch = target.get("block_time_epoch")
    observed_epoch = target.get("observed_epoch")
    discovery_epoch = target.get("discovery_epoch")
    output["seconds_to_target_block_time"] = (block_epoch - sample_epoch) if isinstance(block_epoch, (int, float)) and isinstance(sample_epoch, (int, float)) else None
    output["seconds_to_target_observation"] = (observed_epoch - sample_epoch) if isinstance(observed_epoch, (int, float)) and isinstance(sample_epoch, (int, float)) else None
    output["seconds_to_target_discovery"] = (
        discovery_epoch - sample_epoch
        if target.get("discovery_is_exact") is True
        and isinstance(discovery_epoch, (int, float))
        and isinstance(sample_epoch, (int, float))
        else None
    )
    for name in ("p10_sat_kvb", "p25_sat_kvb", "p50_sat_kvb", "p75_sat_kvb", "p90_sat_kvb", "average_sat_kvb"):
        output[f"target_block_{name}"] = target.get(name)
    for name in (
        "minimum_sat_kvb",
        "maximum_sat_kvb",
        "tx_count",
        "total_fee_sats",
        "total_weight",
        "non_coinbase_weight_fraction_of_4m",
    ):
        output[f"target_block_{name}"] = target.get(name)

    horizon_blocks: list[Mapping[str, Any]] = []
    horizon_complete = bool(tip_height is not None and evaluation_target is not None and evaluation_target > 0)
    if horizon_complete:
        for height in range(tip_height + 1, tip_height + evaluation_target + 1):
            block_hash = canonical_by_height.get(height)
            block = blocks.get(block_hash or "")
            if not block or any(block.get(name) is None for name in ("p10_sat_kvb", "p50_sat_kvb", "p75_sat_kvb")):
                horizon_complete = False
                break
            horizon_blocks.append(block)
    output["horizon_outcome_available"] = horizon_complete
    if horizon_complete and horizon_blocks:
        for name in ("p10_sat_kvb", "p25_sat_kvb", "p50_sat_kvb", "p75_sat_kvb", "p90_sat_kvb", "average_sat_kvb"):
            values = [block.get(name) for block in horizon_blocks]
            output[f"horizon_min_{name}"] = min(values) if all(value is not None for value in values) else None
    else:
        for name in ("p10_sat_kvb", "p25_sat_kvb", "p50_sat_kvb", "p75_sat_kvb", "p90_sat_kvb", "average_sat_kvb"):
            output[f"horizon_min_{name}"] = None

    exclusion_reasons: list[str] = []
    if not row.get("available"):
        exclusion_reasons.append("estimate_unavailable")
    if row.get("estimate_sat_kvb") is None:
        exclusion_reasons.append("estimate_rate_missing")
    if row.get("output_consistent") is not True and not include_inconsistent:
        exclusion_reasons.append("snapshot_inconsistent" if row.get("output_consistent") is False else "snapshot_consistency_unknown")
    if row.get("warmup") and not include_warmup:
        exclusion_reasons.append("warmup")
    if tip_status != "canonical":
        exclusion_reasons.append("sample_tip_stale" if tip_status == "stale" else "sample_tip_canonicality_unknown")
    if not mature:
        exclusion_reasons.append("outcome_not_mature")
    if mature and not outcome_available:
        exclusion_reasons.append("target_block_stats_missing")
    estimate = row.get("estimate_sat_kvb")
    primary_evaluable = not exclusion_reasons and isinstance(estimate, decimal.Decimal)
    output["analysis_included"] = primary_evaluable
    output["analysis_exclusion_reason"] = ";".join(exclusion_reasons)

    requires_mempool_consistency = row.get("output") in {
        "mempool_policy_raw",
        "selected_raw",
        "returned_after_floor",
    }
    if row.get("rpc_error"):
        analysis_status = "rpc_error"
    elif not row.get("diagnostics_present", True) and not str(row.get("output", "")).startswith("provider:"):
        analysis_status = "missing_diagnostics"
    elif row.get("tip_consistent") is not True and not include_inconsistent:
        analysis_status = "tip_inconsistent"
    elif requires_mempool_consistency and row.get("mempool_consistent") is not True and not include_inconsistent:
        analysis_status = "mempool_inconsistent"
    elif row.get("warmup") and not include_warmup:
        analysis_status = "warmup"
    elif not row.get("available"):
        analysis_status = "estimator_unavailable"
    elif tip_status == "unknown":
        analysis_status = "canonical_unknown"
    elif tip_status == "stale":
        analysis_status = "reorged_anchor"
    elif not mature:
        analysis_status = "immature"
    elif not outcome_available:
        analysis_status = "missing_block_stats"
    else:
        analysis_status = "eligible"
    output["analysis_status"] = analysis_status

    sensitivity_exclusions = [
        reason
        for reason in exclusion_reasons
        if reason not in {"snapshot_inconsistent", "snapshot_consistency_unknown"}
    ]
    if row.get("tip_consistent") is not True and not include_inconsistent:
        sensitivity_exclusions.append(
            "tip_inconsistent"
            if row.get("tip_consistent") is False
            else "tip_consistency_unknown"
        )
    output["tip_consistent_sensitivity_included"] = bool(
        not sensitivity_exclusions and isinstance(estimate, decimal.Decimal)
    )

    output.update({
        "primary_classification": "",
        "primary_band_error_sat_kvb": None,
        "primary_band_error_pct": None,
        "point_signed_error_sat_kvb": None,
        "point_absolute_error_sat_kvb": None,
        "point_absolute_percentage_error": None,
        "point_estimate_to_p50_ratio": None,
        "point_log2_ratio": None,
        "point_absolute_log2_error": None,
        "average_signed_error_sat_kvb": None,
        "horizon_analysis_included": False,
        "horizon_classification": "",
        "horizon_band_error_sat_kvb": None,
        "horizon_band_error_pct": None,
        "horizon_point_signed_error_sat_kvb": None,
        "horizon_point_absolute_error_sat_kvb": None,
        "horizon_point_absolute_percentage_error": None,
        "horizon_point_estimate_to_p50_ratio": None,
        "horizon_point_log2_ratio": None,
        "horizon_point_absolute_log2_error": None,
    })
    if primary_evaluable:
        low = target["p10_sat_kvb"]
        midpoint = target["p50_sat_kvb"]
        high = target["p75_sat_kvb"]
        classification, band_error, band_pct = classify_band(estimate, low, high)
        point_error = estimate - midpoint
        output["primary_classification"] = classification
        output["primary_band_error_sat_kvb"] = band_error
        output["primary_band_error_pct"] = band_pct
        output["point_signed_error_sat_kvb"] = point_error
        output["point_absolute_error_sat_kvb"] = abs(point_error)
        output["point_absolute_percentage_error"] = float(abs(point_error / midpoint) * 100) if midpoint > 0 else None
        output["point_estimate_to_p50_ratio"] = float(estimate / midpoint) if midpoint > 0 else None
        if estimate > 0 and midpoint > 0:
            log_ratio = math.log2(float(estimate / midpoint))
            output["point_log2_ratio"] = log_ratio
            output["point_absolute_log2_error"] = abs(log_ratio)
        average = target.get("average_sat_kvb")
        output["average_signed_error_sat_kvb"] = estimate - average if average is not None else None

        if horizon_complete:
            horizon_low = output["horizon_min_p10_sat_kvb"]
            horizon_midpoint = output["horizon_min_p50_sat_kvb"]
            horizon_high = output["horizon_min_p75_sat_kvb"]
            classification, band_error, band_pct = classify_band(estimate, horizon_low, horizon_high)
            point_error = estimate - horizon_midpoint
            output["horizon_analysis_included"] = True
            output["horizon_classification"] = classification
            output["horizon_band_error_sat_kvb"] = band_error
            output["horizon_band_error_pct"] = band_pct
            output["horizon_point_signed_error_sat_kvb"] = point_error
            output["horizon_point_absolute_error_sat_kvb"] = abs(point_error)
            output["horizon_point_absolute_percentage_error"] = float(abs(point_error / horizon_midpoint) * 100) if horizon_midpoint > 0 else None
            output["horizon_point_estimate_to_p50_ratio"] = float(estimate / horizon_midpoint) if horizon_midpoint > 0 else None
            if estimate > 0 and horizon_midpoint > 0:
                log_ratio = math.log2(float(estimate / horizon_midpoint))
                output["horizon_point_log2_ratio"] = log_ratio
                output["horizon_point_absolute_log2_error"] = abs(log_ratio)
    return output


def numeric_values(rows: Iterable[Mapping[str, Any]], field_name: str) -> list[float]:
    values: list[float] = []
    for row in rows:
        value = row.get(field_name)
        if isinstance(value, decimal.Decimal):
            value = float(value)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
            values.append(float(value))
    return values


def quantile(values: Sequence[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    location = (len(ordered) - 1) * probability
    lower = math.floor(location)
    upper = math.ceil(location)
    if lower == upper:
        return ordered[lower]
    fraction = location - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def pct(numerator: int | float, denominator: int | float) -> float | None:
    return 100.0 * numerator / denominator if denominator else None


def grouped_scopes(rows: Sequence[Mapping[str, Any]]) -> list[tuple[str, str, str, str, list[Mapping[str, Any]]]]:
    exact: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    mode_all_targets: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    output_all: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        output = str(row.get("output", ""))
        mode = str(row.get("mode", ""))
        target = str(row.get("requested_target", ""))
        scope = str(row.get("evaluation_scope", "native_target"))
        # Per-requested-target tables retain every call. Only rollups across
        # targets suppress the target-independent mempool result duplicated by
        # the collector's target matrix.
        exact[(output, mode, target, scope)].append(row)
        if row.get("aggregation_duplicate"):
            continue
        mode_all_targets[(output, mode, scope)].append(row)
        output_all[(output, scope)].append(row)
    scopes: list[tuple[str, str, str, str, list[Mapping[str, Any]]]] = []
    for key in sorted(exact):
        scopes.append((*key, exact[key]))
    for key in sorted(mode_all_targets):
        scopes.append((key[0], key[1], "ALL", key[2], mode_all_targets[key]))
    for output, scope in sorted(output_all):
        scopes.append((output, "ALL", "ALL", scope, output_all[(output, scope)]))
    return scopes


def tip_balanced_share(rows: Sequence[Mapping[str, Any]], classification: str) -> float | None:
    """Give every anchor tip equal weight, regardless of samples between blocks."""
    by_tip: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        key = str(row.get("tip_hash") or row.get("target_block_hash") or "")
        if key:
            by_tip[key].append(row)
    if not by_tip:
        return None
    per_tip = [
        sum(row.get("primary_classification") == classification for row in group) / len(group)
        for group in by_tip.values()
    ]
    return 100.0 * statistics.fmean(per_tip)


def summarize(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for output, mode, target, evaluation_scope, group in grouped_scopes(rows):
        evaluated = [row for row in group if row.get("analysis_included")]
        interval_evaluated = [
            row for row in evaluated if row.get("trigger") == "interval"
        ]
        horizon = [row for row in group if row.get("horizon_analysis_included")]
        classifications = Counter(str(row.get("primary_classification")) for row in evaluated)
        interval_classifications = Counter(
            str(row.get("primary_classification")) for row in interval_evaluated
        )
        horizon_classes = Counter(str(row.get("horizon_classification")) for row in horizon)
        estimates = numeric_values(evaluated, "estimate_sat_kvb")
        errors = numeric_values(evaluated, "point_signed_error_sat_kvb")
        absolute_errors = numeric_values(evaluated, "point_absolute_error_sat_kvb")
        interval_errors = numeric_values(interval_evaluated, "point_signed_error_sat_kvb")
        interval_absolute_errors = numeric_values(
            interval_evaluated, "point_absolute_error_sat_kvb"
        )
        percentages = numeric_values(evaluated, "point_absolute_percentage_error")
        ratios = numeric_values(evaluated, "point_estimate_to_p50_ratio")
        log_ratios = numeric_values(evaluated, "point_log2_ratio")
        absolute_log_errors = numeric_values(evaluated, "point_absolute_log2_error")
        average_errors = numeric_values(evaluated, "average_signed_error_sat_kvb")
        horizon_errors = numeric_values(horizon, "horizon_point_signed_error_sat_kvb")
        horizon_absolute = numeric_values(horizon, "horizon_point_absolute_error_sat_kvb")
        horizon_percentages = numeric_values(horizon, "horizon_point_absolute_percentage_error")
        summary = {
            "output": output,
            "mode": mode,
            "requested_target": target,
            "evaluation_scope": evaluation_scope,
            "samples": len(group),
            "available": sum(bool(row.get("available")) for row in group),
            "available_pct": pct(sum(bool(row.get("available")) for row in group), len(group)),
            "strict_valid": sum(bool(row.get("valid_strict")) for row in group),
            "consistent": sum(row.get("output_consistent") is True for row in group),
            "warmup": sum(bool(row.get("warmup")) for row in group),
            "canonical_tip": sum(row.get("canonical_tip_status") == "canonical" for row in group),
            "mature": sum(bool(row.get("mature")) for row in group),
            "evaluated": len(evaluated),
            "evaluated_pct": pct(len(evaluated), len(group)),
            "interval_evaluated": len(interval_evaluated),
            "interval_underestimate_pct": pct(
                interval_classifications["underestimate"], len(interval_evaluated)
            ),
            "interval_within_band_pct": pct(
                interval_classifications["within_band"], len(interval_evaluated)
            ),
            "interval_overestimate_pct": pct(
                interval_classifications["overestimate"], len(interval_evaluated)
            ),
            "interval_point_mean_bias_sat_kvb": (
                statistics.fmean(interval_errors) if interval_errors else None
            ),
            "interval_point_mae_sat_kvb": (
                statistics.fmean(interval_absolute_errors)
                if interval_absolute_errors
                else None
            ),
            "distinct_anchor_tips": len({row.get("tip_hash") for row in evaluated if row.get("tip_hash")}),
            "distinct_target_blocks": len({row.get("target_block_hash") for row in evaluated if row.get("target_block_hash")}),
            "estimate_mean_sat_kvb": statistics.fmean(estimates) if estimates else None,
            "estimate_p05_sat_kvb": quantile(estimates, 0.05),
            "estimate_median_sat_kvb": quantile(estimates, 0.5),
            "estimate_p95_sat_kvb": quantile(estimates, 0.95),
            "primary_underestimate": classifications["underestimate"],
            "primary_within_band": classifications["within_band"],
            "primary_overestimate": classifications["overestimate"],
            "primary_underestimate_pct": pct(classifications["underestimate"], len(evaluated)),
            "primary_within_band_pct": pct(classifications["within_band"], len(evaluated)),
            "primary_overestimate_pct": pct(classifications["overestimate"], len(evaluated)),
            "tip_balanced_underestimate_pct": tip_balanced_share(evaluated, "underestimate"),
            "tip_balanced_within_band_pct": tip_balanced_share(evaluated, "within_band"),
            "tip_balanced_overestimate_pct": tip_balanced_share(evaluated, "overestimate"),
            "point_mean_bias_sat_kvb": statistics.fmean(errors) if errors else None,
            "point_median_bias_sat_kvb": quantile(errors, 0.5),
            "point_mae_sat_kvb": statistics.fmean(absolute_errors) if absolute_errors else None,
            "point_rmse_sat_kvb": math.sqrt(statistics.fmean([value * value for value in errors])) if errors else None,
            "point_median_absolute_percentage_error": quantile(percentages, 0.5),
            "point_p90_absolute_percentage_error": quantile(percentages, 0.9),
            "point_median_estimate_to_p50_ratio": quantile(ratios, 0.5),
            "point_median_log2_ratio": quantile(log_ratios, 0.5),
            "point_p90_absolute_log2_error": quantile(absolute_log_errors, 0.9),
            "average_mean_bias_sat_kvb": statistics.fmean(average_errors) if average_errors else None,
            "average_median_bias_sat_kvb": quantile(average_errors, 0.5),
            "average_mae_sat_kvb": statistics.fmean([abs(value) for value in average_errors]) if average_errors else None,
            "tip_consistent_sensitivity_evaluated": sum(bool(row.get("tip_consistent_sensitivity_included")) for row in group),
            "horizon_evaluated": len(horizon),
            "horizon_underestimate": horizon_classes["underestimate"],
            "horizon_within_band": horizon_classes["within_band"],
            "horizon_overestimate": horizon_classes["overestimate"],
            "horizon_underestimate_pct": pct(horizon_classes["underestimate"], len(horizon)),
            "horizon_within_band_pct": pct(horizon_classes["within_band"], len(horizon)),
            "horizon_overestimate_pct": pct(horizon_classes["overestimate"], len(horizon)),
            "horizon_point_mean_bias_sat_kvb": statistics.fmean(horizon_errors) if horizon_errors else None,
            "horizon_point_mae_sat_kvb": statistics.fmean(horizon_absolute) if horizon_absolute else None,
            "horizon_point_rmse_sat_kvb": math.sqrt(statistics.fmean([value * value for value in horizon_errors])) if horizon_errors else None,
            "horizon_point_median_absolute_percentage_error": quantile(horizon_percentages, 0.5),
        }
        summaries.append(summary)
    return summaries


def availability_summary(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for name, mode, target, evaluation_scope, group in grouped_scopes(rows):
        unavailable_reasons = Counter(
            str(row.get("estimator_error") or row.get("returned_error") or "unspecified")
            for row in group if not row.get("available")
        )
        exclusion_reasons: Counter[str] = Counter()
        for row in group:
            for reason in str(row.get("analysis_exclusion_reason", "")).split(";"):
                if reason:
                    exclusion_reasons[reason] += 1
        output.append({
            "output": name,
            "mode": mode,
            "requested_target": target,
            "evaluation_scope": evaluation_scope,
            "samples": len(group),
            "available": sum(bool(row.get("available")) for row in group),
            "unavailable": sum(not bool(row.get("available")) for row in group),
            "warmup": sum(bool(row.get("warmup")) for row in group),
            "consistent": sum(row.get("output_consistent") is True for row in group),
            "inconsistent": sum(row.get("output_consistent") is False for row in group),
            "consistency_unknown": sum(row.get("output_consistent") is None for row in group),
            "canonical_tip": sum(row.get("canonical_tip_status") == "canonical" for row in group),
            "stale_tip": sum(row.get("canonical_tip_status") == "stale" for row in group),
            "canonicality_unknown": sum(row.get("canonical_tip_status") == "unknown" for row in group),
            "mature": sum(bool(row.get("mature")) for row in group),
            "outcome_available": sum(bool(row.get("outcome_available")) for row in group),
            "evaluated": sum(bool(row.get("analysis_included")) for row in group),
            "top_unavailable_reason": unavailable_reasons.most_common(1)[0][0] if unavailable_reasons else "",
            "unavailable_reasons_json": json.dumps(unavailable_reasons, sort_keys=True),
            "analysis_exclusion_reasons_json": json.dumps(exclusion_reasons, sort_keys=True),
        })
    return output


def selection_summary(wide_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in wide_rows:
        groups[(str(row.get("mode", "")), str(row.get("requested_target", "")))].append(row)
    output: list[dict[str, Any]] = []
    for (mode, target), rows in sorted(groups.items()):
        reasons = Counter(str(row.get("selection_reason") or "missing") for row in rows)
        estimators = Counter(str(row.get("selected_estimator") or "missing") for row in rows)
        differences: list[float] = []
        for row in rows:
            block = row.get("block_policy_estimate_raw_sat_kvb")
            mempool = row.get("mempool_policy_estimate_raw_sat_kvb")
            if isinstance(block, decimal.Decimal) and isinstance(mempool, decimal.Decimal):
                differences.append(float(mempool - block))
        output.append({
            "mode": mode,
            "requested_target": target,
            "samples": len(rows),
            "selection_success": sum(bool(row.get("selection_success")) for row in rows),
            "block_policy_selected": estimators["block_policy"],
            "mempool_policy_selected": estimators["mempool_policy"],
            "block_policy_lower": reasons["block_policy_lower"],
            "mempool_policy_lower": reasons["mempool_policy_lower"],
            "block_policy_tie": reasons["block_policy_tie"],
            "block_policy_error": reasons["block_policy_error"],
            "mempool_policy_error": reasons["mempool_policy_error"],
            "both_estimators_error": reasons["both_estimators_error"],
            "fee_floor_applied": sum(row.get("fee_floor_applied") is True for row in rows),
            "diagnostics_consistent": sum(row.get("selection_diagnostics_consistent") is True for row in rows),
            "diagnostics_inconsistent": sum(row.get("selection_diagnostics_consistent") is False for row in rows),
            "selected_rate_inconsistent": sum(row.get("selection_rate_consistent") is False for row in rows),
            "selected_estimator_inconsistent": sum(row.get("selection_estimator_consistent") is False for row in rows),
            "median_mempool_minus_block_sat_kvb": quantile(differences, 0.5),
            "selection_reasons_json": json.dumps(reasons, sort_keys=True),
        })
    return output


PAIRWISE_OUTPUTS = (
    ("block_policy_raw", "mempool_policy_raw"),
    ("block_policy_raw", "selected_raw"),
    ("mempool_policy_raw", "selected_raw"),
    ("selected_raw", "returned_after_floor"),
)


def pairwise_summary(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    samples: dict[tuple[str, str, str, str], dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for row in rows:
        key = (
            str(row.get("sample_id")),
            str(row.get("mode")),
            str(row.get("requested_target")),
            str(row.get("evaluation_scope", "native_target")),
        )
        samples[key][str(row.get("output"))] = row
    groups: dict[tuple[str, str, str, str, str], list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = defaultdict(list)
    for (_, mode, target, evaluation_scope), by_output in samples.items():
        for left, right in PAIRWISE_OUTPUTS:
            if left in by_output and right in by_output:
                groups[(left, right, mode, target, evaluation_scope)].append((by_output[left], by_output[right]))
    output: list[dict[str, Any]] = []
    for (left_name, right_name, mode, target, evaluation_scope), pairs in sorted(groups.items()):
        available = [(left, right) for left, right in pairs if left.get("available") and right.get("available")]
        differences = [float(right["estimate_sat_kvb"] - left["estimate_sat_kvb"]) for left, right in available]
        same_horizon = [pair for pair in available if pair[0].get("returned_target") == pair[1].get("returned_target")]
        accuracy = [pair for pair in same_horizon if pair[0].get("analysis_included") and pair[1].get("analysis_included")]
        left_wins = right_wins = ties = 0
        for left, right in accuracy:
            left_error = float(left["point_absolute_error_sat_kvb"])
            right_error = float(right["point_absolute_error_sat_kvb"])
            if math.isclose(left_error, right_error, rel_tol=1e-12, abs_tol=1e-12):
                ties += 1
            elif left_error < right_error:
                left_wins += 1
            else:
                right_wins += 1
        output.append({
            "left_output": left_name,
            "right_output": right_name,
            "mode": mode,
            "requested_target": target,
            "evaluation_scope": evaluation_scope,
            "sample_pairs": len(pairs),
            "both_available": len(available),
            "same_returned_horizon": len(same_horizon),
            "accuracy_pairs": len(accuracy),
            "left_lower": sum(diff > 0 for diff in differences),
            "equal": sum(math.isclose(diff, 0.0, abs_tol=1e-12) for diff in differences),
            "right_lower": sum(diff < 0 for diff in differences),
            "mean_right_minus_left_sat_kvb": statistics.fmean(differences) if differences else None,
            "median_right_minus_left_sat_kvb": quantile(differences, 0.5),
            "left_accuracy_wins": left_wins,
            "accuracy_ties": ties,
            "right_accuracy_wins": right_wins,
        })
    return output


def rpc_call_result(record: Mapping[str, Any], method: str) -> Mapping[str, Any]:
    collector_aliases = {
        "getblockchaininfo": "chain",
        "getmempoolinfo": "mempool",
        "getchainstates": "chainstates",
        "getnetworkinfo": "network",
        "uptime": "uptime",
    }
    alias = collector_aliases.get(method, method)
    call = mapping(
        nested(
            record,
            f"rpc_calls.{method}",
            f"calls.{method}",
            f"rpc.{method}",
            f"rpc.{alias}",
            default={},
        )
    )
    return mapping(nested(call, "result", default=call))


def normalize_node_samples(load: LoadResult) -> list[dict[str, Any]]:
    if "node_samples.jsonl" not in load.records:
        return []
    records = semantic_dedupe(
        load.records["node_samples.jsonl"],
        lambda row: nested(row.value, "node_sample_id", "sample_id", "batch_id") or (record_timestamp(row.value)[0], row.ordinal),
        load.counters,
        "node_sample",
    )
    output: list[dict[str, Any]] = []
    for source in records:
        record = source.value
        if record_type(record, "node_sample") not in {"node_sample", "node", "health_sample"}:
            continue
        chain = rpc_call_result(record, "getblockchaininfo")
        mempool = rpc_call_result(record, "getmempoolinfo")
        network = rpc_call_result(record, "getnetworkinfo")
        chainstates_result = rpc_call_result(record, "getchainstates")
        chainstates = nested(chainstates_result, "chainstates", default=[])
        if not isinstance(chainstates, list):
            chainstates = []
        active_chainstate = mapping(chainstates[-1]) if chainstates else {}
        background_chainstate = mapping(chainstates[0]) if len(chainstates) > 1 else {}
        epoch, stamp = record_timestamp(record)
        mempool_min = nested(record, "mempool_min_fee_sat_kvb")
        if mempool_min is None:
            mempool_min = rate_btc_kvb(nested(mempool, "mempoolminfee"))
        min_relay = nested(record, "min_relay_fee_sat_kvb")
        if min_relay is None:
            min_relay = rate_btc_kvb(nested(mempool, "minrelaytxfee", default=nested(network, "relayfee")))
        mempool_usage = as_int(nested(record, "mempool_usage", default=nested(mempool, "usage")))
        max_mempool_bytes = as_int(
            nested(record, "max_mempool_bytes", default=nested(mempool, "maxmempool"))
        )
        output.append({
            "timestamp_utc": stamp,
            "timestamp_epoch": epoch,
            "node_sample_id": nested(record, "node_sample_id", "sample_id", default=f"{source.source}:{source.line}"),
            "batch_id": nested(record, "batch_id", default=""),
            "tip_hash": clean_hash(nested(record, "tip_hash", default=nested(chain, "bestblockhash"))),
            "tip_height": as_int(nested(record, "tip_height", default=nested(chain, "blocks"))),
            "headers": as_int(nested(record, "headers", default=nested(chain, "headers"))),
            "initial_block_download": as_bool(nested(record, "initialblockdownload", "initial_block_download", default=nested(chain, "initialblockdownload"))),
            "verification_progress": as_float(nested(record, "verificationprogress", "verification_progress", default=nested(chain, "verificationprogress"))),
            "chain": nested(chain, "chain", default=nested(record, "chain", default="")),
            "pruned": as_bool(nested(chain, "pruned", default=nested(record, "pruned"))),
            "chainstate_count": len(chainstates),
            "active_chainstate_snapshot_blockhash": clean_hash(
                nested(active_chainstate, "snapshot_blockhash")
            ),
            "active_chainstate_validated": as_bool(
                nested(active_chainstate, "validated")
            ),
            "background_chainstate_blocks": as_int(
                nested(background_chainstate, "blocks")
            ),
            "background_chainstate_verification_progress": as_float(
                nested(background_chainstate, "verificationprogress")
            ),
            "mempool_loaded": as_bool(nested(mempool, "loaded", default=nested(record, "mempool_loaded"))),
            "mempool_tx_count": as_int(nested(record, "mempool_tx_count", default=nested(mempool, "size"))),
            "mempool_bytes": as_int(nested(record, "mempool_bytes", default=nested(mempool, "bytes"))),
            "mempool_usage": mempool_usage,
            "max_mempool_bytes": max_mempool_bytes,
            "mempool_usage_ratio": (
                mempool_usage / max_mempool_bytes
                if mempool_usage is not None
                and max_mempool_bytes is not None
                and max_mempool_bytes > 0
                else None
            ),
            "mempool_total_fee_btc": as_decimal(nested(mempool, "total_fee")),
            "mempool_min_fee_sat_kvb": as_decimal(mempool_min),
            "min_relay_fee_sat_kvb": as_decimal(min_relay),
            "incremental_relay_fee_sat_kvb": rate_btc_kvb(nested(mempool, "incrementalrelayfee")),
            "connections": as_int(nested(network, "connections")),
            "connections_in": as_int(nested(network, "connections_in")),
            "connections_out": as_int(nested(network, "connections_out")),
            "network_active": as_bool(nested(network, "networkactive")),
            "warnings": str(nested(chain, "warnings", default=nested(network, "warnings", default=""))),
            "source_file": source.source,
            "source_line": source.line,
        })
    return output


def attach_node_context(
    wide_rows: Sequence[dict[str, Any]],
    output_rows: Sequence[dict[str, Any]],
    node_rows: Sequence[Mapping[str, Any]],
) -> None:
    """Attach the batch-level node state and apply its warmup flags."""
    by_batch = {
        str(row["batch_id"]): row
        for row in node_rows
        if row.get("batch_id") not in {None, ""}
    }
    fields = (
        "initial_block_download",
        "headers",
        "verification_progress",
        "mempool_loaded",
        "mempool_tx_count",
        "mempool_bytes",
        "mempool_usage",
        "max_mempool_bytes",
        "mempool_usage_ratio",
        "mempool_total_fee_btc",
        "mempool_min_fee_sat_kvb",
        "min_relay_fee_sat_kvb",
        "incremental_relay_fee_sat_kvb",
        "connections",
        "connections_in",
        "connections_out",
        "network_active",
        "pruned",
        "chainstate_count",
        "active_chainstate_snapshot_blockhash",
        "active_chainstate_validated",
        "background_chainstate_blocks",
        "background_chainstate_verification_progress",
    )
    for row in [*wide_rows, *output_rows]:
        node = by_batch.get(str(row.get("batch_id", "")))
        if node is None:
            continue
        for field_name in fields:
            row[f"node_{field_name}"] = node.get(field_name)
        diagnostic_floor = row.get("node_fee_floor_sat_kvb")
        sampled_floor = node.get("mempool_min_fee_sat_kvb")
        if isinstance(diagnostic_floor, decimal.Decimal) and isinstance(
            sampled_floor, decimal.Decimal
        ):
            delta = diagnostic_floor - sampled_floor
            row["fee_floor_node_delta_sat_kvb"] = delta
            row["fee_floor_node_consistent"] = abs(delta) <= decimal.Decimal(1)
        warmup_reasons: list[str] = []
        if node.get("initial_block_download") is True:
            warmup_reasons.append("initial_block_download")
        if (
            node.get("mempool_loaded") is False
            and row.get("output") != "block_policy_raw"
        ):
            warmup_reasons.append("mempool_not_loaded")
        if not warmup_reasons:
            continue
        row["warmup"] = True
        existing = [item for item in str(row.get("warmup_reason", "")).split(";") if item]
        row["warmup_reason"] = ";".join(dict.fromkeys([*existing, *warmup_reasons]))
        if "output" in row:
            row["valid_strict"] = False
            invalid = [item for item in str(row.get("invalid_reason", "")).split(";") if item]
            row["invalid_reason"] = ";".join(dict.fromkeys([*invalid, "warmup"]))


def mark_native_mempool_duplicates(rows: Sequence[dict[str, Any]]) -> None:
    """Avoid counting the target-independent mempool result once per request."""
    seen: set[tuple[Any, ...]] = set()
    ordered = sorted(
        rows,
        key=lambda row: (
            row.get("batch_sequence") if row.get("batch_sequence") is not None else -1,
            row.get("request_order") if row.get("request_order") is not None else -1,
            str(row.get("sample_id", "")),
        ),
    )
    for row in ordered:
        duplicate = False
        if (
            row.get("output") == "mempool_policy_raw"
            and row.get("evaluation_scope") == "native_target"
        ):
            key = (
                row.get("batch_id") or row.get("timestamp_utc"),
                row.get("mode"),
                row.get("native_returned_target"),
            )
            duplicate = key in seen
            seen.add(key)
        row["aggregation_duplicate"] = duplicate


def refresh_wide_validity(
    wide_rows: Sequence[dict[str, Any]], output_rows: Sequence[Mapping[str, Any]]
) -> None:
    names = {
        "block_policy_raw": "block_policy_valid_strict",
        "mempool_policy_raw": "mempool_policy_valid_strict",
        "selected_raw": "selected_valid_strict",
        "returned_after_floor": "returned_valid_strict",
    }
    by_sample = {
        (str(row.get("sample_id")), str(row.get("output"))): row
        for row in output_rows
    }
    for wide in wide_rows:
        sample_id = str(wide.get("sample_id"))
        for output_name, field_name in names.items():
            output = by_sample.get((sample_id, output_name))
            if output is not None:
                wide[field_name] = bool(output.get("valid_strict"))
        wide["sample_valid_strict"] = bool(wide.get("selected_valid_strict"))
        wide["warmup"] = any(
            bool(by_sample.get((sample_id, output_name), {}).get("warmup"))
            for output_name in names
        )


PROVIDER_TARGETS = {
    "fastestfee": 1,
    "fastest": 1,
    "nextblock": 1,
    "halfhourfee": 3,
    "halfhour": 3,
    "hourfee": 6,
    "hour": 6,
}


def provider_key(source: SourceRecord) -> Any:
    record = source.value
    identity = nested(record, "provider_sample_id", "sample_id", "id")
    if identity is not None:
        return str(identity)
    epoch, _ = record_timestamp(record)
    provider = nested(record, "provider_name", "provider", "name")
    return (provider, epoch) if provider is not None or epoch is not None else None


def provider_rate(value: Any, unit: str) -> decimal.Decimal | None:
    normalized_unit = unit.lower().replace(" ", "")
    if "btc" in normalized_unit:
        return rate_btc_kvb(value)
    if "kvb" in normalized_unit or "kb" in normalized_unit:
        return as_decimal(value)
    return rate_sat_vb(value)


def provider_points(record: Mapping[str, Any]) -> list[tuple[str, int, decimal.Decimal, str]]:
    """Extract (label, target, sat/kvB, source-unit) from common API shapes."""
    result = nested(record, "result", "response", "json", "data", default={})
    default_unit = str(nested(record, "unit", "rate_unit", default="sat/vb"))
    points: list[tuple[str, int, decimal.Decimal, str]] = []

    def add(label: Any, target_value: Any, rate_value: Any, unit: str = default_unit) -> None:
        target = as_int(target_value)
        rate = provider_rate(rate_value, unit)
        if target is not None and target > 0 and rate is not None and rate >= 0:
            points.append((str(label), target, rate, unit))

    containers: list[Any] = [result]
    if isinstance(result, Mapping) and "estimates" in result:
        containers.append(result["estimates"])
    if "estimates" in record:
        containers.append(record["estimates"])
    for container in containers:
        if isinstance(container, list):
            for index, item in enumerate(container):
                if not isinstance(item, Mapping):
                    continue
                label = nested(item, "label", "name", default=f"target_{nested(item, 'target', 'blocks', default=index)}")
                target = nested(item, "target", "blocks", "confirmation_target", "conf_target")
                rate_value = nested(item, "feerate_sat_vb", "fee_rate_sat_vb", "sat_per_vbyte", "feerate", "fee_rate", "rate")
                unit = "sat/vb" if nested(item, "feerate_sat_vb", "fee_rate_sat_vb", "sat_per_vbyte") is not None else str(nested(item, "unit", default=default_unit))
                if nested(item, "feerate_sat_kvb", "fee_rate_sat_kvb") is not None:
                    rate_value = nested(item, "feerate_sat_kvb", "fee_rate_sat_kvb")
                    unit = "sat/kvb"
                add(label, target, rate_value, unit)
        elif isinstance(container, Mapping):
            for key, value in container.items():
                normalized_key = str(key).lower().replace("_", "").replace("-", "")
                if normalized_key in PROVIDER_TARGETS and not isinstance(value, (Mapping, list)):
                    add(key, PROVIDER_TARGETS[normalized_key], value, "sat/vb")
                    continue
                numeric_target = as_int(key)
                if numeric_target is not None and not isinstance(value, (Mapping, list)):
                    add(f"target_{numeric_target}", numeric_target, value)
                    continue
                if isinstance(value, Mapping):
                    probabilities = mapping(nested(value, "probabilities", default={}))
                    if numeric_target is not None and probabilities:
                        for probability, prediction in probabilities.items():
                            prediction_map = mapping(prediction)
                            rate_value = nested(
                                prediction_map,
                                "fee_rate",
                                "feerate",
                                "rate",
                                default=prediction if not prediction_map else None,
                            )
                            unit = str(nested(prediction_map, "unit", default=default_unit))
                            add(
                                f"target_{numeric_target}_probability_{probability}",
                                numeric_target,
                                rate_value,
                                unit,
                            )
                        continue
                    target = nested(value, "target", "blocks", "confirmation_target", "conf_target", default=PROVIDER_TARGETS.get(normalized_key))
                    rate_value = nested(value, "feerate_sat_vb", "fee_rate_sat_vb", "sat_per_vbyte", "feerate", "fee_rate", "rate", "value")
                    unit = str(nested(value, "unit", default=default_unit))
                    if nested(value, "feerate_sat_vb", "fee_rate_sat_vb", "sat_per_vbyte") is not None:
                        unit = "sat/vb"
                    if nested(value, "feerate_sat_kvb", "fee_rate_sat_kvb") is not None:
                        rate_value = nested(value, "feerate_sat_kvb", "fee_rate_sat_kvb")
                        unit = "sat/kvb"
                    add(key, target, rate_value, unit)
    # Stable de-duplication matters because result and result.estimates may
    # refer to the same object.
    unique: dict[tuple[str, int], tuple[str, int, decimal.Decimal, str]] = {}
    for point in points:
        unique[(point[0], point[1])] = point
    return list(unique.values())


def normalize_provider_samples(
    load: LoadResult,
    estimate_wide: Sequence[Mapping[str, Any]],
    blocks: Mapping[str, Mapping[str, Any]],
    canonical_by_height: Mapping[int, str],
    chain_metadata: Mapping[str, Any],
    max_skew_seconds: float,
) -> list[dict[str, Any]]:
    records = load.records.get("provider_samples.jsonl", [])
    records = semantic_dedupe(records, provider_key, load.counters, "provider")
    sample_index: dict[int, tuple[list[float], list[Mapping[str, Any]]]] = {}
    by_target: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for sample in estimate_wide:
        target = as_int(sample.get("requested_target"))
        if target is not None and sample.get("timestamp_epoch") is not None:
            by_target[target].append(sample)
    for target, samples in by_target.items():
        ordered = sorted(samples, key=lambda row: float(row["timestamp_epoch"]))
        sample_index[target] = ([float(row["timestamp_epoch"]) for row in ordered], ordered)

    output: list[dict[str, Any]] = []
    for source in records:
        record = source.value
        provider = str(nested(record, "provider_name", "provider", "name", default="unknown_provider"))
        provider_id = str(nested(record, "provider_sample_id", "sample_id", "id", default=f"{source.source}:{source.line}"))
        epoch, stamp = record_timestamp(record)
        error = nested(record, "error", "http_error")
        for label, target, rate, source_unit in provider_points(record):
            matched: Mapping[str, Any] | None = None
            skew: float | None = None
            index = sample_index.get(target)
            if epoch is not None and index and index[0]:
                times, samples = index
                position = bisect.bisect_left(times, epoch)
                candidates = []
                if position < len(times):
                    candidates.append(position)
                if position > 0:
                    candidates.append(position - 1)
                nearest = min(candidates, key=lambda item: abs(times[item] - epoch))
                skew = times[nearest] - epoch
                if abs(skew) <= max_skew_seconds:
                    matched = samples[nearest]
            tip_hash = clean_hash(nested(record, "tip_hash")) or (clean_hash(matched.get("tip_hash")) if matched else None)
            tip_height = as_int(nested(record, "tip_height"))
            if tip_height is None and matched:
                tip_height = as_int(matched.get("tip_height"))
            row = {
                "sample_id": provider_id,
                "batch_id": nested(record, "batch_id", default=""),
                "timestamp_utc": stamp,
                "timestamp_epoch": epoch,
                "source_file": source.source,
                "source_line": source.line,
                "mode": "external",
                "requested_target": target,
                "requested_estimator": provider,
                "tip_hash": tip_hash,
                "tip_height": tip_height,
                "tip_consistent": True if matched or tip_hash else None,
                "mempool_consistent": None,
                "snapshot_consistent": True if matched or tip_hash else None,
                "selected_estimator": provider,
                "selection_reason": "provider_response",
                "output": f"provider:{provider}:{label}",
                "estimator": provider,
                "provider": provider,
                "provider_label": label,
                "provider_source_unit": source_unit,
                "provider_http_status": as_int(nested(record, "http_status", "status")),
                "provider_error": str(error or ""),
                "matched_node_sample_id": matched.get("sample_id", "") if matched else "",
                "provider_node_time_skew_seconds": skew,
                "returned_target": target,
                "estimate_sat_kvb": rate,
                "estimate_sat_vb": DECIMAL_CONTEXT.divide(rate, KVBYTE),
                "estimate_fee_sats": None,
                "estimate_vsize": None,
                "rate_source": f"provider_{source_unit}",
                "available": not bool(error),
                "output_consistent": True if matched or tip_hash else None,
                "warmup": False,
                "warmup_reason": "",
                "valid_strict": bool(not error and (matched or (tip_hash and tip_height is not None))),
                "invalid_reason": "" if not error else "provider_error",
                "estimator_error": str(error or ""),
                "returned_error": str(error or ""),
            }
            output.append(
                score_output(
                    row,
                    blocks,
                    canonical_by_height,
                    chain_metadata,
                    False,
                    False,
                    evaluation_scope="requested_target",
                    evaluation_target=target,
                )
            )
    return output


def csv_value(value: Any) -> Any:
    if isinstance(value, decimal.Decimal):
        return decimal_text(value)
    if isinstance(value, bool):
        return bool_text(value)
    if value is None:
        return ""
    if isinstance(value, float):
        return float_text(value)
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return value


def ordered_fields(rows: Sequence[Mapping[str, Any]], preferred: Sequence[str] = ()) -> list[str]:
    fields: list[str] = []
    seen: set[str] = set()
    for field_name in preferred:
        if field_name not in seen:
            fields.append(field_name)
            seen.add(field_name)
    for row in rows:
        for field_name in row:
            if field_name not in seen:
                fields.append(field_name)
                seen.add(field_name)
    return fields


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as destination:
            destination.write(text)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def write_csv(path: Path, rows: Sequence[Mapping[str, Any]], preferred: Sequence[str] = ()) -> int:
    fields = ordered_fields(rows, preferred)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as destination:
            writer = csv.DictWriter(destination, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
            writer.writeheader()
            for row in rows:
                writer.writerow({field_name: csv_value(row.get(field_name)) for field_name in fields})
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return len(rows)


def input_metadata(input_path: Path, load: LoadResult) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    base = input_path if input_path.is_dir() else input_path.parent

    def read(name: str) -> dict[str, Any] | None:
        path = base / name
        if not path.is_file():
            load.counters[f"missing_{name.replace('.', '_')}"] += 1
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            load.counters[f"invalid_{name.replace('.', '_')}"] += 1
            load.issues.append(Issue("invalid_metadata", name, None, str(exc)))
            return None
        if not isinstance(value, dict):
            load.counters[f"invalid_{name.replace('.', '_')}"] += 1
            load.issues.append(Issue("invalid_metadata", name, None, "top-level value is not an object"))
            return None
        return value

    return read("manifest.json"), read("run_state.json")


def make_data_quality(
    load: LoadResult,
    wide_rows: Sequence[Mapping[str, Any]],
    evaluated_rows: Sequence[Mapping[str, Any]],
    blocks: Mapping[str, Mapping[str, Any]],
    chain_metadata: Mapping[str, Any],
    node_rows: Sequence[Mapping[str, Any]],
    provider_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    metrics: list[tuple[str, Any, str]] = []
    provider_sources = load.records.get("provider_samples.jsonl", [])
    provider_failures = sum(
        bool(nested(source.value, "error", "http_error"))
        or as_int(nested(source.value, "http_status", "status")) not in {None, 200}
        or as_bool(nested(source.value, "truncated")) is True
        for source in provider_sources
    )
    provider_unparseable_successes = sum(
        not bool(nested(source.value, "error", "http_error"))
        and as_int(nested(source.value, "http_status", "status")) in {None, 200}
        and not provider_points(source.value)
        for source in provider_sources
    )
    for name, value in sorted(load.counters.items()):
        metrics.append((f"input.{name}", value, ""))
    metrics.extend([
        ("estimates.samples", len(wide_rows), "one row per RPC call"),
        ("estimates.output_rows", len(evaluated_rows), "output-specific requested/native-horizon rows"),
        ("estimates.snapshot_consistent", sum(row.get("snapshot_consistent") is True for row in wide_rows), ""),
        ("estimates.snapshot_inconsistent", sum(row.get("snapshot_consistent") is False for row in wide_rows), ""),
        ("estimates.snapshot_consistency_unknown", sum(row.get("snapshot_consistent") is None for row in wide_rows), ""),
        ("estimates.selection_diagnostic_mismatch", sum(row.get("selection_diagnostics_consistent") is False for row in wide_rows), "declared reason differs from exact-rate comparison"),
        ("estimates.selection_rate_mismatch", sum(row.get("selection_rate_consistent") is False for row in wide_rows), "selected exact rate differs from min(block,mempool)"),
        ("estimates.selection_estimator_mismatch", sum(row.get("selection_estimator_consistent") is False for row in wide_rows), "selected estimator differs from exact-rate winner/tie rule"),
        ("estimates.fee_floor_node_mismatch", sum(row.get("fee_floor_node_consistent") is False for row in wide_rows), "diagnostic effective floor differs from batch getmempoolinfo by more than 0.001 sat/vB"),
        ("rates.exact_fraction", sum(row.get("rate_source") == "exact_fraction" for row in evaluated_rows), "preferred normalization source"),
        ("rates.collector_normalized", sum(row.get("rate_source") == "collector_normalized_sat_kvb" for row in evaluated_rows), ""),
        ("rates.rounded_rpc_fallback", sum(row.get("rate_source") == "rounded_rpc_btc_kvb" for row in evaluated_rows), ""),
        ("outcomes.canonical_sample_tips", sum(row.get("canonical_tip_status") == "canonical" for row in evaluated_rows), ""),
        ("outcomes.stale_sample_tips", sum(row.get("canonical_tip_status") == "stale" for row in evaluated_rows), "excluded"),
        ("outcomes.unknown_sample_tip_canonicality", sum(row.get("canonical_tip_status") == "unknown" for row in evaluated_rows), "excluded"),
        ("outcomes.not_mature", sum(not row.get("mature") for row in evaluated_rows), ""),
        ("outcomes.missing_target_block_stats", sum(row.get("mature") and not row.get("outcome_available") for row in evaluated_rows), ""),
        ("outcomes.analysis_included", sum(bool(row.get("analysis_included")) for row in evaluated_rows), ""),
        ("blocks.observed", len(blocks), ""),
        ("blocks.canonical", sum(block.get("is_canonical") is True for block in blocks.values()), ""),
        ("blocks.stale", chain_metadata.get("stale_blocks", 0), ""),
        ("blocks.canonical_missing_primary_percentiles", sum(block.get("is_canonical") is True and any(block.get(name) is None for name in ("p10_sat_kvb", "p50_sat_kvb", "p75_sat_kvb")) for block in blocks.values()), ""),
        ("chain.reorg_events", chain_metadata.get("reorg_events", 0), ""),
        ("chain.cycle_detected", int(bool(chain_metadata.get("chain_cycle_detected"))), "must be zero"),
        ("node.samples", len(node_rows), ""),
        ("provider.samples", len(provider_sources), "HTTP observations, including failures"),
        ("provider.failed_samples", provider_failures, "HTTP, TLS, timeout, truncation, or decode failures"),
        ("provider.unparseable_success_samples", provider_unparseable_successes, "successful responses whose schema had no recognized target/rate pairs"),
        ("provider.estimate_points", len(provider_rows), ""),
        ("collector.errors", len(load.records.get("errors.jsonl", [])), "see collector errors stream"),
        ("input.issues", len(load.issues), "malformed/truncated/schema/metadata issues"),
    ])
    for issue_name, count in Counter(issue.category for issue in load.issues).most_common():
        metrics.append((f"issue.{issue_name}", count, ""))
    return [{"metric": name, "count": value, "detail": detail} for name, value, detail in metrics]


def markdown_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    def cell(value: Any) -> str:
        if value is None:
            return "n/a"
        if isinstance(value, float):
            return f"{value:.3f}"
        return str(value).replace("|", "\\|").replace("\n", " ")

    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(cell(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def build_report(
    input_path: Path,
    summary_rows: Sequence[Mapping[str, Any]],
    selection_rows: Sequence[Mapping[str, Any]],
    quality_rows: Sequence[Mapping[str, Any]],
    chain_metadata: Mapping[str, Any],
    wide_rows: Sequence[Mapping[str, Any]],
    provider_rows: Sequence[Mapping[str, Any]],
    settings: Mapping[str, Any],
    chart_names: Sequence[str],
) -> str:
    aggregate = [row for row in summary_rows if row.get("mode") == "ALL" and row.get("requested_target") == "ALL"]
    aggregate_table = markdown_table(
        ["Output", "Scope", "Available", "Evaluated", "Under %", "Within %", "Over %", "MAE sat/kvB", "Bias sat/kvB", "Horizon over %"],
        [
            [
                row["output"],
                row["evaluation_scope"],
                f"{row['available']}/{row['samples']}",
                row["evaluated"],
                row["primary_underestimate_pct"],
                row["primary_within_band_pct"],
                row["primary_overestimate_pct"],
                row["point_mae_sat_kvb"],
                row["point_mean_bias_sat_kvb"],
                row["horizon_overestimate_pct"],
            ]
            for row in aggregate
        ],
    )
    quality_highlights = {
        row["metric"]: row["count"]
        for row in quality_rows
        if row["metric"] in {
            "input.malformed_lines",
            "input.truncated_final_lines",
            "input.unsupported_schema_records",
            "input.issues",
            "estimates.snapshot_inconsistent",
            "estimates.selection_diagnostic_mismatch",
            "outcomes.stale_sample_tips",
            "outcomes.missing_target_block_stats",
            "provider.failed_samples",
            "provider.unparseable_success_samples",
            "collector.errors",
        }
    }
    quality_table = markdown_table(["Check", "Count"], [[key, value] for key, value in quality_highlights.items()])
    selection_table = markdown_table(
        ["Mode", "Target", "Samples", "Block lower", "Mempool lower", "Tie", "Floor applied", "Mismatch"],
        [
            [row["mode"], row["requested_target"], row["samples"], row["block_policy_lower"], row["mempool_policy_lower"], row["block_policy_tie"], row["fee_floor_applied"], row["diagnostics_inconsistent"]]
            for row in selection_rows[:30]
        ],
    )
    generated = dt.datetime.now(tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
    chart_section = "\n".join(f"- `{name}`" for name in chart_names) if chart_names else "No charts were generated."
    return f"""# Fee-estimation experiment analysis

Generated at `{generated}` from `{input_path}`.

## Executive summary

{aggregate_table if aggregate else "No estimates had enough canonical outcome data to score."}

Rates in the tables and CSV files are **sat/kvB**. Divide by 1,000 for sat/vB. The analyzer prefers the exact `(fee_sats, vsize)` fraction emitted by verbosity 3; the rounded BTC/kvB RPC field is only a fallback.

## What is scored

The primary classification is reported in two explicit scopes: the requested-target block and each output's native returned-target block:

- below block p10: `underestimate`
- from p10 through p75 (inclusive): `within_band`
- above block p75: `overestimate`

Point errors use that block's p50 as the reference. The horizon-min sensitivity repeats the calculation against the minimum p10, p50, and p75 observed over every canonical block from the sample tip through the selected scope's horizon. This second view is useful for a "confirm within N blocks" interpretation, but it is deliberately reported separately from the target-block result.

Every estimator output has independent availability, returned target, warmup, consistency, canonicality, and maturity flags. By default, scoring excludes warmup rows, snapshots whose required consistency marker is not true, samples made on a branch that did not survive, and estimates without a fully observed outcome. Current switches: `include_warmup={settings['include_warmup']}`, `include_inconsistent={settings['include_inconsistent']}`.

## Final canonical chain

- Final tip: `{chain_metadata.get('final_tip_hash') or 'unknown'}` at height `{chain_metadata.get('final_tip_height')}`
- Canonical observed span: `{chain_metadata.get('canonical_start_height')}` through `{chain_metadata.get('canonical_end_height')}`
- Observed block records: `{chain_metadata.get('observed_blocks')}`; stale records: `{chain_metadata.get('stale_blocks')}`
- Tip events: `{chain_metadata.get('tip_events')}`; detected reorg events: `{chain_metadata.get('reorg_events')}`

## Estimator selection

{selection_table if selection_rows else "No selection rows were available."}

## Data quality

{quality_table if quality_highlights else "No input-quality warnings were recorded."}

See `data_quality.csv` and `availability.csv` before drawing accuracy conclusions. In particular, a 24-hour collection may yield few independent block outcomes: polling every 30 seconds increases observations, not the number of independent target blocks. Rows sharing a target block are correlated.
The executive table is call-weighted. `summary_by_target.csv` also contains `interval_*` metrics (fixed-cadence rows only) and `tip_balanced_*` shares (every anchor tip receives equal weight), so block-triggered samples and long inter-block periods can be examined separately.

## Public providers

{f"Parsed {len(provider_rows)} provider estimate points; see `provider_estimates.csv` and `provider_metrics.csv`." if provider_rows else "No parseable provider samples were present. Provider APIs must be captured concurrently for a defensible timestamp-aligned comparison."}

Provider estimates without their own chain tip are assigned the nearest node sample with the same requested target within {settings['provider_max_skew_seconds']} seconds. That alignment and its signed skew are retained in the CSV. API labels (for example, "half hour") are mapped to documented block targets by the collector/analyzer and should not be treated as identical products without checking provider semantics.

## Charts

{chart_section}

## Interpretation limits

Block percentiles are an observable clearing-price proxy, not proof that an arbitrary transaction with that fee would have confirmed. Transaction ancestry, package policy, minimum relay/mempool floors, block construction, propagation, and censored or non-standard transactions all matter. The p10-p75 band intentionally avoids claiming a single unknowable "correct" fee. Report sample counts together with the number of distinct target blocks and use longer runs before comparing algorithms.
"""


def generate_charts(output_dir: Path, rows: Sequence[Mapping[str, Any]], summaries: Sequence[Mapping[str, Any]], mode: str) -> tuple[list[str], str | None]:
    if mode == "off":
        return [], None
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        if mode == "on":
            raise AnalysisError("--charts on requires matplotlib") from exc
        return [], "matplotlib is not installed; charts were skipped"

    chart_dir = output_dir / "charts"
    chart_dir.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []
    evaluated = [row for row in rows if row.get("analysis_included")]
    if evaluated:
        # Select the most populated mode/target to avoid connecting unrelated
        # horizons in a single time-series line.
        core_rows = [
            row
            for row in evaluated
            if not str(row.get("output", "")).startswith("provider:")
        ]
        requested_rows = [
            row
            for row in core_rows
            if row.get("evaluation_scope") == "requested_target"
        ]
        chart_population = requested_rows or core_rows or evaluated
        populations = Counter((str(row.get("mode")), str(row.get("requested_target"))) for row in chart_population)
        chosen_mode, chosen_target = populations.most_common(1)[0][0]
        selected = [row for row in chart_population if str(row.get("mode")) == chosen_mode and str(row.get("requested_target")) == chosen_target]
        figure, axis = plt.subplots(figsize=(12, 6))
        for output_name in sorted({str(row.get("output")) for row in selected}):
            output_rows = sorted((row for row in selected if row.get("output") == output_name and row.get("timestamp_epoch") is not None), key=lambda row: float(row["timestamp_epoch"]))
            if output_rows:
                times = [dt.datetime.fromtimestamp(float(row["timestamp_epoch"]), tz=dt.timezone.utc) for row in output_rows]
                rates = [float(row["estimate_sat_kvb"]) / 1000 for row in output_rows]
                axis.plot(times, rates, marker=".", linewidth=1, label=output_name)
        band_rows = sorted(
            (
                row
                for row in selected
                if row.get("output") == "selected_raw"
                and row.get("timestamp_epoch") is not None
                and row.get("target_block_p10_sat_kvb") is not None
                and row.get("target_block_p75_sat_kvb") is not None
            ),
            key=lambda row: float(row["timestamp_epoch"]),
        )
        if band_rows:
            band_times = [
                dt.datetime.fromtimestamp(
                    float(row["timestamp_epoch"]), tz=dt.timezone.utc
                )
                for row in band_rows
            ]
            axis.fill_between(
                band_times,
                [float(row["target_block_p10_sat_kvb"]) / 1000 for row in band_rows],
                [float(row["target_block_p75_sat_kvb"]) / 1000 for row in band_rows],
                alpha=0.15,
                color="black",
                label="target block p10-p75",
            )
        reference_rows: dict[str, Mapping[str, Any]] = {}
        for row in selected:
            if row.get("target_block_hash"):
                reference_rows[str(row["target_block_hash"])] = row
        references = sorted(reference_rows.values(), key=lambda row: float(row.get("timestamp_epoch") or 0))
        if references:
            times = [dt.datetime.fromtimestamp(float(row["timestamp_epoch"]), tz=dt.timezone.utc) for row in references]
            rates = [float(row["target_block_p50_sat_kvb"]) / 1000 for row in references]
            axis.scatter(times, rates, marker="x", color="black", label="target block p50", zorder=5)
        axis.set_title(f"Fee estimates: {chosen_mode}, requested target {chosen_target}")
        axis.set_ylabel("sat/vB")
        axis.set_xlabel("sample time (UTC)")
        axis.grid(alpha=0.25)
        axis.legend()
        figure.autofmt_xdate()
        figure.tight_layout()
        name = "charts/estimate_timeseries.png"
        figure.savefig(output_dir / name, dpi=150)
        plt.close(figure)
        generated.append(name)

        errors_by_output: dict[str, list[float]] = defaultdict(list)
        for row in evaluated:
            value = row.get("point_signed_error_sat_kvb")
            if value is not None:
                errors_by_output[str(row["output"])].append(float(value) / 1000)
        if errors_by_output:
            figure, axis = plt.subplots(figsize=(10, 6))
            labels = sorted(errors_by_output)
            axis.boxplot([errors_by_output[label] for label in labels], tick_labels=labels, showfliers=False)
            axis.axhline(0, color="black", linewidth=1)
            axis.set_ylabel("estimate - target block p50 (sat/vB)")
            axis.set_title("Point-error distribution")
            axis.tick_params(axis="x", rotation=20)
            axis.grid(axis="y", alpha=0.25)
            figure.tight_layout()
            name = "charts/point_error_boxplot.png"
            figure.savefig(output_dir / name, dpi=150)
            plt.close(figure)
            generated.append(name)

    aggregate = [
        row
        for row in summaries
        if row.get("mode") == "ALL"
        and row.get("requested_target") == "ALL"
        and row.get("evaluation_scope") == "requested_target"
        and row.get("evaluated")
        and not str(row.get("output", "")).startswith("provider:")
    ]
    if aggregate:
        figure, axis = plt.subplots(figsize=(10, 6))
        labels = [str(row["output"]) for row in aggregate]
        under = [float(row["primary_underestimate_pct"] or 0) for row in aggregate]
        within = [float(row["primary_within_band_pct"] or 0) for row in aggregate]
        over = [float(row["primary_overestimate_pct"] or 0) for row in aggregate]
        positions = list(range(len(labels)))
        axis.bar(positions, under, label="underestimate")
        axis.bar(positions, within, bottom=under, label="within p10-p75")
        axis.bar(positions, over, bottom=[under[i] + within[i] for i in positions], label="overestimate")
        axis.set_xticks(positions, labels, rotation=20)
        axis.set_ylabel("evaluated rows (%)")
        axis.set_ylim(0, 100)
        axis.set_title("Primary target-block classification")
        axis.legend()
        figure.tight_layout()
        name = "charts/classification_share.png"
        figure.savefig(output_dir / name, dpi=150)
        plt.close(figure)
        generated.append(name)

    target_rows = [
        row
        for row in summaries
        if row.get("output") == "selected_raw"
        and row.get("evaluation_scope") == "requested_target"
        and row.get("mode") != "ALL"
        and row.get("requested_target") != "ALL"
        and row.get("evaluated")
    ]
    for estimate_mode in sorted({str(row.get("mode")) for row in target_rows}):
        mode_rows = sorted(
            (row for row in target_rows if row.get("mode") == estimate_mode),
            key=lambda row: int(str(row["requested_target"])),
        )
        if not mode_rows:
            continue
        labels = [str(row["requested_target"]) for row in mode_rows]
        under = [float(row["primary_underestimate_pct"] or 0) for row in mode_rows]
        within = [float(row["primary_within_band_pct"] or 0) for row in mode_rows]
        over = [float(row["primary_overestimate_pct"] or 0) for row in mode_rows]
        positions = list(range(len(labels)))
        figure, axis = plt.subplots(figsize=(12, 6))
        axis.bar(positions, under, label="underestimate")
        axis.bar(positions, within, bottom=under, label="within p10-p75")
        axis.bar(
            positions,
            over,
            bottom=[under[index] + within[index] for index in positions],
            label="overestimate",
        )
        axis.set_xticks(positions, labels)
        axis.set_xlabel("requested target (blocks)")
        axis.set_ylabel("evaluated rows (%)")
        axis.set_ylim(0, 100)
        axis.set_title(f"Selected estimate classification by target: {estimate_mode}")
        axis.legend()
        figure.tight_layout()
        name = f"charts/selected_classification_{estimate_mode}.png"
        figure.savefig(output_dir / name, dpi=150)
        plt.close(figure)
        generated.append(name)

    selected_rows = [
        row
        for row in rows
        if row.get("output") == "selected_raw"
        and row.get("evaluation_scope") == "requested_target"
    ]
    reasons = Counter(str(row.get("selection_reason") or "missing") for row in selected_rows)
    if reasons:
        labels, counts = zip(*reasons.most_common())
        figure, axis = plt.subplots(figsize=(10, 6))
        axis.bar(range(len(labels)), counts)
        axis.set_xticks(range(len(labels)), labels, rotation=25, ha="right")
        axis.set_ylabel("RPC calls")
        axis.set_title("Manager selection reasons")
        axis.grid(axis="y", alpha=0.25)
        figure.tight_layout()
        name = "charts/selection_reasons.png"
        figure.savefig(output_dir / name, dpi=150)
        plt.close(figure)
        generated.append(name)

    by_sample_scope: dict[tuple[str, str], dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for row in rows:
        if (
            row.get("output") in {"selected_raw", "returned_after_floor"}
            and row.get("evaluation_scope") == "requested_target"
        ):
            key = (str(row.get("sample_id")), str(row.get("evaluation_scope")))
            by_sample_scope[key][str(row.get("output"))] = row
    floor_lifts = []
    for pair in by_sample_scope.values():
        selected = pair.get("selected_raw", {}).get("estimate_sat_kvb")
        returned = pair.get("returned_after_floor", {}).get("estimate_sat_kvb")
        if isinstance(selected, decimal.Decimal) and isinstance(returned, decimal.Decimal):
            floor_lifts.append(float(returned - selected) / 1000)
    if floor_lifts:
        figure, axis = plt.subplots(figsize=(10, 6))
        axis.hist(floor_lifts, bins=min(40, max(5, int(math.sqrt(len(floor_lifts))))))
        axis.set_xlabel("returned - selected raw (sat/vB)")
        axis.set_ylabel("observations")
        axis.set_title("RPC fee-floor lift")
        axis.grid(axis="y", alpha=0.25)
        figure.tight_layout()
        name = "charts/fee_floor_lift.png"
        figure.savefig(output_dir / name, dpi=150)
        plt.close(figure)
        generated.append(name)

    coverage_rows = [
        row
        for row in rows
        if row.get("output") == "mempool_policy_raw"
        and row.get("evaluation_scope") == "requested_target"
        and row.get("analysis_included")
        and row.get("mempool_health_coverage_ratio") is not None
        and row.get("point_absolute_log2_error") is not None
    ]
    if coverage_rows:
        figure, axis = plt.subplots(figsize=(10, 6))
        axis.scatter(
            [float(row["mempool_health_coverage_ratio"]) for row in coverage_rows],
            [float(row["point_absolute_log2_error"]) for row in coverage_rows],
            alpha=0.35,
            s=14,
        )
        axis.axvline(0.75, color="black", linestyle="--", linewidth=1, label="default threshold")
        axis.set_xlabel("mempool health coverage ratio")
        axis.set_ylabel("absolute log2 error")
        axis.set_title("Mempool coverage versus estimation error")
        axis.grid(alpha=0.25)
        axis.legend()
        figure.tight_layout()
        name = "charts/mempool_coverage_vs_error.png"
        figure.savefig(output_dir / name, dpi=150)
        plt.close(figure)
        generated.append(name)

    fullness_rows = [
        row
        for row in rows
        if row.get("output") == "selected_raw"
        and row.get("evaluation_scope") == "requested_target"
        and row.get("analysis_included")
        and row.get("target_block_non_coinbase_weight_fraction_of_4m") is not None
        and row.get("point_signed_error_sat_kvb") is not None
    ]
    if fullness_rows:
        figure, axis = plt.subplots(figsize=(10, 6))
        axis.scatter(
            [
                100
                * float(row["target_block_non_coinbase_weight_fraction_of_4m"])
                for row in fullness_rows
            ],
            [float(row["point_signed_error_sat_kvb"]) / 1000 for row in fullness_rows],
            alpha=0.35,
            s=14,
        )
        axis.axhline(0, color="black", linewidth=1)
        axis.set_xlabel("target block non-coinbase weight / 4,000,000 (%)")
        axis.set_ylabel("estimate - target block p50 (sat/vB)")
        axis.set_title("Selected-estimate bias versus target-block fullness")
        axis.grid(alpha=0.25)
        figure.tight_layout()
        name = "charts/block_fullness_vs_error.png"
        figure.savefig(output_dir / name, dpi=150)
        plt.close(figure)
        generated.append(name)
    return generated, None


def filter_experiment_records(
    load: LoadResult,
    manifest: Mapping[str, Any] | None,
    strict: bool,
) -> str | None:
    """Prevent accidental analysis of records from different experiments."""
    expected = str(manifest.get("experiment_id")) if manifest and manifest.get("experiment_id") else None
    observed = Counter(
        str(source.value["experiment_id"])
        for records in load.records.values()
        for source in records
        if source.value.get("experiment_id")
    )
    if expected is None and len(observed) == 1:
        expected = next(iter(observed))
    if expected is None and len(observed) > 1:
        raise AnalysisError(
            "input contains multiple experiment_id values and has no manifest to select one"
        )
    if expected is None:
        return None
    mismatch_count = 0
    for stream, records in list(load.records.items()):
        accepted: list[SourceRecord] = []
        for source in records:
            actual = source.value.get("experiment_id")
            if actual is not None and str(actual) != expected:
                mismatch_count += 1
                load.issues.append(
                    Issue(
                        "experiment_id_mismatch",
                        source.source,
                        source.line,
                        f"expected {expected}, got {actual}",
                    )
                )
            else:
                accepted.append(source)
        load.records[stream] = accepted
    load.counters["experiment_id_mismatch_records"] += mismatch_count
    if strict and mismatch_count:
        raise AnalysisError("strict input validation rejected mixed experiment ids")
    return expected


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize and score fee-estimator JSONL against final canonical block outcomes."
        )
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        help="collector run directory (or one JSONL file)",
    )
    parser.add_argument("--input-dir", type=Path, help="same as the positional input")
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="analysis directory (default: INPUT/analysis)",
    )
    parser.add_argument(
        "--charts",
        choices=("auto", "on", "off"),
        default="auto",
        help="generate PNG charts; auto skips them if matplotlib is absent",
    )
    parser.add_argument(
        "--no-charts", dest="charts", action="store_const", const="off", help=argparse.SUPPRESS
    )
    parser.add_argument("--include-warmup", action="store_true")
    parser.add_argument("--include-inconsistent", action="store_true")
    parser.add_argument("--strict-input", action="store_true")
    parser.add_argument(
        "--provider-max-skew-seconds",
        type=float,
        default=90.0,
        help="maximum provider-to-Core timestamp alignment difference (default: 90)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace named files in an existing analysis directory",
    )
    return parser


def preferred_score_fields() -> tuple[str, ...]:
    return (
        "experiment_id",
        "run_id",
        "sample_id",
        "batch_id",
        "batch_sequence",
        "request_order",
        "timestamp_utc",
        "schedule_lag_ms",
        "rpc_duration_ms",
        "mode",
        "requested_target",
        "output",
        "estimator",
        "evaluation_scope",
        "evaluation_horizon_blocks",
        "native_returned_target",
        "estimate_sat_vb",
        "estimate_sat_kvb",
        "estimate_fee_sats",
        "estimate_vsize",
        "rate_source",
        "selected_estimator",
        "selection_reason",
        "fee_floor_applied",
        "available",
        "warmup",
        "output_consistent",
        "canonical_tip_status",
        "mature",
        "outcome_available",
        "analysis_status",
        "analysis_included",
        "analysis_exclusion_reason",
        "aggregation_duplicate",
        "tip_hash",
        "tip_height",
        "target_block_hash",
        "target_block_height",
        "target_block_time_utc",
        "target_block_discovery_utc",
        "target_block_discovery_is_exact",
        "seconds_to_target_discovery",
        "target_block_p10_sat_kvb",
        "target_block_p50_sat_kvb",
        "target_block_p75_sat_kvb",
        "target_block_average_sat_kvb",
        "target_block_total_weight",
        "target_block_non_coinbase_weight_fraction_of_4m",
        "primary_classification",
        "primary_band_error_sat_kvb",
        "point_signed_error_sat_kvb",
        "point_absolute_error_sat_kvb",
        "point_absolute_percentage_error",
        "point_estimate_to_p50_ratio",
        "point_log2_ratio",
        "point_absolute_log2_error",
        "horizon_analysis_included",
        "horizon_classification",
        "horizon_min_p10_sat_kvb",
        "horizon_min_p50_sat_kvb",
        "horizon_min_p75_sat_kvb",
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.input is not None and args.input_dir is not None:
        parser.error("use either positional INPUT or --input-dir, not both")
    input_path = (args.input_dir or args.input)
    if input_path is None:
        parser.error("an input run directory is required")
    input_path = input_path.resolve()
    output_dir = (
        args.output_dir.resolve()
        if args.output_dir is not None
        else ((input_path if input_path.is_dir() else input_path.parent) / "analysis").resolve()
    )
    if args.provider_max_skew_seconds < 0:
        parser.error("--provider-max-skew-seconds cannot be negative")
    if output_dir.exists() and any(output_dir.iterdir()) and not args.overwrite:
        parser.error(
            f"output directory {output_dir} is not empty; use --overwrite or choose another"
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        load = load_inputs(input_path, args.strict_input)
        manifest, run_state = input_metadata(input_path, load)
        experiment_id = filter_experiment_records(load, manifest, args.strict_input)

        node_rows = normalize_node_samples(load)
        wide_rows: list[dict[str, Any]] = []
        base_output_rows: list[dict[str, Any]] = []
        for source in extract_estimate_records(load):
            wide, outputs = normalize_estimate(source)
            wide_rows.append(wide)
            base_output_rows.extend(outputs)
        attach_node_context(wide_rows, base_output_rows, node_rows)
        refresh_wide_validity(wide_rows, base_output_rows)

        blocks, canonical_by_height, tip_events, chain_metadata = build_chain(
            load, wide_rows
        )
        scored_rows: list[dict[str, Any]] = []
        for row in base_output_rows:
            requested_target = as_int(row.get("requested_target"))
            native_target = as_int(row.get("returned_target"))
            scored_rows.append(
                score_output(
                    row,
                    blocks,
                    canonical_by_height,
                    chain_metadata,
                    args.include_warmup,
                    args.include_inconsistent,
                    evaluation_scope="requested_target",
                    evaluation_target=requested_target,
                )
            )
            scored_rows.append(
                score_output(
                    row,
                    blocks,
                    canonical_by_height,
                    chain_metadata,
                    args.include_warmup,
                    args.include_inconsistent,
                    evaluation_scope="native_target",
                    evaluation_target=native_target,
                )
            )
        mark_native_mempool_duplicates(scored_rows)

        provider_rows = normalize_provider_samples(
            load,
            wide_rows,
            blocks,
            canonical_by_height,
            chain_metadata,
            args.provider_max_skew_seconds,
        )
        summary_rows = summarize(scored_rows)
        provider_summary_rows = summarize(provider_rows)
        availability_rows = availability_summary([*scored_rows, *provider_rows])
        selection_rows = selection_summary(wide_rows)
        pairwise_rows = pairwise_summary(scored_rows)
        canonical_blocks = sorted(
            blocks.values(),
            key=lambda row: (
                row.get("height") if row.get("height") is not None else -1,
                str(row.get("block_hash")),
            ),
        )
        quality_rows = make_data_quality(
            load,
            wide_rows,
            scored_rows,
            blocks,
            chain_metadata,
            node_rows,
            provider_rows,
        )

        write_csv(
            output_dir / "normalized_estimates.csv",
            wide_rows,
            (
                "experiment_id",
                "run_id",
                "sample_id",
                "batch_id",
                "batch_sequence",
                "request_order",
                "timestamp_utc",
                "mode",
                "requested_target",
                "tip_hash",
                "tip_height",
                "block_policy_estimate_raw_sat_kvb",
                "block_policy_fee_sats",
                "block_policy_vsize",
                "mempool_policy_estimate_raw_sat_kvb",
                "mempool_policy_fee_sats",
                "mempool_policy_vsize",
                "selected_estimator",
                "selection_reason",
                "selected_raw_sat_kvb",
                "node_fee_floor_sat_kvb",
                "returned_estimate_sat_kvb",
                "returned_target",
                "snapshot_consistent",
                "sample_snapshot_valid",
                "block_policy_valid_strict",
                "mempool_policy_valid_strict",
                "selected_valid_strict",
                "returned_valid_strict",
                "sample_valid_strict",
                "warmup",
            ),
        )
        write_csv(output_dir / "scores.csv", scored_rows, preferred_score_fields())
        write_csv(
            output_dir / "summary_by_target.csv",
            summary_rows,
            ("output", "mode", "requested_target", "evaluation_scope"),
        )
        write_csv(
            output_dir / "availability.csv",
            availability_rows,
            ("output", "mode", "requested_target", "evaluation_scope"),
        )
        write_csv(
            output_dir / "selection_summary.csv",
            selection_rows,
            ("mode", "requested_target"),
        )
        write_csv(
            output_dir / "pairwise_comparison.csv",
            pairwise_rows,
            ("left_output", "right_output", "mode", "requested_target", "evaluation_scope"),
        )
        write_csv(
            output_dir / "canonical_blocks.csv",
            canonical_blocks,
            ("height", "block_hash", "previous_block_hash", "is_canonical"),
        )
        write_csv(
            output_dir / "tip_events.csv",
            tip_events,
            ("timestamp_utc", "event_type", "new_tip_height", "new_tip_hash"),
        )
        write_csv(output_dir / "node_samples.csv", node_rows, ("timestamp_utc", "batch_id"))
        write_csv(
            output_dir / "provider_estimates.csv",
            provider_rows,
            preferred_score_fields(),
        )
        write_csv(
            output_dir / "provider_metrics.csv",
            provider_summary_rows,
            ("output", "mode", "requested_target", "evaluation_scope"),
        )
        write_csv(output_dir / "data_quality.csv", quality_rows, ("metric", "count", "detail"))

        chart_names, chart_warning = generate_charts(
            output_dir, [*scored_rows, *provider_rows], [*summary_rows, *provider_summary_rows], args.charts
        )
        if chart_warning:
            print(f"warning: {chart_warning}", file=sys.stderr)

        settings = {
            "include_warmup": args.include_warmup,
            "include_inconsistent": args.include_inconsistent,
            "strict_input": args.strict_input,
            "provider_max_skew_seconds": args.provider_max_skew_seconds,
            "charts": args.charts,
        }
        report = build_report(
            input_path,
            summary_rows,
            selection_rows,
            quality_rows,
            chain_metadata,
            wide_rows,
            provider_rows,
            settings,
            chart_names,
        )
        atomic_text(output_dir / "analysis_report.md", report)

        analysis_manifest = {
            "analysis_schema_version": ANALYZER_SCHEMA_VERSION,
            "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace(
                "+00:00", "Z"
            ),
            "input_path": str(input_path),
            "output_path": str(output_dir),
            "experiment_id": experiment_id,
            "settings": settings,
            "collector_manifest": manifest,
            "collector_run_state": run_state,
            "chain": chain_metadata,
            "counts": {
                "estimate_calls": len(wide_rows),
                "score_rows": len(scored_rows),
                "included_score_rows": sum(bool(row.get("analysis_included")) for row in scored_rows),
                "provider_score_rows": len(provider_rows),
                "observed_blocks": len(blocks),
                "node_samples": len(node_rows),
                "input_issues": len(load.issues),
            },
            "input_files": [
                {
                    "name": path.name,
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
                for path in load.paths
            ],
            "charts": chart_names,
            "chart_warning": chart_warning,
        }
        atomic_text(
            output_dir / "analysis_manifest.json",
            json.dumps(analysis_manifest, indent=2, sort_keys=True, default=str) + "\n",
        )
    except AnalysisError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        f"analysis complete: {len(wide_rows)} estimate calls, "
        f"{sum(bool(row.get('analysis_included')) for row in scored_rows)} eligible score rows; "
        f"outputs in {output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
