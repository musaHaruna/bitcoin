#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Collect Bitcoin Core fee-estimator diagnostics and their future outcomes.

The collector deliberately stores append-only JSON Lines with the complete RPC
results.  Flattening and scoring are performed by analyze_fee_estimates.py so a
new analysis cannot require data that was discarded during collection.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import http.client
import json
import math
import os
import pathlib
import queue
import signal
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Iterable


SCHEMA_VERSION = 1
DEFAULT_TARGETS = (1, 2, 3, 6, 12, 24, 48, 72, 144)
DEFAULT_MODES = ("economical", "conservative")
STREAM_NAMES = (
    "estimates.jsonl",
    "node_samples.jsonl",
    "blocks.jsonl",
    "provider_samples.jsonl",
    "errors.jsonl",
)
BLOCK_STATS = (
    "blockhash",
    "height",
    "time",
    "mediantime",
    "avgfeerate",
    "feerate_percentiles",
    "minfeerate",
    "maxfeerate",
    "total_weight",
    "totalfee",
    "txs",
)


def utc_now() -> str:
    """Return an unambiguous, lexically sortable UTC timestamp."""
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def utc_from_epoch(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def parse_duration(value: str) -> float:
    """Parse a duration such as 30s, 10m, 24h, or 1d into seconds."""
    text = value.strip().lower()
    units = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}
    for suffix in ("ms", "s", "m", "h", "d"):
        if text.endswith(suffix):
            try:
                result = float(text[: -len(suffix)]) * units[suffix]
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"invalid duration: {value}") from exc
            if not math.isfinite(result) or result < 0:
                raise argparse.ArgumentTypeError("duration must be finite and non-negative")
            return result
    try:
        result = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid duration {value!r}; use a suffix such as 30s or 24h"
        ) from exc
    if not math.isfinite(result) or result < 0:
        raise argparse.ArgumentTypeError("duration must be finite and non-negative")
    return result


def parse_targets(value: str) -> tuple[int, ...]:
    try:
        targets = tuple(dict.fromkeys(int(item.strip()) for item in value.split(",")))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("targets must be comma-separated integers") from exc
    if not targets or any(target < 1 or target > 1008 for target in targets):
        raise argparse.ArgumentTypeError("every target must be between 1 and 1008")
    return targets


def parse_modes(value: str) -> tuple[str, ...]:
    modes = tuple(dict.fromkeys(item.strip().lower() for item in value.split(",")))
    allowed = {"economical", "conservative"}
    if not modes or any(mode not in allowed for mode in modes):
        raise argparse.ArgumentTypeError(
            "modes must contain economical and/or conservative"
        )
    return modes


@dataclass(frozen=True)
class Provider:
    name: str
    url: str


def parse_provider(value: str) -> Provider:
    if "=" not in value:
        raise argparse.ArgumentTypeError("provider must be NAME=URL")
    name, url = value.split("=", 1)
    name = name.strip()
    parsed = urllib.parse.urlsplit(url.strip())
    if not name or not all(char.isalnum() or char in "-_." for char in name):
        raise argparse.ArgumentTypeError("provider NAME contains invalid characters")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError("provider URL must be http:// or https://")
    return Provider(name=name, url=url.strip())


def rpc_url_for_log(value: str) -> str:
    """Return an endpoint without credentials, query-string secrets, or fragments."""
    parsed = urllib.parse.urlsplit(value)
    if not parsed.hostname:
        return "invalid-rpc-url"
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    port = f":{parsed.port}" if parsed.port is not None else ""
    path = parsed.path or "/"
    return urllib.parse.urlunsplit((parsed.scheme, f"{host}{port}", path, "", ""))


def url_has_secret_parts(value: str) -> bool:
    parsed = urllib.parse.urlsplit(value)
    return bool(parsed.username or parsed.password or parsed.query or parsed.fragment)


def default_bitcoin_datadir() -> pathlib.Path:
    """Match Bitcoin Core's platform-specific default data directory."""
    if sys.platform == "darwin":
        return pathlib.Path.home() / "Library" / "Application Support" / "Bitcoin"
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        return pathlib.Path(appdata) / "Bitcoin" if appdata else pathlib.Path.home() / "Bitcoin"
    return pathlib.Path.home() / ".bitcoin"


class RPCTransportError(RuntimeError):
    """An HTTP, authentication, or response-framing error."""


class JSONRPCClient:
    """Small persistent JSON-RPC 2.0 client with cookie authentication."""

    def __init__(
        self,
        url: str,
        *,
        cookie: pathlib.Path | None,
        rpc_user: str | None,
        rpc_password: str | None,
        timeout: float,
    ) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("RPC URL must be an http:// or https:// URL")
        self._scheme = parsed.scheme
        self._host = parsed.hostname
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._path = parsed.path or "/"
        if parsed.query:
            self._path += "?" + parsed.query
        url_user = urllib.parse.unquote(parsed.username) if parsed.username else None
        url_password = urllib.parse.unquote(parsed.password) if parsed.password else None
        self._user = rpc_user if rpc_user is not None else url_user
        self._password = rpc_password if rpc_password is not None else url_password
        self._cookie = cookie
        self._timeout = timeout
        self._connection: http.client.HTTPConnection | None = None
        self._lock = threading.Lock()

    def clone(self, *, timeout: float | None = None) -> "JSONRPCClient":
        scheme = self._scheme
        host = f"[{self._host}]" if ":" in self._host else self._host
        return JSONRPCClient(
            f"{scheme}://{host}:{self._port}{self._path}",
            cookie=self._cookie,
            rpc_user=self._user,
            rpc_password=self._password,
            timeout=self._timeout if timeout is None else timeout,
        )

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def _credentials(self) -> tuple[str, str]:
        if self._user is not None and self._password is not None:
            return self._user, self._password
        if self._cookie is None:
            raise RPCTransportError(
                "no RPC authentication configured; pass --cookie or both "
                "--rpc-user and --rpc-password"
            )
        try:
            cookie_text = self._cookie.expanduser().read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RPCTransportError(f"cannot read RPC cookie {self._cookie}: {exc}") from exc
        if ":" not in cookie_text:
            raise RPCTransportError(f"malformed RPC cookie {self._cookie}")
        return tuple(cookie_text.split(":", 1))  # type: ignore[return-value]

    def _new_connection(self) -> http.client.HTTPConnection:
        if self._scheme == "https":
            return http.client.HTTPSConnection(
                self._host,
                self._port,
                timeout=self._timeout,
                context=ssl.create_default_context(),
            )
        return http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)

    def batch(self, calls: Iterable[tuple[str, str, list[Any]]]) -> dict[str, dict[str, Any]]:
        requests = [
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            for request_id, method, params in calls
        ]
        if not requests:
            return {}
        body = json.dumps(requests, separators=(",", ":")).encode("utf-8")
        user, password = self._credentials()
        token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
            "Connection": "keep-alive",
        }
        with self._lock:
            # A single reconnect handles a server restart or a stale keep-alive
            # socket. Calls are read-only, and no retry is made for RPC errors.
            for attempt in range(2):
                if self._connection is None:
                    self._connection = self._new_connection()
                try:
                    self._connection.request("POST", self._path, body=body, headers=headers)
                    response = self._connection.getresponse()
                    payload = response.read()
                except (OSError, http.client.HTTPException) as exc:
                    self._connection.close()
                    self._connection = None
                    if attempt == 0:
                        continue
                    raise RPCTransportError(f"RPC transport failed: {exc}") from exc
                if response.status != 200:
                    if response.status in {401, 403}:
                        # Re-read the cookie on the next user-visible attempt.
                        self._connection.close()
                        self._connection = None
                    excerpt = payload.decode("utf-8", errors="replace")[:500]
                    raise RPCTransportError(
                        f"RPC HTTP {response.status} {response.reason}: {excerpt}"
                    )
                try:
                    decoded = json.loads(payload)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise RPCTransportError("RPC returned invalid JSON") from exc
                responses = decoded if isinstance(decoded, list) else [decoded]
                by_id: dict[str, dict[str, Any]] = {}
                for item in responses:
                    if not isinstance(item, dict) or "id" not in item:
                        raise RPCTransportError("RPC batch contains an invalid response item")
                    by_id[str(item["id"])] = item
                missing = [request["id"] for request in requests if request["id"] not in by_id]
                if missing:
                    raise RPCTransportError(f"RPC batch omitted response ids: {missing}")
                return by_id
        raise AssertionError("unreachable")

    def call(self, method: str, params: list[Any] | None = None) -> dict[str, Any]:
        response = self.batch((("single", method, params or []),))["single"]
        return response


class OutputStore:
    """Thread-safe append-only streams plus atomically replaced run state."""

    def __init__(self, output_dir: pathlib.Path, *, resume: bool) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = output_dir / "manifest.json"
        self.state_path = output_dir / "run_state.json"
        existing = [path for path in output_dir.iterdir() if path.name != ".DS_Store"]
        if resume:
            if not self.manifest_path.exists():
                raise ValueError("--resume requires an existing manifest.json")
        elif existing:
            raise ValueError(
                f"output directory {output_dir} is not empty; choose another directory or use --resume"
            )
        self._handles = {
            name: (output_dir / name).open("a", encoding="utf-8", buffering=1)
            for name in STREAM_NAMES
        }
        self._lock = threading.Lock()

    def append(self, stream: str, record: dict[str, Any]) -> None:
        encoded = json.dumps(record, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
        with self._lock:
            self._handles[stream].write(encoded + "\n")

    def sync(self) -> None:
        with self._lock:
            for handle in self._handles.values():
                handle.flush()
                os.fsync(handle.fileno())

    def write_atomic(self, path: pathlib.Path, value: dict[str, Any]) -> None:
        fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, path)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise

    def close(self) -> None:
        self.sync()
        with self._lock:
            for handle in self._handles.values():
                handle.close()


def rpc_value(response: dict[str, Any] | None) -> Any:
    if not response or response.get("error") is not None:
        return None
    return response.get("result")


def rpc_error(response: dict[str, Any] | None) -> Any:
    if response is None:
        return {"type": "missing_response", "message": "RPC response was absent"}
    return response.get("error")


def safe_load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def iter_jsonl(path: pathlib.Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value


def fetch_provider(
    provider: Provider,
    *,
    experiment_id: str,
    run_id: str,
    batch_id: str,
    scheduled_utc: str,
    timeout: float,
    max_bytes: int,
    ca_file: pathlib.Path | None,
) -> dict[str, Any]:
    started_utc = utc_now()
    started = time.monotonic()
    status: int | None = None
    headers: dict[str, str] = {}
    raw_text: str | None = None
    parsed_json: Any = None
    error: dict[str, Any] | None = None
    truncated = False
    request = urllib.request.Request(
        provider.url,
        headers={"Accept": "application/json", "User-Agent": "bitcoin-core-fee-study/1"},
    )
    try:
        context = ssl.create_default_context(cafile=str(ca_file)) if ca_file else None
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            status = response.status
            headers = {
                key.lower(): value
                for key, value in response.headers.items()
                if key.lower() in {"content-type", "retry-after", "etag", "last-modified"}
            }
            payload = response.read(max_bytes + 1)
            truncated = len(payload) > max_bytes
            raw_text = payload[:max_bytes].decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = {
            key.lower(): value
            for key, value in exc.headers.items()
            if key.lower() in {"content-type", "retry-after", "etag", "last-modified"}
        }
        raw_text = exc.read(max_bytes).decode("utf-8", errors="replace")
        error = {"type": "http", "message": str(exc), "status": exc.code}
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        error = {"type": "transport", "message": str(exc)}
    if raw_text is not None and not truncated:
        try:
            parsed_json = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            if error is None:
                error = {"type": "invalid_json", "message": str(exc)}
    if truncated and error is None:
        error = {
            "type": "response_too_large",
            "message": f"provider response exceeded {max_bytes} bytes",
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "provider_sample",
        "experiment_id": experiment_id,
        "run_id": run_id,
        "batch_id": batch_id,
        "provider": provider.name,
        "url": rpc_url_for_log(provider.url),
        "scheduled_utc": scheduled_utc,
        "request_started_utc": started_utc,
        "response_received_utc": utc_now(),
        "latency_ms": round((time.monotonic() - started) * 1000, 3),
        "http_status": status,
        "response_headers": headers,
        "json": parsed_json,
        "raw_text": raw_text,
        "truncated": truncated,
        "error": error,
    }


class Collector:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.output_dir = args.output_dir.resolve()
        self.store = OutputStore(self.output_dir, resume=args.resume)
        self.run_id = str(uuid.uuid4())
        if args.resume:
            manifest = safe_load_json(self.store.manifest_path)
            if manifest.get("schema_version") != SCHEMA_VERSION:
                raise ValueError("existing experiment uses an unsupported schema version")
            self.experiment_id = str(manifest["experiment_id"])
            expected = manifest.get("collection", {})
            if not expected.get("targets") or not expected.get("modes"):
                raise ValueError("manifest.json is missing collection targets or modes")
            # The original manifest is authoritative on resume. This prevents
            # an unnoticed change of targets, cadence, or provider population
            # halfway through one experiment.
            args.targets = tuple(int(value) for value in expected["targets"])
            args.modes = tuple(str(value) for value in expected["modes"])
            args.interval = float(expected.get("interval_seconds", args.interval))
            args.sample_duration = float(
                expected.get("sample_duration_seconds", args.sample_duration)
            )
            args.outcome_tail = float(
                expected.get("outcome_tail_seconds", args.outcome_tail)
            )
            args.outcome_tail_blocks = int(
                expected.get("outcome_tail_blocks", args.outcome_tail_blocks)
            )
            args.sample_on_block = bool(
                expected.get("sample_on_block", args.sample_on_block)
            )
            args.no_block_watcher = not bool(
                expected.get("block_watcher", not args.no_block_watcher)
            )
            args.provider_interval = float(
                expected.get("provider_interval_seconds", args.provider_interval)
            )
            args.rpc_timeout = float(
                expected.get("rpc_timeout_seconds", args.rpc_timeout)
            )
            args.provider_timeout = float(
                expected.get("provider_timeout_seconds", args.provider_timeout)
            )
            args.provider_max_bytes = int(
                expected.get("provider_max_bytes", args.provider_max_bytes)
            )
            args.block_wait_timeout = int(
                expected.get("block_wait_timeout_ms", args.block_wait_timeout)
            )
            args.max_backfill_blocks = int(
                expected.get("max_backfill_blocks", args.max_backfill_blocks)
            )
            manifest_providers = list(expected.get("providers", []))
            if args.provider:
                supplied = {
                    provider.name: rpc_url_for_log(provider.url)
                    for provider in args.provider
                }
                recorded = {
                    str(item["name"]): str(item["url"])
                    for item in manifest_providers
                }
                if supplied != recorded:
                    raise ValueError(
                        "--provider values do not match the original experiment"
                    )
            elif any(item.get("url_redacted") for item in manifest_providers):
                raise ValueError(
                    "the original provider URL contained redacted credentials or a query; "
                    "repeat its --provider NAME=URL option when resuming"
                )
            else:
                args.provider = [
                    Provider(name=str(item["name"]), url=str(item["url"]))
                    for item in manifest_providers
                ]
            if args.provider_ca_file is None and expected.get("provider_ca_file"):
                args.provider_ca_file = pathlib.Path(expected["provider_ca_file"])
            deadline_text = expected.get("sampling_deadline_utc")
            try:
                self.sample_deadline_epoch = dt.datetime.fromisoformat(
                    str(deadline_text).replace("Z", "+00:00")
                ).timestamp()
            except (TypeError, ValueError):
                created_text = manifest.get("created_utc")
                try:
                    created_epoch = dt.datetime.fromisoformat(
                        str(created_text).replace("Z", "+00:00")
                    ).timestamp()
                except (TypeError, ValueError) as exc:
                    raise ValueError("manifest has no valid sampling deadline") from exc
                self.sample_deadline_epoch = created_epoch + float(
                    expected.get("sample_duration_seconds", args.sample_duration)
                )
        else:
            self.experiment_id = str(uuid.uuid4())
            # Set after preflight succeeds so RPC startup delays do not shorten
            # the requested sampling window.
            self.sample_deadline_epoch = 0.0
        self.rpc = JSONRPCClient(
            args.rpc_url,
            cookie=args.cookie,
            rpc_user=args.rpc_user,
            rpc_password=args.rpc_password,
            timeout=args.rpc_timeout,
        )
        self.block_rpc = self.rpc.clone(
            timeout=max(args.rpc_timeout, args.block_wait_timeout / 1000 + 10)
        )
        self.stop_event = threading.Event()
        self.block_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.tip_lock = threading.Lock()
        self.current_tip_hash: str | None = None
        self.current_tip_height: int | None = None
        self.current_tip_discovery_utc: str | None = None
        self.batch_sequence = 0
        self.known_blocks: set[str] = set()
        self.block_thread: threading.Thread | None = None
        self.next_provider_at = 0.0
        self.outcome_required_height: int | None = None
        self.last_sample_tip_height: int | None = None
        self._load_resume_state()

    def _load_resume_state(self) -> None:
        if self.args.resume and self.store.state_path.exists():
            state = safe_load_json(self.store.state_path)
            self.batch_sequence = int(state.get("next_batch_sequence", 0))
            if state.get("outcome_required_height") is not None:
                self.outcome_required_height = int(state["outcome_required_height"])
            if state.get("last_sample_tip_height") is not None:
                self.last_sample_tip_height = int(state["last_sample_tip_height"])
        for record in iter_jsonl(self.output_dir / "blocks.jsonl"):
            if record.get("record_type") == "block_observation" and record.get("block_hash"):
                self.known_blocks.add(str(record["block_hash"]))
            if record.get("record_type") == "tip_event" and record.get("tip_hash"):
                record_tip_hash = str(record["tip_hash"])
                if record_tip_hash != self.current_tip_hash:
                    self.current_tip_discovery_utc = None
                self.current_tip_hash = record_tip_hash
                if record.get("tip_height") is not None:
                    self.current_tip_height = int(record["tip_height"])
                if record.get("discovery_is_exact") and record.get("discovery_utc"):
                    self.current_tip_discovery_utc = str(record["discovery_utc"])

    def _base_record(self, record_type: str) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "record_type": record_type,
            "experiment_id": self.experiment_id,
            "run_id": self.run_id,
        }

    def record_error(
        self,
        component: str,
        message: str,
        *,
        fatal: bool = False,
        context: dict[str, Any] | None = None,
    ) -> None:
        record = self._base_record("collector_error")
        record.update(
            {
                "timestamp_utc": utc_now(),
                "component": component,
                "message": message,
                "fatal": fatal,
                "context": context or {},
            }
        )
        self.store.append("errors.jsonl", record)
        level = "fatal" if fatal else "warning"
        print(f"{level}: {component}: {message}", file=sys.stderr, flush=True)

    def _write_state(self, phase: str) -> None:
        state = self._base_record("run_state")
        with self.tip_lock:
            tip_hash = self.current_tip_hash
            tip_height = self.current_tip_height
        state.update(
            {
                "updated_utc": utc_now(),
                "phase": phase,
                "sampling_deadline_utc": dt.datetime.fromtimestamp(
                    self.sample_deadline_epoch, tz=dt.timezone.utc
                ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "outcome_deadline_utc": dt.datetime.fromtimestamp(
                    self.sample_deadline_epoch + self.args.outcome_tail,
                    tz=dt.timezone.utc,
                ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "next_batch_sequence": self.batch_sequence,
                "tip_hash": tip_hash,
                "tip_height": tip_height,
                "outcome_required_height": self.outcome_required_height,
                "last_sample_tip_height": self.last_sample_tip_height,
            }
        )
        self.store.write_atomic(self.store.state_path, state)

    def _write_manifest(self, preflight: dict[str, Any]) -> None:
        if self.args.resume:
            return
        created_utc = utc_now()
        deadline_utc = dt.datetime.fromtimestamp(
            self.sample_deadline_epoch, tz=dt.timezone.utc
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        outcome_deadline_utc = dt.datetime.fromtimestamp(
            self.sample_deadline_epoch + self.args.outcome_tail,
            tz=dt.timezone.utc,
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "experiment_manifest",
            "experiment_id": self.experiment_id,
            "created_utc": created_utc,
            "collector": pathlib.Path(__file__).name,
            "python_version": sys.version.split()[0],
            "collection": {
                "targets": list(self.args.targets),
                "modes": list(self.args.modes),
                "interval_seconds": self.args.interval,
                "sample_duration_seconds": self.args.sample_duration,
                "sampling_started_utc": created_utc,
                "sampling_deadline_utc": deadline_utc,
                "outcome_deadline_utc": outcome_deadline_utc,
                "outcome_tail_seconds": self.args.outcome_tail,
                "outcome_tail_blocks": self.args.outcome_tail_blocks,
                "sample_on_block": self.args.sample_on_block,
                "block_watcher": not self.args.no_block_watcher,
                "provider_interval_seconds": self.args.provider_interval,
                "rpc_timeout_seconds": self.args.rpc_timeout,
                "provider_timeout_seconds": self.args.provider_timeout,
                "provider_max_bytes": self.args.provider_max_bytes,
                "block_wait_timeout_ms": self.args.block_wait_timeout,
                "max_backfill_blocks": self.args.max_backfill_blocks,
                "providers": [
                    {
                        "name": provider.name,
                        "url": rpc_url_for_log(provider.url),
                        "url_redacted": url_has_secret_parts(provider.url),
                    }
                    for provider in self.args.provider
                ],
                "provider_ca_file": str(self.args.provider_ca_file)
                if self.args.provider_ca_file
                else None,
            },
            "rpc": {
                "url": rpc_url_for_log(self.args.rpc_url),
                "datadir": str(self.args.datadir.resolve()) if self.args.datadir else None,
                "authentication": (
                    "user_password"
                    if self.args.rpc_user or urllib.parse.urlsplit(self.args.rpc_url).username
                    else "cookie"
                ),
                "cookie_path": str(self.args.cookie) if self.args.cookie else None,
            },
            "preflight": preflight,
            "units": {
                "rpc_formatted_feerate": "BTC/kvB",
                "diagnostic_exact_ratio": "feerate_fee_sats / feerate_vsize = sat/vB",
                "block_stats_feerate": "sat/vB",
            },
        }
        self.store.write_atomic(self.store.manifest_path, manifest)

    def preflight(self) -> dict[str, Any]:
        calls = (
            ("chain", "getblockchaininfo", []),
            ("mempool", "getmempoolinfo", []),
            ("chainstates", "getchainstates", []),
            ("network", "getnetworkinfo", []),
            ("uptime", "uptime", []),
            (
                "diagnostic",
                "estimatesmartfee",
                [
                    2,
                    "economical",
                    {"verbosity": 3, "fee_rate_estimator": "none"},
                ],
            ),
        )
        started = time.monotonic()
        responses = self.rpc.batch(calls)
        preflight = {
            key: {"result": rpc_value(responses.get(key)), "error": rpc_error(responses.get(key))}
            for key, _, _ in calls
        }
        preflight["latency_ms"] = round((time.monotonic() - started) * 1000, 3)
        chain = rpc_value(responses["chain"])
        diagnostic = rpc_value(responses["diagnostic"])
        if not isinstance(chain, dict):
            raise RPCTransportError("getblockchaininfo failed during preflight")
        if chain.get("chain") != self.args.expected_chain:
            raise ValueError(
                f"expected chain {self.args.expected_chain!r}, got {chain.get('chain')!r}"
            )
        if chain.get("chain") != "main" and not self.args.allow_non_mainnet:
            raise ValueError(
                "non-mainnet collection requires --allow-non-mainnet in addition "
                "to the matching --expected-chain"
            )
        if not isinstance(diagnostic, dict) or not isinstance(
            diagnostic.get("diagnostics"), dict
        ):
            raise ValueError(
                "estimatesmartfee verbosity 3 diagnostics are unavailable; rebuild and run "
                "bitcoind from this instrumented branch"
            )
        warnings: list[str] = []
        mempool = rpc_value(responses["mempool"])
        network = rpc_value(responses["network"])
        if chain.get("initialblockdownload"):
            warnings.append("active chainstate is still in initial block download")
        if chain.get("blocks") != chain.get("headers"):
            warnings.append("active chainstate has not reached the best known header")
        if not chain.get("pruned"):
            warnings.append("node is not running in prune mode")
        if isinstance(mempool, dict) and mempool.get("loaded") is False:
            warnings.append("mempool is not loaded")
        if isinstance(network, dict) and int(network.get("connections", 0)) == 0:
            warnings.append("node has no network peers")
        for warning in warnings:
            self.record_error("preflight", warning)
        if self.args.require_pruned and not chain.get("pruned"):
            raise ValueError("--require-pruned was set but the node reports pruned=false")
        preflight["warnings"] = warnings
        return preflight

    def write_preflight_node_sample(self, preflight: dict[str, Any]) -> None:
        record = self._base_record("node_preflight")
        record.update({"timestamp_utc": utc_now(), "rpc": preflight})
        self.store.append("node_samples.jsonl", record)

    def _tip(self) -> tuple[str | None, int | None]:
        with self.tip_lock:
            return self.current_tip_hash, self.current_tip_height

    def _tip_discovery(self) -> tuple[str | None, str | None]:
        with self.tip_lock:
            return self.current_tip_hash, self.current_tip_discovery_utc

    def _set_tip(self, block_hash: str, height: int, discovery_utc: str | None) -> None:
        with self.tip_lock:
            if block_hash == self.current_tip_hash and discovery_utc is None:
                discovery_utc = self.current_tip_discovery_utc
            self.current_tip_hash = block_hash
            self.current_tip_height = height
            self.current_tip_discovery_utc = discovery_utc

    def _single_rpc(self, method: str, params: list[Any]) -> tuple[Any, Any]:
        response = self.rpc.call(method, params)
        return rpc_value(response), rpc_error(response)

    def _observe_block(
        self,
        block_hash: str,
        header: dict[str, Any],
        *,
        source: str,
        observed_utc: str,
        discovery_utc: str | None,
    ) -> None:
        try:
            stats, stats_error = self._single_rpc(
                "getblockstats", [block_hash, list(BLOCK_STATS)]
            )
        except Exception as exc:
            # A node restart or short transport outage must not terminate a
            # day-long run.  Preserve the header/parent link and make the
            # missing outcome explicit so it can be excluded during analysis.
            stats = None
            stats_error = {"type": type(exc).__name__, "message": str(exc)}
            self.record_error(
                "block_stats",
                f"could not fetch statistics for {block_hash}: {exc}",
                context={"block_hash": block_hash},
            )
        record = self._base_record("block_observation")
        record.update(
            {
                "observed_utc": observed_utc,
                "discovery_utc": discovery_utc,
                "discovery_is_exact": discovery_utc is not None,
                "source": source,
                "block_hash": block_hash,
                "height": header.get("height"),
                "previous_block_hash": header.get("previousblockhash"),
                "header": header,
                "header_error": None,
                "block_stats": stats,
                "block_stats_error": stats_error,
            }
        )
        self.store.append("blocks.jsonl", record)
        self.known_blocks.add(block_hash)

    def observe_tip(
        self,
        block_hash: str,
        height: int,
        *,
        source: str,
        observed_utc: str | None = None,
        discovery_utc: str | None = None,
    ) -> None:
        observed_utc = observed_utc or utc_now()
        old_hash, old_height = self._tip()
        chain: list[tuple[str, dict[str, Any]]] = []
        cursor = block_hash
        initial_observation = source == "startup" and not self.known_blocks
        for _ in range(self.args.max_backfill_blocks):
            if cursor in self.known_blocks:
                break
            try:
                header, error = self._single_rpc("getblockheader", [cursor, True])
            except Exception as exc:
                header = None
                error = {"type": type(exc).__name__, "message": str(exc)}
            if error is not None or not isinstance(header, dict):
                record = self._base_record("block_observation")
                record.update(
                    {
                        "observed_utc": observed_utc,
                        "discovery_utc": discovery_utc if cursor == block_hash else None,
                        "discovery_is_exact": cursor == block_hash and discovery_utc is not None,
                        "source": source if cursor == block_hash else "backfill",
                        "block_hash": cursor,
                        "height": height if cursor == block_hash else None,
                        "previous_block_hash": None,
                        "header": None,
                        "header_error": error
                        or {"message": "getblockheader returned a non-object"},
                        "block_stats": None,
                        "block_stats_error": None,
                    }
                )
                self.store.append("blocks.jsonl", record)
                self.record_error(
                    "block_observer",
                    f"could not fetch header for {cursor}",
                    context={"rpc_error": error},
                )
                break
            chain.append((cursor, header))
            # On a fresh experiment the current tip is the chain anchor.  Its
            # parent predates every sample, so walking thousands of ancestors
            # would add cost without helping any future-outcome join.
            if initial_observation:
                break
            previous = header.get("previousblockhash")
            if not previous:
                break
            cursor = str(previous)
        else:
            self.record_error(
                "block_observer",
                "backfill limit reached before a known ancestor",
                context={"tip_hash": block_hash, "limit": self.args.max_backfill_blocks},
            )
        for candidate_hash, header in reversed(chain):
            is_tip = candidate_hash == block_hash
            self._observe_block(
                candidate_hash,
                header,
                source=source if is_tip else "backfill",
                observed_utc=observed_utc,
                discovery_utc=discovery_utc if is_tip else None,
            )
        event = self._base_record("tip_event")
        event.update(
            {
                "observed_utc": observed_utc,
                "source": source,
                "tip_hash": block_hash,
                "tip_height": height,
                "previous_observed_tip_hash": old_hash,
                "previous_observed_tip_height": old_height,
                "discovery_utc": discovery_utc,
                "discovery_is_exact": discovery_utc is not None,
            }
        )
        self.store.append("blocks.jsonl", event)
        self._set_tip(block_hash, height, discovery_utc)
        self.store.sync()

    def observe_current_tip(self, source: str) -> None:
        response = self.rpc.call("getblockchaininfo", [])
        chain = rpc_value(response)
        if not isinstance(chain, dict):
            raise RPCTransportError(f"getblockchaininfo failed: {rpc_error(response)}")
        self.observe_tip(
            str(chain["bestblockhash"]),
            int(chain["blocks"]),
            source=source,
        )

    def _watch_blocks(self) -> None:
        while not self.stop_event.is_set():
            current_hash, _ = self._tip()
            if current_hash is None:
                self.stop_event.wait(0.2)
                continue
            started_utc = utc_now()
            started = time.monotonic()
            try:
                response = self.block_rpc.call(
                    "waitfornewblock", [int(self.args.block_wait_timeout), current_hash]
                )
                received_utc = utc_now()
                result = rpc_value(response)
                error = rpc_error(response)
                self.block_queue.put(
                    {
                        "result": result,
                        "error": error,
                        "request_started_utc": started_utc,
                        "response_received_utc": received_utc,
                        "latency_ms": round((time.monotonic() - started) * 1000, 3),
                        "waited_from_tip": current_hash,
                    }
                )
                if isinstance(result, dict) and str(result.get("hash")) != current_hash:
                    # Do not spin: until the main thread has durably recorded
                    # this tip, another wait using the old hash returns at once.
                    while not self.stop_event.is_set() and self._tip()[0] == current_hash:
                        self.stop_event.wait(0.05)
            except Exception as exc:  # keep the sampling loop alive across restarts
                self.block_queue.put(
                    {
                        "result": None,
                        "error": {"type": type(exc).__name__, "message": str(exc)},
                        "request_started_utc": started_utc,
                        "response_received_utc": utc_now(),
                        "latency_ms": round((time.monotonic() - started) * 1000, 3),
                        "waited_from_tip": current_hash,
                    }
                )
                self.stop_event.wait(min(1.0, self.args.interval))

    def start_block_watcher(self) -> None:
        if self.args.no_block_watcher or self.args.once:
            return
        self.block_thread = threading.Thread(
            target=self._watch_blocks, name="fee-study-block-watcher", daemon=True
        )
        self.block_thread.start()

    def _node_calls(self) -> tuple[tuple[str, str, list[Any]], ...]:
        return (
            ("node:chain", "getblockchaininfo", []),
            ("node:mempool", "getmempoolinfo", []),
            ("node:chainstates", "getchainstates", []),
            ("node:network", "getnetworkinfo", []),
            ("node:uptime", "uptime", []),
        )

    def collect_batch(self, trigger: str, scheduled_utc: str) -> None:
        sequence = self.batch_sequence
        self.batch_sequence += 1
        batch_id = str(uuid.uuid4())
        combinations = [
            (mode, target) for mode in self.args.modes for target in self.args.targets
        ]
        rotation = sequence % len(combinations)
        combinations = combinations[rotation:] + combinations[:rotation]
        estimate_meta: dict[str, dict[str, Any]] = {}
        estimate_calls: list[tuple[str, str, list[Any]]] = []
        for request_order, (mode, target) in enumerate(combinations):
            sample_id = str(uuid.uuid4())
            request_id = f"estimate:{sample_id}"
            params = [
                target,
                mode,
                {"verbosity": 3, "fee_rate_estimator": "none"},
            ]
            estimate_meta[request_id] = {
                "sample_id": sample_id,
                "request_order": request_order,
                "mode": mode,
                "requested_target": target,
                "rpc_params": params,
            }
            estimate_calls.append((request_id, "estimatesmartfee", params))

        provider_futures: list[concurrent.futures.Future[dict[str, Any]]] = []
        provider_executor: concurrent.futures.ThreadPoolExecutor | None = None
        now = time.monotonic()
        if self.args.provider and now >= self.next_provider_at:
            self.next_provider_at = now + self.args.provider_interval
            provider_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=min(8, len(self.args.provider)), thread_name_prefix="fee-provider"
            )
            for provider in self.args.provider:
                provider_futures.append(
                    provider_executor.submit(
                        fetch_provider,
                        provider,
                        experiment_id=self.experiment_id,
                        run_id=self.run_id,
                        batch_id=batch_id,
                        scheduled_utc=scheduled_utc,
                        timeout=self.args.provider_timeout,
                        max_bytes=self.args.provider_max_bytes,
                        ca_file=self.args.provider_ca_file,
                    )
                )

        request_started_utc = utc_now()
        try:
            scheduled_epoch = dt.datetime.fromisoformat(
                scheduled_utc.replace("Z", "+00:00")
            ).timestamp()
            schedule_lag_ms: float | None = round(
                (time.time() - scheduled_epoch) * 1000, 3
            )
        except ValueError:
            schedule_lag_ms = None
        started = time.monotonic()
        responses: dict[str, dict[str, Any]] = {}
        transport_error: dict[str, Any] | None = None
        try:
            responses = self.rpc.batch((*estimate_calls, *self._node_calls()))
        except Exception as exc:
            transport_error = {"type": type(exc).__name__, "message": str(exc)}
            self.record_error(
                "sample_batch",
                str(exc),
                context={"batch_id": batch_id, "batch_sequence": sequence},
            )
        response_received_utc = utc_now()
        latency_ms = round((time.monotonic() - started) * 1000, 3)
        for request_id, metadata in estimate_meta.items():
            response = responses.get(request_id)
            result = rpc_value(response)
            result_map = result if isinstance(result, dict) else {}
            diagnostics = result_map.get("diagnostics")
            diagnostics = diagnostics if isinstance(diagnostics, dict) else {}
            diagnostic_height = diagnostics.get("tip_height_before")
            if isinstance(diagnostic_height, int):
                self.last_sample_tip_height = diagnostic_height
            seen_hash, seen_utc = self._tip_discovery()
            result_tip = diagnostics.get("tip_hash_before")
            seconds_since_tip_seen: float | None = None
            if seen_utc is not None and seen_hash == result_tip:
                try:
                    seen_time = dt.datetime.fromisoformat(seen_utc.replace("Z", "+00:00"))
                    response_time = dt.datetime.fromisoformat(
                        response_received_utc.replace("Z", "+00:00")
                    )
                    seconds_since_tip_seen = max(
                        0.0, (response_time - seen_time).total_seconds()
                    )
                except ValueError:
                    pass
            record = self._base_record("fee_estimate")
            record.update(
                {
                    "batch_id": batch_id,
                    "sample_id": metadata["sample_id"],
                    "batch_sequence": sequence,
                    "request_order": metadata["request_order"],
                    "trigger": trigger,
                    "scheduled_utc": scheduled_utc,
                    "request_started_utc": request_started_utc,
                    "response_received_utc": response_received_utc,
                    "rpc_latency_ms": latency_ms,
                    "schedule_lag_ms": schedule_lag_ms,
                    "seconds_since_tip_seen": seconds_since_tip_seen,
                    "mode": metadata["mode"],
                    "requested_target": metadata["requested_target"],
                    "rpc_params": metadata["rpc_params"],
                    "result": result,
                    "rpc_error": transport_error or rpc_error(response),
                }
            )
            self.store.append("estimates.jsonl", record)

        node_record = self._base_record("node_sample")
        node_record.update(
            {
                "batch_id": batch_id,
                "batch_sequence": sequence,
                "trigger": trigger,
                "scheduled_utc": scheduled_utc,
                "request_started_utc": request_started_utc,
                "response_received_utc": response_received_utc,
                "rpc_latency_ms": latency_ms,
                "schedule_lag_ms": schedule_lag_ms,
                "transport_error": transport_error,
                "rpc": {
                    name.removeprefix("node:"): {
                        "result": rpc_value(responses.get(name)),
                        "error": rpc_error(responses.get(name))
                        if transport_error is None
                        else transport_error,
                    }
                    for name, _, _ in self._node_calls()
                },
            }
        )
        self.store.append("node_samples.jsonl", node_record)

        for future in provider_futures:
            try:
                self.store.append("provider_samples.jsonl", future.result())
            except Exception as exc:
                self.record_error(
                    "provider",
                    str(exc),
                    context={"batch_id": batch_id},
                )
        if provider_executor is not None:
            provider_executor.shutdown(wait=True)
        self.store.sync()
        self._write_state("sampling")
        valid_count = sum(
            1
            for response in responses.values()
            if response.get("error") is None and response.get("result") is not None
        )
        print(
            f"{response_received_utc} batch={sequence} trigger={trigger} "
            f"estimates={len(estimate_meta)} rpc_results={valid_count}",
            flush=True,
        )

    def drain_block_events(self, *, sampling: bool) -> bool:
        saw_new_tip = False
        while True:
            try:
                event = self.block_queue.get_nowait()
            except queue.Empty:
                break
            if event.get("error") is not None:
                self.record_error("block_watcher", "waitfornewblock failed", context=event)
                continue
            result = event.get("result")
            if not isinstance(result, dict) or "hash" not in result or "height" not in result:
                self.record_error(
                    "block_watcher", "waitfornewblock returned an invalid result", context=event
                )
                continue
            current_hash, _ = self._tip()
            returned_hash = str(result["hash"])
            if returned_hash == current_hash:
                continue  # normal wait timeout
            self.observe_tip(
                returned_hash,
                int(result["height"]),
                source="waitfornewblock",
                observed_utc=str(event["response_received_utc"]),
                discovery_utc=str(event["response_received_utc"]),
            )
            saw_new_tip = True
        return saw_new_tip and sampling and self.args.sample_on_block

    def run(self) -> None:
        preflight = self.preflight()
        if not self.args.resume:
            self.sample_deadline_epoch = time.time() + self.args.sample_duration
        self._write_manifest(preflight)
        self.write_preflight_node_sample(preflight)
        self.observe_current_tip("startup")
        self._write_state("starting")
        self.start_block_watcher()

        started = time.monotonic()
        started_epoch = time.time()
        sample_deadline = started + max(0.0, self.sample_deadline_epoch - time.time())
        # Both deadlines are absolute experiment deadlines. In particular, a
        # restart during the outcome tail must not silently start a fresh full
        # wall-clock tail and change the experiment definition.
        outcome_deadline_epoch = self.sample_deadline_epoch + self.args.outcome_tail
        outcome_deadline = started + max(0.0, outcome_deadline_epoch - time.time())
        next_sample = started
        sampled_once = False
        sampling_ended_recorded = False
        terminal_phase = "interrupted"
        try:
            while not self.stop_event.is_set():
                now = time.monotonic()
                sampling = self.args.once and not sampled_once or (
                    not self.args.once and now < sample_deadline
                )
                sample_for_block = self.drain_block_events(sampling=sampling)
                now = time.monotonic()
                if sample_for_block:
                    self.collect_batch("new_block", utc_now())
                    sampled_once = True
                    now = time.monotonic()
                if sampling and now >= next_sample:
                    scheduled_utc = utc_from_epoch(
                        started_epoch + (next_sample - started)
                    )
                    self.collect_batch("interval", scheduled_utc)
                    sampled_once = True
                    if self.args.once:
                        break
                    next_sample += self.args.interval
                    if next_sample <= time.monotonic():
                        skipped = int((time.monotonic() - next_sample) // self.args.interval) + 1
                        next_sample += skipped * self.args.interval
                        self.record_error(
                            "scheduler",
                            f"skipped {skipped} interval(s) because collection overran",
                        )
                now = time.monotonic()
                if not self.args.once and now >= sample_deadline:
                    if not sampling_ended_recorded:
                        _, tail_start_height = self._tip()
                        if self.last_sample_tip_height is not None:
                            tail_start_height = max(
                                tail_start_height
                                if tail_start_height is not None
                                else self.last_sample_tip_height,
                                self.last_sample_tip_height,
                            )
                        if (
                            self.outcome_required_height is None
                            and tail_start_height is not None
                            and self.args.outcome_tail_blocks
                        ):
                            self.outcome_required_height = (
                                tail_start_height + self.args.outcome_tail_blocks
                            )
                        self._write_state("outcome_tail")
                        sampling_ended_recorded = True
                        print(
                            f"{utc_now()} estimate/provider sampling complete; observing blocks "
                            f"for at least {self.args.outcome_tail:g} more seconds"
                            + (
                                f" and through height {self.outcome_required_height}"
                                if self.outcome_required_height is not None
                                else ""
                            ),
                            flush=True,
                        )
                    _, current_height = self._tip()
                    block_tail_complete = (
                        self.outcome_required_height is None
                        or (
                            current_height is not None
                            and current_height >= self.outcome_required_height
                        )
                    )
                    if now >= outcome_deadline and block_tail_complete:
                        break
                if not sampling:
                    wake_at = (
                        outcome_deadline
                        if time.monotonic() < outcome_deadline
                        else time.monotonic() + 1.0
                    )
                else:
                    wake_at = min(next_sample, sample_deadline)
                self.stop_event.wait(max(0.05, min(1.0, wake_at - time.monotonic())))
            if not self.stop_event.is_set():
                terminal_phase = "complete"
        except Exception as exc:
            terminal_phase = "failed"
            self.record_error("run", str(exc), fatal=True)
            self.store.sync()
            raise
        finally:
            self.stop_event.set()
            if self.block_thread is not None:
                self.block_thread.join(timeout=2.0)
            if self.block_thread is None or not self.block_thread.is_alive():
                self.block_rpc.close()
            try:
                self.observe_current_tip("shutdown")
            except Exception as exc:
                self.record_error("shutdown_tip", str(exc))
            self._write_state(terminal_phase)
            self.store.close()
            self.rpc.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Poll verbosity-3 estimatesmartfee diagnostics and preserve block outcomes "
            "for offline comparison."
        )
    )
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    parser.add_argument(
        "--datadir",
        type=pathlib.Path,
        help="Bitcoin Core data directory; used to infer the mainnet RPC cookie",
    )
    parser.add_argument(
        "--cookie",
        "--rpc-cookie",
        type=pathlib.Path,
        default=None,
        help="RPC cookie path (default: DATADIR/.cookie or ~/.bitcoin/.cookie)",
    )
    parser.add_argument("--rpc-user", default=os.environ.get("BITCOIN_RPC_USER"))
    parser.add_argument("--rpc-password", default=os.environ.get("BITCOIN_RPC_PASSWORD"))
    parser.add_argument("--rpc-timeout", type=float, default=30.0)
    parser.add_argument("--targets", type=parse_targets, default=DEFAULT_TARGETS)
    parser.add_argument("--modes", type=parse_modes, default=DEFAULT_MODES)
    parser.add_argument("--interval", type=parse_duration, default=30.0)
    parser.add_argument(
        "--sample-duration", "--duration", type=parse_duration, default=24 * 3600.0
    )
    parser.add_argument(
        "--outcome-tail",
        type=parse_duration,
        default=36 * 3600.0,
        help="continue recording blocks after sampling stops (default: 36h)",
    )
    parser.add_argument(
        "--outcome-tail-blocks",
        type=int,
        default=0,
        help=(
            "after sampling, also wait for this many new tip heights; use the maximum "
            "target to guarantee maturity absent a deep reorg"
        ),
    )
    parser.add_argument(
        "--provider",
        action="append",
        type=parse_provider,
        default=[],
        metavar="NAME=URL",
        help="capture a public JSON fee API; repeat for multiple providers",
    )
    parser.add_argument("--provider-interval", type=parse_duration, default=60.0)
    parser.add_argument("--provider-timeout", type=float, default=15.0)
    parser.add_argument("--provider-max-bytes", type=int, default=2_000_000)
    parser.add_argument(
        "--provider-ca-file",
        type=pathlib.Path,
        help="optional PEM CA bundle for HTTPS provider verification",
    )
    parser.add_argument("--block-wait-timeout", type=int, default=15_000)
    parser.add_argument("--max-backfill-blocks", type=int, default=2016)
    parser.add_argument(
        "--sample-on-block",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="also sample immediately after each observed new tip (default: enabled)",
    )
    parser.add_argument("--no-block-watcher", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--once", action="store_true", help="collect one batch and exit")
    parser.add_argument(
        "--expected-chain",
        choices=("main", "test", "testnet4", "signet", "regtest"),
        default="main",
    )
    parser.add_argument(
        "--require-pruned",
        action="store_true",
        help="abort unless getblockchaininfo reports pruned=true",
    )
    parser.add_argument(
        "--allow-non-mainnet",
        action="store_true",
        help="allow regtest/testnet/signet (intended only for script testing)",
    )
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if (args.rpc_user is None) != (args.rpc_password is None):
        parser.error("--rpc-user and --rpc-password must be supplied together")
    if args.rpc_user is not None:
        args.cookie = None
    elif args.cookie is None:
        data_dir = (
            args.datadir.expanduser()
            if args.datadir is not None
            else default_bitcoin_datadir()
        )
        chain_subdirectory = {
            "main": "",
            "test": "testnet3",
            "testnet4": "testnet4",
            "signet": "signet",
            "regtest": "regtest",
        }[args.expected_chain]
        args.cookie = data_dir / chain_subdirectory / ".cookie"
    if args.interval <= 0:
        parser.error("--interval must be greater than zero")
    if args.sample_duration <= 0 and not args.once:
        parser.error("--sample-duration must be greater than zero")
    if args.provider_interval <= 0:
        parser.error("--provider-interval must be greater than zero")
    if (
        not math.isfinite(args.rpc_timeout)
        or not math.isfinite(args.provider_timeout)
        or args.rpc_timeout <= 0
        or args.provider_timeout <= 0
    ):
        parser.error("timeouts must be finite and greater than zero")
    if args.block_wait_timeout <= 0:
        parser.error("--block-wait-timeout must be greater than zero")
    if args.max_backfill_blocks <= 0:
        parser.error("--max-backfill-blocks must be greater than zero")
    if args.outcome_tail_blocks < 0:
        parser.error("--outcome-tail-blocks cannot be negative")
    if args.provider_max_bytes <= 0:
        parser.error("--provider-max-bytes must be greater than zero")
    if args.provider_ca_file is not None and not args.provider_ca_file.is_file():
        parser.error("--provider-ca-file must name a readable PEM file")
    if (
        args.no_block_watcher
        and not args.once
        and (args.outcome_tail > 0 or args.outcome_tail_blocks > 0)
    ):
        parser.error("an outcome tail requires the block watcher")
    provider_names = [provider.name for provider in args.provider]
    if len(provider_names) != len(set(provider_names)):
        parser.error("provider names must be unique")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    validate_args(parser, args)
    collector: Collector | None = None

    def stop(_signum: int, _frame: Any) -> None:
        if collector is not None:
            collector.stop_event.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        collector = Collector(args)
        collector.run()
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        if collector is not None:
            try:
                collector.record_error("fatal", str(exc), fatal=True)
                collector.store.close()
            except Exception:
                pass
        print(f"fatal: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
