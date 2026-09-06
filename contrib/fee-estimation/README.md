# Mainnet fee-estimation experiment

These scripts collect the verbose `estimatesmartfee` diagnostics added on the [`rpc-fee-estimator-diagnostics` Bitcoin Core branch](https://github.com/musaHaruna/bitcoin/tree/rpc-fee-estimator-diagnostics)
and evaluate them after the target blocks have been mined.

The instrumented Bitcoin Core code and the experiment tools are distributed as two independent repositories:

* `https://github.com/musaHaruna/bitcoin.git` contains the modified Bitcoin Core node and RPC implementation.
* `https://github.com/musaHaruna/fee-estimation.git` contains this README and the collector, analyzer, requirements, and focused script tests.

Clone the tools repository into the Bitcoin Core checkout at
`contrib/fee-estimation`. All commands in this guide assume that layout:

```text
bitcoin-fee-estimation/
|-- build/
|-- contrib/
|   `-- fee-estimation/
|       |-- README.md
|       |-- collect_fee_estimates.py
|       |-- analyze_fee_estimates.py
|       |-- requirements.txt
|       `-- test_fee_estimation_scripts.py
`-- src/
```

The two main tools are [`collect_fee_estimates.py`](collect_fee_estimates.py)
and [`analyze_fee_estimates.py`](analyze_fee_estimates.py). The exploratory
results from runs 001 and 002 are documented in
[`reports/mainnet-runs-001-002.md`](reports/mainnet-runs-001-002.md); a shorter
GitHub-ready version is in
[`reports/github-comment-draft.md`](reports/github-comment-draft.md).

## Experimental timeline

Treat these as separate stages:

1. Synchronize headers, load an AssumeUTXO snapshot, and let the snapshot
   chainstate catch up to the network tip.
2. Warm both estimators. A new mempool estimator needs six newly observed
   blocks before its health window is full. A new block-policy estimator needs
   much more history: without a previously populated estimator file, target
   144 cannot become usable until at least roughly 288 blocks have been
   observed, and more data is preferable.
3. Collect estimates for 24 hours.
4. Stop creating estimates, but keep the node and collector running for an
   outcome tail. In the command below, `--outcome-tail-blocks 144` ensures an
   estimate made just before the 24-hour deadline can mature.
5. Analyze only after the tail finishes. Incomplete outcomes remain in the raw
   data and are excluded from outcome metrics.

AssumeUTXO accelerates chainstate availability. It does **not** import fee
estimator history, populate this node's mempool, or eliminate estimator warmup.
A 24-hour run started from a fresh data directory is therefore a pipeline test,
not a sound long-target benchmark.

## 1. Build this branch

Follow the platform-specific build guide in `doc/`. A minimal Unix build is:

```sh
git clone https://github.com/musaHaruna/bitcoin.git
cd bitcoin
git checkout --detach 11ef080faf3cf7d9c139cca513a8399a12b30f46
cmake -B build -DBUILD_GUI=OFF
cmake --build build -j 4
./build/bin/bitcoind -version
```

The detached checkout pins the exact diagnostic revision used for the two
documented mainnet pilot runs. Use the binaries from this build for both the
node and `bitcoin-cli`. A release binary without this branch's verbosity-3 RPC
fields is not compatible with the collector.

Python 3.10 or newer is required. The collector and non-chart analysis use only
the Python standard library. Install Matplotlib in a virtual environment for
PNG charts:

```sh
python3 -m venv .venv-fee-estimation
. .venv-fee-estimation/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r contrib/fee-estimation/requirements.txt
```

The focused script tests need no third-party packages:

```sh
python3 contrib/fee-estimation/test_fee_estimation_scripts.py
```

## 2. Create a dedicated pruned mainnet node

Do not reuse a valuable wallet data directory for an experimental build. Pick
an absolute data directory and create `bitcoin.conf` inside it:

```sh
export FEE_NODE_DATADIR="$PWD/fee-estimation-mainnet"
mkdir -p "$FEE_NODE_DATADIR"
```

Suggested `bitcoin.conf`:

```ini
server=1
prune=10000
blocksonly=0
persistmempool=1
maxmempool=300
debug=estimatefee
logtimemicros=1
```

`prune=10000` is a 10,000 MiB block-file target, not a total disk-space cap.
AssumeUTXO temporarily uses two chainstate directories, and the snapshot file
itself also needs space. Bitcoin Core permits a smaller prune target (the
AssumeUTXO path uses at least 1,100 MiB), but extra headroom makes interruption
and outcome backfill safer. Do not enable `txindex`; it is incompatible with
pruning. More `dbcache` can speed background validation if the machine has
spare RAM.

Keep the policy configuration fixed for the whole experiment. In particular,
changing `maxmempool`, relay fee settings, mempool expiry, peer connectivity,
or `blocksonly` changes the local mempool and therefore the result being
measured. Make sure the system clock is synchronized. Good transaction relay
connectivity matters because the health check measures how much mined
transaction weight this node saw in its own mempool.

Start the node and wait for RPC readiness:

```sh
./build/bin/bitcoind -datadir="$FEE_NODE_DATADIR" -daemon
./build/bin/bitcoin-cli -datadir="$FEE_NODE_DATADIR" -rpcwait getblockchaininfo
```

RPC is intended to remain local. The commands below use Bitcoin Core's cookie
authentication; do not expose port 8332 to the internet.

## 3. Load an AssumeUTXO snapshot

Read `doc/assumeutxo.md` first. Bitcoin Core does not designate a canonical
snapshot download source. Obtain a mainnet snapshot from a source you trust,
record the source and its published file checksum, and use a height recognized
by this exact build. At the time of this branch, mainnet entries exist at
heights 840000, 880000, 910000, and 935000 in
`src/kernel/chainparams.cpp`.

First let the node receive headers through the snapshot height. Check progress
with:

```sh
./build/bin/bitcoin-cli -datadir="$FEE_NODE_DATADIR" getchainstates
```

When the reported `headers` value is at least the chosen snapshot height, load
the snapshot using an absolute path:

```sh
export FEE_SNAPSHOT_PATH=/absolute/path/to/utxo-snapshot.dat
./build/bin/bitcoin-cli -datadir="$FEE_NODE_DATADIR" \
  -rpcclienttimeout=0 loadtxoutset "$FEE_SNAPSHOT_PATH"
```

`loadtxoutset` verifies the snapshot contents against the hash committed in the
chain parameters. It then activates the snapshot chainstate while normal
validation continues from genesis in the background. Monitor both with:

```sh
./build/bin/bitcoin-cli -datadir="$FEE_NODE_DATADIR" getchainstates
./build/bin/bitcoin-cli -datadir="$FEE_NODE_DATADIR" getblockchaininfo
```

Do not start the measured window until the active snapshot chainstate is at the
network tip and `initialblockdownload` is false. The background chainstate may
still be validating; `getchainstates` will show it separately. Keep that fact
with the run metadata. After `loadtxoutset` succeeds, the downloaded snapshot
file is no longer needed by Bitcoin Core, although retaining its checksum and
provenance is useful for reproducibility.

## 4. Warm up and preflight verbosity 3

Leave the node online at the tip so it learns live mempool arrivals and block
confirmations. On a fresh estimator, wait for at least six naturally arriving
blocks before expecting `mempool_health.status` to become `healthy`. Longer
block-policy targets need days rather than hours. Restarts preserve estimator
state when shutdown is clean, but do not assume that a successful RPC alone
means every target is warm.

Run the exact RPC shape required by the collector:

```sh
./build/bin/bitcoin-cli -datadir="$FEE_NODE_DATADIR" \
  estimatesmartfee 2 economical \
  '{"fee_rate_estimator":"none","verbosity":3}'
```

The response must contain `diagnostics`, including `block_policy`,
`mempool_policy`, `selection`, `fee_floor`, `mempool_health`, and the
tip/mempool consistency markers. `mempool_template` is present only when that
estimator succeeds. During warmup it is normal for an estimator to report an
error and for `selection.success` to be false. A missing `diagnostics` object
means the wrong binary is running.

Here `fee_rate_estimator="none"` means "ask the manager to combine both
estimators"; it does not disable estimation. Verbosity 3 exposes the decision
in stages:

1. `block_policy` and `mempool_policy` contain each independent result before
   the RPC fee floor, including exact fee-in-satoshis and virtual-size
   components. The losing raw result is retained.
2. `mempool_template.p50` is the conservative candidate and `p75` is the
   economical candidate.
3. `selection` says whether both estimators succeeded and records
   `block_policy_lower`, `mempool_policy_lower`, `block_policy_tie`, or the
   relevant error. The combined manager chooses the lower raw fee rate; a tie
   is attributed to block policy.
4. `fee_floor.effective` is the higher of the dynamic mempool minimum and the
   minimum relay rate. It is applied after manager selection. Therefore
   `selection.feerate_before_rpc_floor` and the top-level returned `feerate`
   can differ.
5. `mempool_health` explains whether the rolling six-block window is healthy,
   lacks data, or has low coverage. `snapshot_consistent` is true only if the
   active tip and mempool sequence stayed fixed while diagnostics were read.

The returned target also matters. A block-policy result may be clamped to a
different usable target, while a mempool-policy result currently reports target
2. Outcome analysis must join on the returned target for each output, not only
the requested target.

Use a one-shot collector preflight before committing to a long run:

```sh
python3 contrib/fee-estimation/collect_fee_estimates.py \
  --output-dir fee-preflight \
  --datadir "$FEE_NODE_DATADIR" \
  --expected-chain main \
  --require-pruned \
  --once --no-block-watcher
```

Remove or choose a new preflight output directory before the real run. A new
run intentionally refuses to write into a populated experiment directory.

## 5. Run a 24-hour collection

The default targets are `1,2,3,6,12,24,48,72,144`; the default modes are
`economical,conservative`; and the default interval is 30 seconds. New blocks
also trigger an immediate estimate by default so the transition around a block
is not missed.

```sh
export FEE_RUN_DIR="$PWD/fee-run-001"
python3 contrib/fee-estimation/collect_fee_estimates.py \
  --output-dir "$FEE_RUN_DIR" \
  --datadir "$FEE_NODE_DATADIR" \
  --rpc-url http://127.0.0.1:8332 \
  --expected-chain main \
  --require-pruned \
  --interval 30s \
  --duration 24h \
  --targets 1,2,3,6,12,24,48,72,144 \
  --modes economical,conservative \
  --outcome-tail 0s \
  --outcome-tail-blocks 144
```

`--duration` controls the estimate/provider sampling window. After it expires,
the collector records blocks until 144 additional blocks have arrived. This is
better than a fixed 24- or 36-hour delay: Bitcoin block discovery is random,
whereas target 144 specifically needs the 144th block after the last anchor.
Keep both the collector and node running throughout the tail. When both
`--outcome-tail` and `--outcome-tail-blocks` are nonzero, both requirements
must be satisfied. The default wall-clock tail is 36 hours, so the explicit
`--outcome-tail 0s` above makes the 144-block condition the only condition.

The collector can infer the mainnet cookie from `--datadir`. Alternatively pass
`--rpc-cookie /absolute/path/to/.cookie`, or use `--rpc-user` and
`--rpc-password`. Cookie authentication is preferable on the same machine.

Use a terminal multiplexer or a service manager for an unattended run. If
redirecting output yourself, keep the process ID outside the append-only data
files:

```sh
python3 contrib/fee-estimation/collect_fee_estimates.py \
  --output-dir "$FEE_RUN_DIR" \
  --datadir "$FEE_NODE_DATADIR" \
  --expected-chain main --require-pruned \
  --duration 24h --outcome-tail 0s --outcome-tail-blocks 144 \
  >"$FEE_RUN_DIR.collector.log" 2>&1 &
export FEE_COLLECTOR_PID=$!
```

Inspect `run_state.json`, the collector log, and `errors.jsonl` while it runs.
Do not edit or sort a live JSONL stream.

### Public providers

Public fee APIs normally do not provide a complete historical series with the
same timestamps and target semantics. Polling them concurrently is the fairest
comparison. Add a provider once per URL:

```sh
python3 contrib/fee-estimation/collect_fee_estimates.py \
  --output-dir "$FEE_RUN_DIR" \
  --datadir "$FEE_NODE_DATADIR" \
  --expected-chain main --require-pruned \
  --duration 24h --outcome-tail 0s --outcome-tail-blocks 144 \
  --provider-interval 60s \
  --provider 'blockstream=https://blockstream.info/api/fee-estimates' \
  --provider 'mempool_space=https://mempool.space/api/v1/fees/recommended'
```

Repeat `--provider NAME=URL` for more endpoints. Provider failures are retained
in `provider_samples.jsonl` and do not stop the Core experiment. The collector
stores the raw response and fetch time: provider
fields such as "fastest", "half hour", and "economy" are service-specific
products, not exact aliases for Core confirmation targets. Compare a field only
after documenting its intended target, units, rounding, cache behavior, and
whether the response came from the same network.

The analyzer recognizes Blockstream-style numeric target keys directly. It
maps mempool.space's `fastestFee`, `halfHourFee`, and `hourFee` to the customary
1-, 3-, and 6-block comparison labels; it intentionally does not invent block
targets for `economyFee` or `minimumFee`. It also recognizes Augur's nested
target/probability response when you run the Augur reference service yourself.

Do not send RPC credentials to a provider URL. Public APIs can rate-limit,
cache, change schema, or disappear, so they should be treated as optional
benchmarks rather than ground truth.

HTTPS verification is never disabled. If a Python installation cannot find
the operating system CA certificates, fix that installation or pass a trusted
PEM bundle with `--provider-ca-file /absolute/path/to/ca-bundle.pem`; do not
work around the error with an unverified connection.

## 6. Stop or resume safely

Press Ctrl-C once, or send `SIGINT`/`SIGTERM`, to stop the collector. It flushes
its files, records a final tip event, and marks the run interrupted. Avoid
`SIGKILL`.

Resume with the same output directory and configuration:

```sh
python3 contrib/fee-estimation/collect_fee_estimates.py \
  --output-dir "$FEE_RUN_DIR" \
  --datadir "$FEE_NODE_DATADIR" \
  --expected-chain main --require-pruned \
  --resume
```

Resume uses `manifest.json` and `run_state.json`; it preserves the experiment
ID, original sampling deadline, sequence counter, configuration, and already
recorded rows while assigning the resumed process a new run ID. If the node was
offline, the gap and any RPC/backfill errors
remain observable. A very long outage can exceed retained pruned block data;
do not silently discard such a gap.

After collection and its outcome tail finish, stop the node cleanly if desired:

```sh
./build/bin/bitcoin-cli -datadir="$FEE_NODE_DATADIR" stop
```

## Raw collection files

Each experiment directory contains:

| File | Purpose |
| --- | --- |
| `manifest.json` | Immutable experiment ID, schema/configuration, node identity, targets, modes, and providers. |
| `run_state.json` | Mutable phase, deadlines, tips, progress counters, and completion/interruption state. |
| `estimates.jsonl` | One observation per time, mode, and target, including both raw estimators, combined selection, final fee floor, errors, health, and consistency markers. |
| `node_samples.jsonl` | Tip, sync, peer, mempool size/weight/usage, fee floors, and policy context sampled from the node. |
| `blocks.jsonl` | Canonical/reorg-aware block observations and realized transaction fee-rate summaries used for outcomes. |
| `provider_samples.jsonl` | Timestamped raw public-provider responses or normalized numeric fields. |
| `errors.jsonl` | Structured RPC, HTTP, decoding, backfill, and loop errors. |

The raw estimator values are retained even when the other estimator wins or a
fee floor changes the RPC return. This permits four separate comparisons:
block policy, mempool policy, the manager-selected raw estimate, and the final
returned estimate. Do not reconstruct the losing estimate from the winner.
`discovery_utc` is marked exact only when `waitfornewblock` observed the tip;
startup and outage-backfill observation times are retained but are not falsely
reported as block-discovery times.

`node_samples.jsonl` records the current mempool's aggregate size, bytes,
memory use, configured capacity, total fee, dynamic/effective floors, sequence
context, and the estimator's representativeness window. It intentionally does
not dump `getrawmempool true` every 30 seconds: that would create a very large,
slow dataset and is not needed for the target-block comparison here. A future
counterfactual block-template replay is a separate experiment and should use a
lower-cadence transaction/package snapshot stream or an estimator such as a
locally run Augur service.

## 7. Analyze the completed run

With Matplotlib installed, run:

```sh
python3 contrib/fee-estimation/analyze_fee_estimates.py \
  --input-dir "$FEE_RUN_DIR" \
  --output-dir "$FEE_RUN_DIR/analysis" \
  --charts on
```

For a standard-library-only analysis:

```sh
python3 contrib/fee-estimation/analyze_fee_estimates.py \
  "$FEE_RUN_DIR" --no-charts
```

By default, warmup rows, internally inconsistent RPC snapshots, and immature
outcomes are not used for accuracy metrics. Do not use
`--include-warmup` or `--include-inconsistent` for headline results; those
options are for diagnosing why data was rejected. Use `--strict-input` in a final
reproducible run to turn malformed/incompatible input into a failure.

The analysis directory contains:

* `normalized_estimates.csv`: wide per-sample records with both estimator raw values,
  selection reason, selected raw value, fee floor, and returned value.
* `scores.csv`: long, outcome-joined observations for block policy, mempool
  policy, selected raw, and returned-after-floor rates. Requested-target and
  native-returned-target scopes are separate rows; target-block weight,
  approximate fullness, transaction count, total fee, timestamps, average,
  and p10-p90 fee-rate context are retained alongside each score.
* `canonical_blocks.csv` and `node_samples.csv`: flattened chain and mempool
  context.
* `summary_by_target.csv`, `availability.csv`, `selection_summary.csv`, and
  `pairwise_comparison.csv`: counts, availability, selection/floor behavior,
  errors, and estimator comparisons by mode, target, and evaluation scope.
* `provider_estimates.csv` and `provider_metrics.csv`, when compatible provider
  observations exist.
* `tip_events.csv`, `data_quality.csv`, `analysis_report.md`, and
  `analysis_manifest.json`: chain history, exclusions, readable findings, and
  exact analysis configuration.
* `charts/*.png`, when chart generation is enabled and Matplotlib is available.

Start with `data_quality.csv`, then `availability.csv`. Accuracy percentages
are misleading if most rows were warm, inconsistent, unavailable, or still
waiting for a target block. Next inspect `selection_summary.csv` to see how often each
raw estimator won and how often the RPC floor changed that choice. Finally use
`summary_by_target.csv`, `pairwise_comparison.csv`, and the charts to compare signed error,
overestimation, underestimation, and absolute error for each output.

Do not confuse the percentile families. `mempool_template.p50` and `p75` are
inputs produced by the new mempool estimator. Block `p10,p25,p50,p75,p90`
values come from `getblockstats` and describe realized non-coinbase
transaction fee rates by weight. Columns such as `estimate_p05` and
`estimate_p95` in a summary describe how the collected estimates varied across
time; they are aggregate reporting quantiles, not extra internal estimator
outputs.

The template and block percentile labels also have opposite traversal
directions. The template is accumulated from highest mining score downward, so
template `p75 <= p50`; `getblockstats` accumulates mined fee rates low-to-high,
so block `p75 >= p50`. Do not compare them label-for-label. Block percentile
thresholds are integer sat/vB, while verbosity-3 estimator fractions can be
sub-sat/vB; equality and category counts near a boundary therefore inherit
1 sat/vB outcome quantization.

For an estimate `q`, the headline target-block rule is: `q < p10` is an
underestimate, `p10 <= q <= p75` is within the observed band, and `q > p75` is
an overestimate. Point bias is `q - p50`; the analyzer also reports absolute
error, percentage error when p50 is positive, estimate/p50 ratio, log2 ratio,
absolute log2 error, and bias versus `avgfeerate`. The separately named
`horizon_min_*` columns repeat the comparison against the minimum realized
percentile over blocks 1 through N; they are a sensitivity analysis and are
never mixed into the target-block headline percentages.

Read `evaluation_scope` whenever using `scores.csv`. `requested_target`
evaluates the question the caller asked. `native_target` evaluates the target
the individual estimator actually returned (mempool policy currently returns
2, and block policy may clamp). The native mempool result is identical across
requested targets in one batch, so the analyzer marks repetitions with
`aggregation_duplicate` and excludes those duplicates from aggregate metrics.
`summary_by_target.csv` reports ordinary per-row shares and equal-anchor-tip
shares; the latter prevents unusually long intervals between blocks from
dominating a comparison. Its `interval_*` columns use only interval-triggered
rows, so the extra post-block samples cannot distort that result. Inspect
`schedule_lag_ms` and actual request timestamps before describing those rows as
a fixed cadence: host sleep, node downtime, or a stalled process can create
large gaps even when `--interval 30s` was configured.

## Interpretation caveats

* A 30-second interval creates many rows, not many independent trials. All rows
  sharing an anchor tip often resolve against the same future block. Report
sample counts, unique anchor tips, and block/day coverage; confidence
  intervals should cluster or bootstrap by block or day rather than by row.
* A realized block's median, mean, or fee-rate percentiles are useful proxies,
  not a literal minimum clearing fee. Miners select ancestor packages, blocks
  may not be full, and private, accelerated, out-of-band, or otherwise unseen
  transactions can appear in a block.
* "Would have confirmed" is counterfactual. A stronger future study would save
  enough mempool/package state to replay selection. The files here support
  observational comparison, not proof that a hypothetical transaction would
  have been mined.
* Economical and conservative modes have different intended behavior. Analyze
  them separately. Also separate pre-floor selection from the returned rate;
  otherwise relay/mempool floors can be incorrectly attributed to an
  estimator.
* Reorganizations, node downtime, RPC inconsistency, estimator errors, and
  provider time skew are data-quality events, not zero-fee observations.
* One node observes one peer set and one mempool policy. Repeat longer than one
  day, across weekdays/weekends and ideally across independently connected
  nodes, before generalizing to the Bitcoin network.
