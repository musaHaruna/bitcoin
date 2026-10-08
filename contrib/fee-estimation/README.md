# Fee-estimation experiment

Used these two scripts to collect Bitcoin Core's verbosity-3
`estimatesmartfee` diagnostics and compare each estimate with the blocks that
arrive later.

They write JSONL, CSV, and a short Markdown report. They do **not** download
data from third parties or create charts/graphs. Python 3.10+ is enough; no
extra Python packages are required.

## What You need

* A Bitcoin Core build from the `rpc-fee-estimator-diagnostics` branch. A
  normal release binary does not have the required verbosity-3 fields.
* A mainnet node at the tip, with RPC available locally and cookie
  authentication enabled.
* Enough time for the estimators to warm up. AssumeUTXO speeds up chainstate
  synchronization, but it does not restore the node's mempool or estimator
  history.

## Build and prepare the node

Build the diagnostic branch following Bitcoin Core's normal build guide, then
choose a separate data directory for the experiment:

```sh
export FEE_NODE_DATADIR="$PWD/fee-estimation-mainnet"
mkdir -p "$FEE_NODE_DATADIR"
```

Put a `bitcoin.conf` in that directory. This is a reasonable pruned-node
starting point:

```ini
server=1
prune=10000
persistmempool=1
maxmempool=300
```

Start the node and wait for it to finish initial block download:

```sh
./build/bin/bitcoind -datadir="$FEE_NODE_DATADIR" -daemon
./build/bin/bitcoin-cli -datadir="$FEE_NODE_DATADIR" -rpcwait getblockchaininfo
```

If I use AssumeUTXO, I first wait for headers through the snapshot height,
then load a snapshot whose source and checksum I trust:

```sh
./build/bin/bitcoin-cli -datadir="$FEE_NODE_DATADIR" \
  -rpcclienttimeout=0 loadtxoutset /absolute/path/to/snapshot.dat
```

Before collecting, `getblockchaininfo` should show
`"initialblockdownload": false`. I also leave the node online long enough to
observe live blocks. The mempool estimator needs at least six new blocks to
become healthy; long block-policy targets need more history.

Check that I am using the intended binary:

```sh
./build/bin/bitcoin-cli -datadir="$FEE_NODE_DATADIR" \
  estimatesmartfee 2 economical \
  '{"fee_rate_estimator":"none","verbosity":3}'
```

The result must contain `diagnostics`.

## Collect a run

The collector reads the RPC cookie from `$FEE_NODE_DATADIR/.cookie` and uses
the node's local RPC endpoint. First, I can make one test request:

```sh
python3 contrib/fee-estimation/collect_fee_estimates.py \
  --output-dir fee-preflight \
  --datadir "$FEE_NODE_DATADIR" \
  --once
```

For a full day of estimates, followed by enough blocks to score target 144:

```sh
export FEE_RUN_DIR="$PWD/fee-run-001"
python3 contrib/fee-estimation/collect_fee_estimates.py \
  --output-dir "$FEE_RUN_DIR" \
  --datadir "$FEE_NODE_DATADIR" \
  --duration 24h \
  --outcome-tail 0s \
  --outcome-tail-blocks 144
```

The defaults are 30-second sampling, targets `1,2,3,6,12,24,48,72,144`, and
both economical and conservative modes. After sampling ends, the collector
keeps recording blocks so that the latest estimates can mature. Do not edit
the JSONL files while collection is running.

If collection stops, resume the same run directory:

```sh
python3 contrib/fee-estimation/collect_fee_estimates.py \
  --output-dir "$FEE_RUN_DIR" \
  --datadir "$FEE_NODE_DATADIR" \
  --resume
```

## Analyze a completed run

```sh
python3 contrib/fee-estimation/analyze_fee_estimates.py "$FEE_RUN_DIR"
```

This writes an `analysis/` directory. Start with:

* `analysis_report.md` — short overview in first-person wording.
* `data_quality.csv` — malformed input, inconsistent snapshots, incomplete
  outcomes, and other exclusions.
* `summary_by_target.csv` — accuracy summaries by output, mode, and target.
* `pairwise_comparison.csv` — comparison of the two estimators, selection,
  and final returned rate.
* `scores.csv` — the detailed rows used in the summaries.

By default I exclude warmup estimates, inconsistent snapshots, reorged tips,
and estimates that do not yet have a target-block outcome. I can use
`--include-warmup` or `--include-inconsistent` only when diagnosing those
rows, not for my headline result.

Rates are stored as sat/kvB. Divide by 1,000 to obtain sat/vB. I treat an
estimate below the target block's p10 as low, one from p10 through p75 as
within the observed band, and one above p75 as high. This is an observational
comparison: a block's fee-rate percentiles are useful context, not proof that
an arbitrary transaction at that fee would have confirmed.

## Test the scripts

```sh
python3 contrib/fee-estimation/test_fee_estimation_scripts.py
```
