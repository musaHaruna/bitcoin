// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <coins.h>
#include <consensus/amount.h>
#include <node/coin.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>
#include <validation.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <utility>
#include <vector>

namespace {
// Cycle through five common script types with random data for this experiment.
// The mix of script types on mainnet can be different.
CScript MakeScript(FastRandomContext& rng, size_t index, bool wallet)
{
    const size_t type{index % 5};
    auto payload{rng.randbytes(type < 3 ? 20 : 32)};
    // Give the scripts we search for and the other outputs different last bytes
    // so they cannot match by accident.
    payload.back() = wallet;
    switch (type) {
    case 0: return CScript{} << OP_DUP << OP_HASH160 << payload << OP_EQUALVERIFY << OP_CHECKSIG;
    case 1: return CScript{} << OP_HASH160 << payload << OP_EQUAL;
    case 2:
    case 3: return CScript{} << OP_0 << payload;
    default: return CScript{} << OP_1 << payload;
    }
}

enum class Matches { NONE, FEW, MANY };

void UTXOScan(benchmark::Bench& bench, size_t coin_count, size_t script_count, Matches matches, bool dirty)
{
    // Each case chooses how many UTXOs to create. Setting up the database warms
    // the caches before we start timing.
    const size_t match_count{matches == Matches::FEW ? std::min(coin_count, size_t{10}) :
                             matches == Matches::MANY ? coin_count / 10 : 0};
    const size_t dirty_count{dirty ? std::min(coin_count, size_t{10'000}) : 0};
    auto setup{MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST, {.coins_db_in_memory = false, .setup_net = false})};
    auto& chainstate{setup->m_node.chainman->ActiveChainstate()};
    FastRandomContext script_rng{/*fDeterministic=*/true};
    FastRandomContext coin_rng{/*fDeterministic=*/true};
    std::set<CScript> scripts;
    std::vector<CScript> wallet_scripts;
    for (size_t i{0}; i < script_count; ++i) {
        wallet_scripts.push_back(MakeScript(script_rng, i, /*wallet=*/true));
        scripts.insert(wallet_scripts.back());
    }
    Assert(scripts.size() == script_count);

    std::vector<std::pair<COutPoint, Coin>> dirty_coins;
    {
        LOCK(cs_main);
        auto& cache{chainstate.CoinsTip()};
        for (size_t i{0}; i < coin_count; ++i) {
            const COutPoint outpoint{Txid::FromUint256(coin_rng.rand256()), static_cast<uint32_t>(i % 4)};
            auto script{MakeScript(coin_rng, i, /*wallet=*/false)};
            if (i < match_count) script = wallet_scripts[i % script_count];
            Coin coin{CTxOut{1 + coin_rng.randrange(50 * COIN), std::move(script)},
                      static_cast<int>(1 + i % 900'000), /*coinbase=*/i % 100 == 0};
            if (i < dirty_count) dirty_coins.emplace_back(outpoint, coin);
            cache.AddCoin(outpoint, std::move(coin), /*possible_overwrite=*/false);
            // Flush as we add coins to keep memory use down.
            if ((i + 1) % 16'384 == 0) cache.Flush();
        }
        chainstate.ForceFlushStateToDisk();
    }

    std::map<COutPoint, Coin> found;
    uint256 best_block;
    // Time one full scan, including the flush.
    // Make the coins dirty again before each run so each scan has coins to flush.
    // Clear the previous results before starting the timer.
    bench.batch(coin_count).unit("UTXO").setup([&] {
            found.clear();
            best_block.SetNull();
            LOCK(cs_main);
            for (auto& [outpoint, coin] : dirty_coins) {
                ++coin.out.nValue;
                chainstate.CoinsTip().AddCoin(outpoint, Coin{coin}, /*possible_overwrite=*/true);
            }
        })
        .run([&] {
            Assert(node::FindCoinsByScript(setup->m_node, scripts, found, best_block));
            Assert(found.size() == match_count);
            Assert(!best_block.IsNull());
        });
}
} // namespace

static void UTXOScanNoMatches1Script_10000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 10'000, 1, Matches::NONE, /*dirty=*/false); }
static void UTXOScanNoMatches1000Scripts_10000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 10'000, 1'000, Matches::NONE, /*dirty=*/false); }
static void UTXOScanNoMatches10000Scripts_10000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 10'000, 10'000, Matches::NONE, /*dirty=*/false); }
static void UTXOScanFewMatches_10000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 10'000, 1'000, Matches::FEW, /*dirty=*/false); }
static void UTXOScanManyMatches_10000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 10'000, 1'000, Matches::MANY, /*dirty=*/false); }
static void UTXOScanDirty10000_10000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 10'000, 1'000, Matches::NONE, /*dirty=*/true); }

static void UTXOScanNoMatches1Script_100000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 100'000, 1, Matches::NONE, /*dirty=*/false); }
static void UTXOScanNoMatches1000Scripts_100000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 100'000, 1'000, Matches::NONE, /*dirty=*/false); }
static void UTXOScanNoMatches10000Scripts_100000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 100'000, 10'000, Matches::NONE, /*dirty=*/false); }
static void UTXOScanFewMatches_100000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 100'000, 1'000, Matches::FEW, /*dirty=*/false); }
static void UTXOScanManyMatches_100000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 100'000, 1'000, Matches::MANY, /*dirty=*/false); }
static void UTXOScanDirty10000_100000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 100'000, 1'000, Matches::NONE, /*dirty=*/true); }

static void UTXOScanNoMatches1Script_1000000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 1'000'000, 1, Matches::NONE, /*dirty=*/false); }
static void UTXOScanNoMatches1000Scripts_1000000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 1'000'000, 1'000, Matches::NONE, /*dirty=*/false); }
static void UTXOScanNoMatches10000Scripts_1000000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 1'000'000, 10'000, Matches::NONE, /*dirty=*/false); }
static void UTXOScanFewMatches_1000000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 1'000'000, 1'000, Matches::FEW, /*dirty=*/false); }
static void UTXOScanManyMatches_1000000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 1'000'000, 1'000, Matches::MANY, /*dirty=*/false); }
static void UTXOScanDirty10000_1000000UTXOs(benchmark::Bench& bench) { UTXOScan(bench, 1'000'000, 1'000, Matches::NONE, /*dirty=*/true); }

BENCHMARK(UTXOScanNoMatches1Script_10000UTXOs);
BENCHMARK(UTXOScanNoMatches1000Scripts_10000UTXOs);
BENCHMARK(UTXOScanNoMatches10000Scripts_10000UTXOs);
BENCHMARK(UTXOScanFewMatches_10000UTXOs);
BENCHMARK(UTXOScanManyMatches_10000UTXOs);
BENCHMARK(UTXOScanDirty10000_10000UTXOs);

BENCHMARK(UTXOScanNoMatches1Script_100000UTXOs);
BENCHMARK(UTXOScanNoMatches1000Scripts_100000UTXOs);
BENCHMARK(UTXOScanNoMatches10000Scripts_100000UTXOs);
BENCHMARK(UTXOScanFewMatches_100000UTXOs);
BENCHMARK(UTXOScanManyMatches_100000UTXOs);
BENCHMARK(UTXOScanDirty10000_100000UTXOs);

BENCHMARK(UTXOScanNoMatches1Script_1000000UTXOs);
BENCHMARK(UTXOScanNoMatches1000Scripts_1000000UTXOs);
BENCHMARK(UTXOScanNoMatches10000Scripts_1000000UTXOs);
BENCHMARK(UTXOScanFewMatches_1000000UTXOs);
BENCHMARK(UTXOScanManyMatches_1000000UTXOs);
BENCHMARK(UTXOScanDirty10000_1000000UTXOs);
