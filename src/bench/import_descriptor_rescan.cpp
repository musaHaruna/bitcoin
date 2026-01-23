// Copyright (c) 2012-2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <interfaces/chain.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/time.h>
#include <validation.h>
#include <wallet/wallet.h>
#include <wallet/receive.h>
#include <wallet/test/util.h>

#include <cassert>
#include <memory>
#include <optional>
#include <string>

using interfaces::FoundBlock;

namespace wallet {

// Get chain tip time safely
static int64_t GetChainTipTime(CWallet& wallet)
{
    int64_t tip_time{};
    int64_t tip_mtp{};
    LOCK(wallet.cs_wallet);
    CHECK_NONFATAL(wallet.chain().findBlock(wallet.GetLastBlockHash(), FoundBlock().time(tip_time).mtpTime(tip_mtp)));
    return tip_time;
}


static void NormalRescan(benchmark::Bench& bench, int64_t start_time_offset)
{
    const auto test_setup = MakeNoLogFileContext<const TestingSetup>();

    CWallet wallet{test_setup->m_node.chain.get(), "", CreateMockableWalletDatabase()};
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    auto handler = test_setup->m_node.chain->handleNotifications({&wallet, [](CWallet*) {}});

    // Mine 100 deterministic blocks
    const auto address = getnewaddress(wallet);
    for (int i = 0; i < 100; ++i) {
        generatetoaddress(test_setup->m_node, address);
    }

    WalletRescanReserver reserver(wallet);
    assert(reserver.reserve());

    int64_t tip_time = GetChainTipTime(wallet);
    int64_t start_time = tip_time - start_time_offset;

    bench.run([&] {
        wallet.RescanFromTime(start_time, reserver, /*update=*/true);
    });
}

static void BenchmarkRescanFull(benchmark::Bench& bench)   { NormalRescan(bench, 3600*24*365); } // ~1 year

struct IncrementalRescanResult {
    bool matched{false};          // Wallet balance matches UTXO-set balance
    int chunks_scanned{0};        // Number of incremental chunks scanned
    int64_t matched_from_time{0}; // Timestamp where match occurred
};

static std::optional<IncrementalRescanResult> IncrementalRescan(CWallet& wallet, const CAmount utxo_target, WalletRescanReserver& reserver)
{
    constexpr int BLOCKS_PER_CHUNK = 1000;
    constexpr int64_t AVG_BLOCK_TIME_SEC = 600; // seconds per block (~10 minutes)

    // Get current chain tip
    int64_t tip_time{0};
    int tip_height{0};
    LOCK(wallet.cs_wallet);
    CHECK_NONFATAL(wallet.chain().findBlock(wallet.GetLastBlockHash(),interfaces::FoundBlock().time(tip_time).height(tip_height)));

    // Compute earliest safe rescan time if node is pruned
    bool has_prune_boundary = false;
    int64_t earliest_safe_time = 0;

    if (auto prune_height_opt = wallet.chain().getPruneHeight()) {
        int64_t difference = tip_height - *prune_height_opt;  
        int64_t blocks_available = std::max(difference, int64_t(0));
        earliest_safe_time = std::max(tip_time - blocks_available * AVG_BLOCK_TIME_SEC, int64_t(0));
        has_prune_boundary = true;
    }

    int64_t next_chunk_end_time = tip_time; // upper boundary of next chunk
    int chunk_index = 1;

    IncrementalRescanResult result;

    while (true) {
        result.chunks_scanned++;

        // Compute start time of this chunk
        int64_t chunk_start_time = tip_time > int64_t(chunk_index) * BLOCKS_PER_CHUNK * AVG_BLOCK_TIME_SEC ? tip_time - int64_t(chunk_index) * BLOCKS_PER_CHUNK * AVG_BLOCK_TIME_SEC : 0;

        int64_t chunk_end_time = next_chunk_end_time;

        // Check prune boundary
        if (has_prune_boundary && chunk_start_time < earliest_safe_time) {
            chunk_start_time = earliest_safe_time;
        }

        // No more chunks left to scan
        if (chunk_index > 1 && chunk_start_time == next_chunk_end_time) {
            break;
        }

        // Perform rescan for this chunk [chunk_start_time, chunk_end_time)
        int64_t scanned_up_to_time = wallet.RescanFromTime(chunk_start_time, reserver, /*update=*/true, /*endTime=*/std::optional<int64_t>(chunk_end_time));

        // If some blocks in the chunk failed to scan, return nullopt for fallback
        if (scanned_up_to_time > chunk_start_time) {
            return std::nullopt;
        }

        // Check if wallet balance matches target after this chunk
        const auto bal = GetBalance(wallet);
        if (bal.m_mine_trusted == utxo_target) {
            result.matched = true;
            result.matched_from_time = chunk_start_time;
            return result;
        }

        next_chunk_end_time = chunk_start_time;

        // Stop if we've reached genesis or prune boundary
        if (chunk_start_time == 0 || (has_prune_boundary && chunk_start_time == earliest_safe_time)) {
            break;
        }

        ++chunk_index;
    }

    return std::nullopt;
}

static void BenchmarkIncrementalRescans(benchmark::Bench& bench)
{
    const auto test_setup = MakeNoLogFileContext<const TestingSetup>();
    CWallet wallet(test_setup->m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }
    auto handler = test_setup->m_node.chain->handleNotifications({&wallet, [](CWallet*) {} });

    const auto address = getnewaddress(wallet);
    for (int i = 0; i < 500; ++i) {
        generatetoaddress(test_setup->m_node, address);
    }

    WalletRescanReserver reserver(wallet);
    assert(reserver.reserve());

    const CAmount utxo_target = GetBalance(wallet).m_mine_trusted;

    bench.run([&] {
        IncrementalRescan(wallet, utxo_target, reserver);
    });
}


BENCHMARK(BenchmarkRescanFull, benchmark::PriorityLevel::HIGH);
BENCHMARK(BenchmarkIncrementalRescans, benchmark::PriorityLevel::HIGH);

} // namespace wallet
