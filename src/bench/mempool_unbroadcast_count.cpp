// Temporary diagnostic benchmark; not part of the production patch.
#include <bench/bench.h>
#include <consensus/amount.h>
#include <kernel/cs_main.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <util/check.h>

#include <cstddef>
#include <cstring>

// Both paths use the real CTxMemPool, and both include the RPC's outer lock.
template <bool Copy>
static void UnbroadcastCount(benchmark::Bench& bench, size_t count)
{
    const auto setup = MakeNoLogFileContext<const TestingSetup>();
    CTxMemPool& pool{*Assert(setup->m_node.mempool)};
    {
        LOCK2(cs_main, pool.cs);
        for (size_t i = 0; i < count; ++i) {
            uint256 prev_hash;
            std::memcpy(prev_hash.data(), &i, sizeof(i));
            CMutableTransaction tx;
            tx.vin.emplace_back(COutPoint{Txid::FromUint256(prev_hash), 0});
            tx.vout.emplace_back(10 * COIN, CScript{} << OP_TRUE);
            const auto tx_ref{MakeTransactionRef(tx)};
            TryAddToMempool(pool, TestMemPoolEntryHelper{}.Fee(1000).FromTx(tx_ref));
            Assert(pool.exists(tx_ref->GetHash()));
            pool.AddUnbroadcastTx(tx_ref->GetHash());
        }
        Assert(pool.size() == count);
        Assert(pool.GetUnbroadcastTxCount() == count);
        Assert(pool.GetUnbroadcastTxs().size() == count);
    }

    // All population and fixture creation above are excluded from measurement.
    bench.unit("query").warmup(100).run([&] {
        LOCK(pool.cs);
        if constexpr (Copy) {
            const auto n{pool.GetUnbroadcastTxs().size()};
            ankerl::nanobench::doNotOptimizeAway(n);
        } else {
            const auto n{pool.GetUnbroadcastTxCount()};
            ankerl::nanobench::doNotOptimizeAway(n);
        }
    });
}

#define REGISTER_COUNT(N) \
    static void UnbroadcastCountCopy_##N(benchmark::Bench& bench) { UnbroadcastCount<true>(bench, N); } \
    static void UnbroadcastCountDirect_##N(benchmark::Bench& bench) { UnbroadcastCount<false>(bench, N); } \
    BENCHMARK(UnbroadcastCountCopy_##N); \
    BENCHMARK(UnbroadcastCountDirect_##N);

REGISTER_COUNT(0)
REGISTER_COUNT(1)
REGISTER_COUNT(10)
REGISTER_COUNT(100)
REGISTER_COUNT(1000)
REGISTER_COUNT(10000)
