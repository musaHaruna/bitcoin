// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/mempool_entry.h>
#include <kernel/mempool_removal_reason.h>
#include <random.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <util/hasher.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <optional>
#include <utility>
#include <vector>

class MempoolUpdatesListener : public CValidationInterface
{
public:
    std::vector<MemPoolChunksUpdate> updates;
    void MempoolUpdated(const MemPoolChunksUpdate& update) override { updates.push_back(update); }
    void Clear() { updates.clear(); }
};

struct MemPoolUpdateSetup : TestingSetup {
    MempoolUpdatesListener listener;
    CTxMemPool& mpool;
    MemPoolUpdateSetup()
        : TestingSetup{ChainType::REGTEST, TestOpts{.setup_net = false}},
          mpool{*Assert(m_node.mempool)}
    {
        // Finish setup notifications before collecting this test's updates.
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        m_node.validation_signals->RegisterValidationInterface(&listener);
    }
    ~MemPoolUpdateSetup()
    {
        m_node.validation_signals->UnregisterValidationInterface(&listener);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
    }

    void AddWithContext(const CTxMemPoolEntry& entry, MemPoolObservationContext context)
    {
        LOCK2(cs_main, mpool.cs);
        auto changeset = mpool.GetChangeSet();
        changeset->StageAddition(
            entry.GetSharedTx(), entry.GetFee(), entry.GetTime().count(),
            entry.GetHeight(), entry.GetSequence(), entry.GetSpendsCoinbase(),
            entry.GetSigOpCost(), entry.GetLockPoints());
        BOOST_REQUIRE(changeset->CheckMemPoolPolicyLimits());
        changeset->Apply(context);
    }

    std::vector<RemovedMempoolTransactionInfo> BlockRemoval(
        const std::vector<CTransactionRef>& transactions, unsigned int height)
    {
        LOCK2(cs_main, mpool.cs);
        return mpool.removeForBlock(transactions, MemPoolObservationContext{height, true, false});
    }
};

BOOST_FIXTURE_TEST_SUITE(mempool_update_tests, MemPoolUpdateSetup)

static FastRandomContext det_rand{true};

static CMutableTransaction ConstructTx(CAmount value = 1 * COIN, std::optional<COutPoint> prev_out = std::nullopt)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    if (prev_out) {
        tx.vin[0].prevout = prev_out.value();
    } else {
        tx.vin[0].prevout = COutPoint{Txid::FromUint256(det_rand.rand256()), 0};
    }
    tx.vout.resize(1);
    tx.vout[0].nValue = value;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

static uint256 ExpectedChunkHash(const std::vector<CMutableTransaction>& txs)
{
    std::vector<Wtxid> wtxids;
    wtxids.reserve(txs.size());
    for (const auto& tx : txs) {
        wtxids.emplace_back(CTransaction(tx).GetWitnessHash());
    }
    return GetHashFromWitnesses(std::move(wtxids));
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_NormalAddition)
{
    TestMemPoolEntryHelper entry;
    auto tx = ConstructTx();
    CAmount fee{100};
    auto tx_entry = entry.Fee(fee).FromTx(tx);
    int32_t size{tx_entry.GetAdjustedWeight()};
    FeeFrac expected_fee_rate{fee, size};
    {
        LOCK2(cs_main, mpool.cs);
        TryAddToMempool(mpool, tx_entry);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& update = listener.updates[0];
    BOOST_CHECK(update.reason == MemPoolRemovalReason::REPLACED);
    BOOST_CHECK(update.cause == MemPoolUpdateCause::TRANSACTIONS);
    BOOST_CHECK(!update.block_height.has_value());
    BOOST_CHECK(update.old_chunks.empty());
    BOOST_REQUIRE_EQUAL(update.new_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(update.new_chunks[0].m_chunk_hash, ExpectedChunkHash({tx}));
    BOOST_CHECK(update.new_chunks[0].m_fee_rate == expected_fee_rate);
    // The synthetic helper supplied no validation context for fee estimation.
    BOOST_CHECK(!update.new_chunks[0].m_fee_estimation_eligible);
    listener.Clear();
    // Child pays for low-fee parent
    auto parent_tx = ConstructTx();
    CAmount parent_fee{100};
    auto parent_entry = entry.Fee(parent_fee).FromTx(parent_tx);
    int32_t parent_size{parent_entry.GetAdjustedWeight()};
    FeeFrac parent_fee_rate{parent_fee, parent_size};
    // Child spends parent output and pays a high fee, boosting the package.
    auto child_tx = ConstructTx(1 * COIN, COutPoint{parent_tx.GetHash(), 0});
    CAmount child_fee{10000};
    auto child_entry = entry.Fee(child_fee).FromTx(child_tx);
    int32_t child_size{child_entry.GetAdjustedWeight()};
    // Once child is added the two txs form a single chunk — fee rate is combined.
    FeeFrac expected_cpfp_rate{parent_fee + child_fee, parent_size + child_size};
    {
        LOCK2(cs_main, mpool.cs);
        TryAddToMempool(mpool, parent_entry);
        TryAddToMempool(mpool, child_entry);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    // Two signals: one for parent, one for child.
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 2U);
    // After the child is added the chunk merges parent+child
    const auto& cpfp_update = listener.updates[1];
    BOOST_CHECK(cpfp_update.reason == MemPoolRemovalReason::REPLACED);
    BOOST_CHECK(cpfp_update.cause == MemPoolUpdateCause::TRANSACTIONS);
    BOOST_CHECK(!cpfp_update.block_height.has_value());
    BOOST_REQUIRE_EQUAL(cpfp_update.old_chunks.size(), 1U);
    const auto& old_chunk = cpfp_update.old_chunks[0];
    BOOST_CHECK_EQUAL(old_chunk.m_chunk_hash, ExpectedChunkHash({parent_tx}));
    BOOST_CHECK(old_chunk.m_fee_rate == parent_fee_rate);
    BOOST_REQUIRE_EQUAL(cpfp_update.new_chunks.size(), 1U);
    const auto& cpfp_chunk = cpfp_update.new_chunks[0];
    BOOST_CHECK_EQUAL(cpfp_chunk.m_chunk_hash, ExpectedChunkHash({parent_tx, child_tx}));
    BOOST_CHECK(cpfp_chunk.m_fee_rate == expected_cpfp_rate);
    BOOST_CHECK(!old_chunk.m_fee_estimation_eligible);
    BOOST_CHECK(!cpfp_chunk.m_fee_estimation_eligible);
    listener.Clear();
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_RBFReplacement)
{
    TestMemPoolEntryHelper entry;
    COutPoint shared_input{Txid::FromUint256(det_rand.rand256()), 0};
    auto original_tx = ConstructTx();
    original_tx.vin[0].prevout = shared_input;
    CAmount original_fee{1000};
    auto original_entry = entry.Fee(original_fee).FromTx(original_tx);
    FeeFrac expected_original_rate{original_fee, original_entry.GetAdjustedWeight()};
    // Exercise the ChangeSet notification path with distinct conflicting transactions.
    // This test does not exercise full RBF admission policy.
    CAmount replacement_fee{5000};
    auto replacement_tx = original_tx;
    replacement_tx.vout[0].nValue -= replacement_fee - original_fee;
    BOOST_REQUIRE(original_tx.GetHash() != replacement_tx.GetHash());
    BOOST_REQUIRE(CTransaction(original_tx).GetWitnessHash() != CTransaction(replacement_tx).GetWitnessHash());
    BOOST_REQUIRE(ExpectedChunkHash({original_tx}) != ExpectedChunkHash({replacement_tx}));
    auto replacement_entry = entry.Fee(replacement_fee).FromTx(replacement_tx);
    FeeFrac expected_replacement_rate{replacement_fee, replacement_entry.GetAdjustedWeight()};
    {
        LOCK2(cs_main, mpool.cs);
        TryAddToMempool(mpool, original_entry);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    listener.Clear();
    {
        LOCK2(cs_main, mpool.cs);
        auto changeset = mpool.GetChangeSet();
        changeset->StageAddition(replacement_entry.GetSharedTx(), replacement_entry.GetFee(), replacement_entry.GetTime().count(),
                                 replacement_entry.GetHeight(), replacement_entry.GetSequence(), replacement_entry.GetSpendsCoinbase(),
                                 replacement_entry.GetSigOpCost(), replacement_entry.GetLockPoints());
        auto conflict_iter = mpool.GetIter(original_entry.GetSharedTx()->GetHash());
        BOOST_REQUIRE(conflict_iter.has_value());
        changeset->StageRemoval(conflict_iter.value());
        changeset->Apply();
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& update = listener.updates[0];
    BOOST_CHECK(update.reason == MemPoolRemovalReason::REPLACED);
    BOOST_CHECK(update.cause == MemPoolUpdateCause::TRANSACTIONS);
    BOOST_CHECK(!update.block_height.has_value());
    // Old diagram: original tx's chunk is gone.
    BOOST_REQUIRE_EQUAL(update.old_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(update.old_chunks[0].m_chunk_hash, ExpectedChunkHash({original_tx}));
    BOOST_CHECK(update.old_chunks[0].m_fee_rate == expected_original_rate);
    // New diagram: replacement tx's chunk appears.
    BOOST_REQUIRE_EQUAL(update.new_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(update.new_chunks[0].m_chunk_hash, ExpectedChunkHash({replacement_tx}));
    BOOST_CHECK(update.new_chunks[0].m_fee_rate == expected_replacement_rate);
    BOOST_CHECK(!mpool.exists(original_tx.GetHash()));
    BOOST_CHECK(mpool.exists(replacement_tx.GetHash()));
    listener.Clear();
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_ChunkHashDeterminism)
{
    TestMemPoolEntryHelper entry;
    auto tx = ConstructTx();
    const uint256 expected_hash = ExpectedChunkHash({tx});
    CAmount fee{1000};
    int32_t size{entry.Fee(fee).FromTx(tx).GetAdjustedWeight()};
    FeeFrac expected_fee_rate{fee, size};
    for (int round = 0; round < 2; ++round) {
        {
            LOCK2(cs_main, mpool.cs);
            TryAddToMempool(mpool, entry.Fee(fee).FromTx(tx));
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        listener.Clear();
        const auto removed = BlockRemoval({MakeTransactionRef(tx)}, /*height=*/1);
        BOOST_REQUIRE_EQUAL(removed.size(), 1U);
        BOOST_CHECK_EQUAL(removed[0].info.m_tx->GetHash(), tx.GetHash());
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
        BOOST_REQUIRE_EQUAL(listener.updates[0].new_chunks.size(), 0U);
        BOOST_REQUIRE_EQUAL(listener.updates[0].old_chunks.size(), 1U);
        BOOST_CHECK(listener.updates[0].reason == MemPoolRemovalReason::BLOCK);
        BOOST_REQUIRE(listener.updates[0].block_height.has_value());
        BOOST_CHECK(listener.updates[0].block_height.value() == 1);
        BOOST_CHECK(listener.updates[0].cause == MemPoolUpdateCause::BLOCK);
        BOOST_REQUIRE_EQUAL(listener.updates[0].fully_confirmed_chunks.size(), 1U);
        BOOST_CHECK_EQUAL(listener.updates[0].fully_confirmed_chunks[0], expected_hash);
        const auto& chunk = listener.updates[0].old_chunks[0];
        // Both rounds must produce the same hash, matching the expected value.
        BOOST_CHECK_EQUAL(chunk.m_chunk_hash, expected_hash);
        BOOST_CHECK(chunk.m_fee_rate == expected_fee_rate);
    }
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_BlockConnection)
{
    TestMemPoolEntryHelper entry;
    // Build a CPFP cluster: low-fee parent + high-fee child.
    // Together they form one chunk with the combined package fee rate.
    auto parent_tx = ConstructTx();
    CAmount parent_fee{100};
    auto parent_entry = entry.Fee(parent_fee).FromTx(parent_tx);
    int32_t parent_size{parent_entry.GetAdjustedWeight()};
    auto child_tx = ConstructTx(1 * COIN, COutPoint{parent_tx.GetHash(), 0});
    CAmount child_fee{10000};
    auto child_entry = entry.Fee(child_fee).FromTx(child_tx);
    int32_t child_size{child_entry.GetAdjustedWeight()};
    FeeFrac expected_cluster_rate{parent_fee + child_fee, parent_size + child_size};
    FeeFrac expected_child_solo_rate{child_fee, child_size};
    {
        LOCK2(cs_main, mpool.cs);
        TryAddToMempool(mpool, parent_entry);
        TryAddToMempool(mpool, child_entry);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    listener.Clear();
    // Mine the parent — child remains but is now its own solo chunk.
    const auto removed = BlockRemoval({MakeTransactionRef(parent_tx)}, /*height=*/2);
    BOOST_REQUIRE_EQUAL(removed.size(), 1U);
    BOOST_CHECK_EQUAL(removed[0].info.m_tx->GetHash(), parent_tx.GetHash());
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& update = listener.updates[0];
    BOOST_CHECK(update.reason == MemPoolRemovalReason::BLOCK);
    BOOST_REQUIRE(update.block_height.has_value());
    BOOST_CHECK(update.block_height.value() == 2);
    BOOST_CHECK(update.cause == MemPoolUpdateCause::BLOCK);
    BOOST_CHECK(update.fully_confirmed_chunks.empty());
    // Old diagram: the merged parent+child chunk.
    BOOST_REQUIRE_EQUAL(update.old_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(update.old_chunks[0].m_chunk_hash, ExpectedChunkHash({parent_tx, child_tx}));
    BOOST_CHECK(update.old_chunks[0].m_fee_rate == expected_cluster_rate);

    // New diagram: child is now a solo chunk with its own fee rate.
    BOOST_REQUIRE_EQUAL(update.new_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(update.new_chunks[0].m_chunk_hash, ExpectedChunkHash({child_tx}));
    BOOST_CHECK(update.new_chunks[0].m_fee_rate == expected_child_solo_rate);

    BOOST_CHECK(!mpool.exists(parent_tx.GetHash()));
    BOOST_CHECK(mpool.exists(child_tx.GetHash()));
    listener.Clear();
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_BlockConflict)
{
    TestMemPoolEntryHelper entry;
    COutPoint shared_input{Txid::FromUint256(det_rand.rand256()), 0};
    auto mempool_tx = ConstructTx();
    mempool_tx.vin[0].prevout = shared_input;
    const uint256 expected_hash = ExpectedChunkHash({mempool_tx});
    CAmount fee{1000};
    int32_t size{entry.Fee(fee).FromTx(mempool_tx).GetAdjustedWeight()};
    FeeFrac expected_fee_rate{fee, size};

    {
        LOCK2(cs_main, mpool.cs);
        TryAddToMempool(mpool, entry.Fee(fee).FromTx(mempool_tx));
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    listener.Clear();

    // block_tx spends the same input — evicts mempool_tx as a conflict.
    auto block_tx = ConstructTx();
    block_tx.vin[0].prevout = shared_input;
    block_tx.vout[0].nValue = 9 * COIN / 10;
    const auto removed = BlockRemoval({MakeTransactionRef(block_tx)}, /*height=*/3);
    BOOST_CHECK(removed.empty());
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    // One BLOCK update (empty staged set) and one CONFLICT update.
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 2U);
    const auto& block_update = listener.updates[0];
    BOOST_CHECK(block_update.reason == MemPoolRemovalReason::BLOCK);
    BOOST_CHECK(block_update.cause == MemPoolUpdateCause::BLOCK);
    BOOST_REQUIRE(block_update.block_height.has_value());
    BOOST_CHECK_EQUAL(block_update.block_height.value(), 3);
    BOOST_CHECK(block_update.old_chunks.empty());
    BOOST_CHECK(block_update.new_chunks.empty());
    BOOST_CHECK(block_update.fully_confirmed_chunks.empty());
    // Conflict notification comes after block.
    const auto& update = listener.updates[1];
    BOOST_REQUIRE_EQUAL(update.old_chunks.size(), 1U);
    const auto& chunk = update.old_chunks[0];
    BOOST_CHECK(update.new_chunks.empty());
    BOOST_CHECK_EQUAL(chunk.m_chunk_hash, expected_hash);
    BOOST_CHECK(chunk.m_fee_rate == expected_fee_rate);
    BOOST_CHECK(update.reason == MemPoolRemovalReason::CONFLICT);
    BOOST_CHECK(update.cause == MemPoolUpdateCause::REMOVAL);
    BOOST_CHECK(!update.block_height.has_value());
    BOOST_CHECK(!mpool.exists(mempool_tx.GetHash()));
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_Expiry)
{
    TestMemPoolEntryHelper entry;
    auto old_tx = ConstructTx();
    auto fresh_tx = ConstructTx();
    CAmount fee{1000};
    int32_t size{entry.Fee(fee).FromTx(old_tx).GetAdjustedWeight()};
    FeeFrac expected_fee_rate{fee, size};
    const NodeSeconds now{std::chrono::seconds{1'700'000'000}};
    const auto old_time = now - std::chrono::hours(25);
    {
        LOCK2(cs_main, mpool.cs);
        TryAddToMempool(mpool, entry.Fee(fee).Time(old_time).FromTx(old_tx));
        TryAddToMempool(mpool, entry.Fee(1000).Time(now).FromTx(fresh_tx));
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    listener.Clear();
    {
        LOCK2(cs_main, mpool.cs);
        BOOST_CHECK_EQUAL(mpool.Expire((now - std::chrono::seconds(1)).time_since_epoch()), 1U);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& update = listener.updates[0];
    BOOST_REQUIRE_EQUAL(update.old_chunks.size(), 1U);
    const auto& chunk = update.old_chunks[0];
    BOOST_CHECK(update.reason == MemPoolRemovalReason::EXPIRY);
    BOOST_CHECK(update.cause == MemPoolUpdateCause::REMOVAL);
    BOOST_CHECK(!update.block_height.has_value());
    BOOST_CHECK_EQUAL(chunk.m_chunk_hash, ExpectedChunkHash({old_tx}));
    BOOST_CHECK(chunk.m_fee_rate == expected_fee_rate);
    BOOST_CHECK(update.new_chunks.empty());
    BOOST_CHECK(!mpool.exists(old_tx.GetHash()));
    BOOST_CHECK(mpool.exists(fresh_tx.GetHash()));
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_SizeLimit)
{
    TestMemPoolEntryHelper entry;
    auto low_fee_tx = ConstructTx();
    auto high_fee_tx = ConstructTx();
    CAmount fee_low{1000};
    CAmount fee_high{9000};
    FeeFrac expected_fee_rate_low{fee_low, entry.Fee(fee_low).FromTx(low_fee_tx).GetAdjustedWeight()};
    auto low_fee_entry = entry.Fee(fee_low).FromTx(low_fee_tx);
    {
        LOCK2(cs_main, mpool.cs);
        TryAddToMempool(mpool, entry.Fee(fee_high).FromTx(high_fee_tx));
        TryAddToMempool(mpool, entry.Fee(fee_low).FromTx(low_fee_tx));
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    listener.Clear();
    // Require less memory than is currently used; the low-fee chunk is evicted.
    {
        LOCK2(cs_main, mpool.cs);
        mpool.TrimToSize(mpool.DynamicMemoryUsage() - low_fee_entry.DynamicMemoryUsage());
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& update = listener.updates[0];
    BOOST_REQUIRE_EQUAL(update.old_chunks.size(), 1U);
    const auto& chunk_low = update.old_chunks[0];
    BOOST_CHECK(update.reason == MemPoolRemovalReason::SIZELIMIT);
    BOOST_CHECK(update.cause == MemPoolUpdateCause::REMOVAL);
    BOOST_CHECK(!update.block_height.has_value());
    BOOST_CHECK_EQUAL(chunk_low.m_chunk_hash, ExpectedChunkHash({low_fee_tx}));
    BOOST_CHECK(chunk_low.m_fee_rate == expected_fee_rate_low);
    BOOST_CHECK(update.new_chunks.empty());
    BOOST_CHECK(!mpool.exists(low_fee_tx.GetHash()));
    BOOST_CHECK(mpool.exists(high_fee_tx.GetHash()));
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_RemoveRecursive)
{
    TestMemPoolEntryHelper entry;
    auto parent_tx = ConstructTx();
    auto child_tx = ConstructTx(1 * COIN, COutPoint{parent_tx.GetHash(), 0});
    auto independent_tx = ConstructTx();
    const auto parent_entry = entry.Fee(100).FromTx(parent_tx);
    const auto child_entry = entry.Fee(10000).FromTx(child_tx);
    const auto independent_entry = entry.Fee(2000).FromTx(independent_tx);
    const FeeFrac expected_chunk_rate{
        10100, parent_entry.GetAdjustedWeight() + child_entry.GetAdjustedWeight()};
    {
        LOCK2(cs_main, mpool.cs);
        TryAddToMempool(mpool, parent_entry);
        TryAddToMempool(mpool, child_entry);
        TryAddToMempool(mpool, independent_entry);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    listener.Clear();
    {
        LOCK(mpool.cs);
        // Removing the parent recursively must remove its child too.
        mpool.removeRecursive(CTransaction(parent_tx), MemPoolRemovalReason::REORG);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& update = listener.updates[0];
    BOOST_CHECK(update.reason == MemPoolRemovalReason::REORG);
    BOOST_CHECK(update.cause == MemPoolUpdateCause::REMOVAL);
    BOOST_CHECK(!update.block_height.has_value());
    BOOST_REQUIRE_EQUAL(update.old_chunks.size(), 1U);
    const auto& removed_chunk = update.old_chunks[0];
    BOOST_CHECK_EQUAL(removed_chunk.m_chunk_hash, ExpectedChunkHash({parent_tx, child_tx}));
    BOOST_CHECK(removed_chunk.m_fee_rate == expected_chunk_rate);
    BOOST_CHECK(update.new_chunks.empty());
    BOOST_CHECK(!mpool.exists(parent_tx.GetHash()));
    BOOST_CHECK(!mpool.exists(child_tx.GetHash()));
    BOOST_CHECK(mpool.exists(independent_tx.GetHash()));
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_UnchangedChunk)
{
    TestMemPoolEntryHelper entry;
    auto parent_tx = ConstructTx();
    auto child_tx = ConstructTx(1 * COIN, COutPoint{parent_tx.GetHash(), 0});
    const auto parent_entry = entry.Fee(10000).FromTx(parent_tx);
    const auto child_entry = entry.Fee(100).FromTx(child_tx);
    const FeeFrac parent_rate{10000, parent_entry.GetAdjustedWeight()};
    const FeeFrac child_rate{100, child_entry.GetAdjustedWeight()};
    {
        LOCK2(cs_main, mpool.cs);
        TryAddToMempool(mpool, parent_entry);
        TryAddToMempool(mpool, child_entry);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    listener.Clear();
    {
        LOCK(mpool.cs);
        mpool.removeRecursive(CTransaction(child_tx), MemPoolRemovalReason::REORG);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& update = listener.updates[0];
    BOOST_CHECK(update.reason == MemPoolRemovalReason::REORG);
    BOOST_CHECK(update.cause == MemPoolUpdateCause::REMOVAL);
    BOOST_CHECK(!update.block_height.has_value());
    BOOST_REQUIRE_EQUAL(update.old_chunks.size(), 2U);
    BOOST_REQUIRE_EQUAL(update.new_chunks.size(), 1U);
    // The unchanged high-fee parent legitimately occurs in both affected diagrams.
    BOOST_CHECK_EQUAL(update.old_chunks[0].m_chunk_hash, ExpectedChunkHash({parent_tx}));
    BOOST_CHECK_EQUAL(update.new_chunks[0].m_chunk_hash, ExpectedChunkHash({parent_tx}));
    BOOST_CHECK(update.old_chunks[0].m_fee_rate == parent_rate);
    BOOST_CHECK(update.new_chunks[0].m_fee_rate == parent_rate);
    BOOST_CHECK_EQUAL(update.old_chunks[1].m_chunk_hash, ExpectedChunkHash({child_tx}));
    BOOST_CHECK(update.old_chunks[1].m_fee_rate == child_rate);
    BOOST_CHECK(mpool.exists(parent_tx.GetHash()));
    BOOST_CHECK(!mpool.exists(child_tx.GetHash()));
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_FullChunkBlockRemoval)
{
    TestMemPoolEntryHelper entry;
    auto parent_tx = ConstructTx();
    auto child_tx = ConstructTx(1 * COIN, COutPoint{parent_tx.GetHash(), 0});
    const auto parent_entry = entry.Fee(100).FromTx(parent_tx);
    const auto child_entry = entry.Fee(10000).FromTx(child_tx);
    const FeeFrac chunk_rate{10100, parent_entry.GetAdjustedWeight() + child_entry.GetAdjustedWeight()};
    {
        LOCK2(cs_main, mpool.cs);
        TryAddToMempool(mpool, parent_entry);
        TryAddToMempool(mpool, child_entry);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    listener.Clear();
    const auto removed = BlockRemoval(
        {MakeTransactionRef(parent_tx), MakeTransactionRef(child_tx)}, /*height=*/4);
    BOOST_REQUIRE_EQUAL(removed.size(), 2U);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& update = listener.updates[0];
    BOOST_CHECK(update.reason == MemPoolRemovalReason::BLOCK);
    BOOST_REQUIRE(update.block_height.has_value());
    BOOST_CHECK_EQUAL(update.block_height.value(), 4);
    BOOST_CHECK(update.cause == MemPoolUpdateCause::BLOCK);
    BOOST_REQUIRE_EQUAL(update.fully_confirmed_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(update.fully_confirmed_chunks[0], ExpectedChunkHash({parent_tx, child_tx}));
    BOOST_REQUIRE_EQUAL(update.old_chunks.size(), 1U);
    BOOST_CHECK(update.new_chunks.empty());
    BOOST_CHECK_EQUAL(update.old_chunks[0].m_chunk_hash, ExpectedChunkHash({parent_tx, child_tx}));
    BOOST_CHECK(update.old_chunks[0].m_fee_rate == chunk_rate);
    BOOST_CHECK(!mpool.exists(parent_tx.GetHash()));
    BOOST_CHECK(!mpool.exists(child_tx.GetHash()));
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_ObservationContext)
{
    TestMemPoolEntryHelper entry;
    auto parent_tx = ConstructTx();
    auto child_tx = ConstructTx(1 * COIN, COutPoint{parent_tx.GetHash(), 0});
    const auto parent_entry = entry.Fee(100).FromTx(parent_tx);
    const auto child_entry = entry.Fee(10000).FromTx(child_tx);
    const FeeFrac parent_rate{100, parent_entry.GetAdjustedWeight()};
    const FeeFrac combined_rate{
        10100, parent_entry.GetAdjustedWeight() + child_entry.GetAdjustedWeight()};
    const auto parent_hash = ExpectedChunkHash({parent_tx});
    const auto combined_hash = ExpectedChunkHash({parent_tx, child_tx});

    AddWithContext(parent_entry, MemPoolObservationContext{100, true, false});
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& parent_update = listener.updates[0];
    BOOST_CHECK(parent_update.cause == MemPoolUpdateCause::TRANSACTIONS);
    BOOST_REQUIRE(parent_update.observation_height.has_value());
    BOOST_CHECK_EQUAL(parent_update.observation_height.value(), 100U);
    BOOST_CHECK(parent_update.chainstate_is_current);
    BOOST_CHECK(!parent_update.block_height.has_value());
    BOOST_CHECK(!parent_update.reset_observations);
    BOOST_CHECK(parent_update.fully_confirmed_chunks.empty());
    BOOST_CHECK(parent_update.old_chunks.empty());
    BOOST_REQUIRE_EQUAL(parent_update.new_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(parent_update.new_chunks[0].m_chunk_hash, parent_hash);
    BOOST_CHECK(parent_update.new_chunks[0].m_fee_rate == parent_rate);
    BOOST_CHECK(parent_update.new_chunks[0].m_fee_estimation_eligible);
    const auto parent_sequence = parent_update.sequence;
    BOOST_CHECK_GT(parent_sequence, 0U);
    listener.Clear();

    // The combined configuration first appears at height 103, not at the
    // parent's earlier observation height of 100.
    AddWithContext(child_entry, MemPoolObservationContext{103, true, false});
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& child_update = listener.updates[0];
    BOOST_CHECK(child_update.cause == MemPoolUpdateCause::TRANSACTIONS);
    BOOST_REQUIRE(child_update.observation_height.has_value());
    BOOST_CHECK_EQUAL(child_update.observation_height.value(), 103U);
    BOOST_CHECK(child_update.chainstate_is_current);
    BOOST_CHECK(!child_update.block_height.has_value());
    BOOST_CHECK(child_update.fully_confirmed_chunks.empty());
    BOOST_REQUIRE_EQUAL(child_update.old_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(child_update.old_chunks[0].m_chunk_hash, parent_hash);
    BOOST_CHECK(child_update.old_chunks[0].m_fee_rate == parent_rate);
    BOOST_CHECK(child_update.old_chunks[0].m_fee_estimation_eligible);
    BOOST_REQUIRE_EQUAL(child_update.new_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(child_update.new_chunks[0].m_chunk_hash, combined_hash);
    BOOST_CHECK(child_update.new_chunks[0].m_fee_rate == combined_rate);
    BOOST_CHECK(child_update.new_chunks[0].m_fee_estimation_eligible);
    const auto child_sequence = child_update.sequence;
    BOOST_CHECK_GT(child_sequence, parent_sequence);
    listener.Clear();

    const auto removed = BlockRemoval(
        {MakeTransactionRef(parent_tx), MakeTransactionRef(child_tx)}, /*height=*/104);
    BOOST_REQUIRE_EQUAL(removed.size(), 2U);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& block_update = listener.updates[0];
    BOOST_CHECK(block_update.cause == MemPoolUpdateCause::BLOCK);
    BOOST_REQUIRE(block_update.block_height.has_value());
    BOOST_CHECK_EQUAL(block_update.block_height.value(), 104U);
    BOOST_REQUIRE(block_update.observation_height.has_value());
    BOOST_CHECK_EQUAL(block_update.observation_height.value(), 104U);
    BOOST_CHECK(block_update.chainstate_is_current);
    BOOST_REQUIRE_EQUAL(block_update.old_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(block_update.old_chunks[0].m_chunk_hash, combined_hash);
    BOOST_CHECK(block_update.old_chunks[0].m_fee_rate == combined_rate);
    BOOST_CHECK(block_update.old_chunks[0].m_fee_estimation_eligible);
    BOOST_CHECK(block_update.new_chunks.empty());
    BOOST_REQUIRE_EQUAL(block_update.fully_confirmed_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(block_update.fully_confirmed_chunks[0], combined_hash);
    BOOST_CHECK_GT(block_update.sequence, child_sequence);
    BOOST_CHECK(!mpool.exists(parent_tx.GetHash()));
    BOOST_CHECK(!mpool.exists(child_tx.GetHash()));
}

BOOST_AUTO_TEST_CASE(MempoolUpdated_EmptyBlock)
{
    const auto removed = BlockRemoval({}, /*height=*/105);
    BOOST_CHECK(removed.empty());
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(listener.updates.size(), 1U);
    const auto& update = listener.updates[0];
    BOOST_CHECK(update.reason == MemPoolRemovalReason::BLOCK);
    BOOST_CHECK(update.cause == MemPoolUpdateCause::BLOCK);
    BOOST_REQUIRE(update.block_height.has_value());
    BOOST_CHECK_EQUAL(update.block_height.value(), 105U);
    BOOST_REQUIRE(update.observation_height.has_value());
    BOOST_CHECK_EQUAL(update.observation_height.value(), 105U);
    BOOST_CHECK(update.chainstate_is_current);
    BOOST_CHECK(!update.reset_observations);
    BOOST_CHECK(update.old_chunks.empty());
    BOOST_CHECK(update.new_chunks.empty());
    BOOST_CHECK(update.fully_confirmed_chunks.empty());
    BOOST_CHECK_GT(update.sequence, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
