// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <kernel/mempool_entry.h>
#include <policy/fees/block_policy_estimator.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdio>
#include <cmath>
#include <limits>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

namespace {

MemPoolChunk MakeChunk(uint64_t id, CAmount fee = 2000, int32_t weight = 800, bool eligible = true)
{
    HashWriter writer;
    writer << id;
    return MemPoolChunk{FeeFrac{fee, weight}, writer.GetHash(), eligible};
}

std::vector<uint256> ChunkHashes(const std::vector<MemPoolChunk>& chunks)
{
    std::vector<uint256> hashes;
    for (const auto& chunk : chunks) hashes.push_back(chunk.m_chunk_hash);
    return hashes;
}

struct ObservationCounts {
    double total;
    double success;
    double pending;
    double failure;
    double unknown;
};

/** Deliver the same owned event contract used by the mempool publisher. */
struct ChunkEstimatorHarness {
    CBlockPolicyEstimator estimator{fs::path{}, false};
    uint64_t next_sequence{1};

    MemPoolChunksUpdate MakeUpdate(std::optional<unsigned int> height,
                                  std::vector<MemPoolChunk> old_chunks = {},
                                  std::vector<MemPoolChunk> new_chunks = {},
                                  MemPoolUpdateCause cause = MemPoolUpdateCause::TRANSACTIONS,
                                  std::vector<uint256> confirmed = {},
                                  bool current = true)
    {
        return MemPoolChunksUpdate{
            .old_chunks = std::move(old_chunks),
            .new_chunks = std::move(new_chunks),
            .reason = cause == MemPoolUpdateCause::BLOCK ? MemPoolRemovalReason::BLOCK : MemPoolRemovalReason::REPLACED,
            .block_height = cause == MemPoolUpdateCause::BLOCK ? height : std::nullopt,
            .fully_confirmed_chunks = std::move(confirmed),
            .observation_height = height,
            .chainstate_is_current = current,
            .cause = cause,
            .sequence = next_sequence++,
        };
    }

    void Send(const MemPoolChunksUpdate& update)
    {
        estimator.processMempoolUpdate(update);
        estimator.SanityCheck();
    }

    void Update(std::optional<unsigned int> height,
                std::vector<MemPoolChunk> old_chunks = {},
                std::vector<MemPoolChunk> new_chunks = {},
                MemPoolUpdateCause cause = MemPoolUpdateCause::TRANSACTIONS,
                std::vector<uint256> confirmed = {},
                bool current = true)
    {
        Send(MakeUpdate(height, std::move(old_chunks), std::move(new_chunks), cause, std::move(confirmed), current));
    }

    void Block(unsigned int height, std::vector<MemPoolChunk> old_chunks = {},
               std::vector<MemPoolChunk> new_chunks = {}, std::vector<uint256> confirmed = {})
    {
        Update(height, std::move(old_chunks), std::move(new_chunks), MemPoolUpdateCause::BLOCK, std::move(confirmed));
    }

    void Confirm(unsigned int height, const std::vector<MemPoolChunk>& chunks)
    {
        Block(height, chunks, {}, ChunkHashes(chunks));
    }

    ObservationCounts Counts(int target = 1, FeeEstimateHorizon horizon = FeeEstimateHorizon::SHORT_HALFLIFE) const
    {
        EstimationResult result;
        estimator.estimateRawFee(target, .95, horizon, &result);
        return {
            result.all.Total(),
            result.all.success,
            double(result.active_observations),
            result.all.failure,
            result.all.Unknown(),
        };
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(blockpolicyestimator_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(BlockPolicyEstimates)
{
    ChunkEstimatorHarness test;
    auto& fee_estimator = test.estimator;
    constexpr CAmount BASE_FEE{2000};
    constexpr CAmount DELTA_FEE{100};
    constexpr int32_t CHUNK_WEIGHT{800};
    const CFeeRate base_rate{BASE_FEE, CHUNK_WEIGHT / 4};
    std::array<std::vector<MemPoolChunk>, 10> pending;
    uint64_t id{0};
    unsigned int height{0};

    const auto add_chunks = [&] {
        std::vector<MemPoolChunk> added;
        for (size_t bucket = 0; bucket < pending.size(); ++bucket) {
            for (int count = 0; count < 4; ++count) {
                const auto chunk = MakeChunk(++id, BASE_FEE * (bucket + 1), CHUNK_WEIGHT);
                pending[bucket].push_back(chunk);
                added.push_back(chunk);
            }
        }
        // Explicit height zero is a valid context, unlike an absent height.
        test.Update(height, {}, std::move(added));
    };

    const auto take_bucket = [&](size_t bucket, std::vector<MemPoolChunk>& block) {
        block.insert(block.end(), pending[bucket].begin(), pending[bucket].end());
        pending[bucket].clear();
    };

    // Preserve the original fee-curve experiment: forty observations per block,
    // with the highest-fee observations selected most frequently.
    while (height < 200) {
        add_chunks();
        std::vector<MemPoolChunk> block;
        for (unsigned int offset = 0; offset <= height % 10; ++offset) {
            take_bucket(9 - offset, block);
        }
        test.Confirm(++height, block);
        if (height == 3) {
            BOOST_CHECK(fee_estimator.estimateFee(1) == CFeeRate{0});
            // Known successes supply target-two support immediately.
            BOOST_CHECK_GT(fee_estimator.estimateFee(2).GetFeePerK(), 0);
        }
    }

    std::vector<CAmount> original_estimates;
    for (int target = 1; target < 10; ++target) {
        original_estimates.push_back(fee_estimator.estimateFee(target).GetFeePerK());
        if (target > 2) BOOST_CHECK(original_estimates[target - 1] <= original_estimates[target - 2]);
        if (target % 2 == 0) {
            const int multiple{11 - target};
            BOOST_CHECK(original_estimates[target - 1] < multiple * base_rate.GetFeePerK() + DELTA_FEE);
            BOOST_CHECK(original_estimates[target - 1] > multiple * base_rate.GetFeePerK() - DELTA_FEE);
        }
    }
    for (int target = 10; target <= 48; ++target) original_estimates.push_back(fee_estimator.estimateFee(target).GetFeePerK());

    // Empty blocks still advance and decay the estimator exactly once.
    while (height < 250) test.Block(++height);
    BOOST_CHECK(fee_estimator.estimateFee(1) == CFeeRate{0});
    for (int target = 2; target < 10; ++target) {
        BOOST_CHECK(fee_estimator.estimateFee(target).GetFeePerK() < original_estimates[target - 1] + DELTA_FEE);
        BOOST_CHECK(fee_estimator.estimateFee(target).GetFeePerK() > original_estimates[target - 1] - DELTA_FEE);
    }

    // Congestion: new observations arrive but none confirms for fifteen blocks.
    while (height < 265) {
        add_chunks();
        test.Block(++height);
    }
    for (int target = 1; target < 10; ++target) {
        BOOST_CHECK(fee_estimator.estimateFee(target) == CFeeRate{0} ||
                    fee_estimator.estimateFee(target).GetFeePerK() > original_estimates[target - 1] - DELTA_FEE);
    }

    std::vector<MemPoolChunk> block;
    for (size_t bucket = 0; bucket < pending.size(); ++bucket) take_bucket(bucket, block);
    test.Confirm(++height, block);
    for (int target = 2; target < 10; ++target) {
        BOOST_CHECK(fee_estimator.estimateFee(target) == CFeeRate{0} ||
                    fee_estimator.estimateFee(target).GetFeePerK() > original_estimates[target - 1] - DELTA_FEE);
    }

    // Continue through height 665 with every observation confirming next block.
    while (height < 665) {
        add_chunks();
        block.clear();
        for (size_t bucket = 0; bucket < pending.size(); ++bucket) take_bucket(bucket, block);
        test.Confirm(++height, block);
    }
    BOOST_CHECK(fee_estimator.estimateFee(1) == CFeeRate{0});
    for (int target = 2; target < 9; ++target) {
        BOOST_CHECK(fee_estimator.estimateFee(target).GetFeePerK() < original_estimates[target - 1] - DELTA_FEE);
    }
}

BOOST_AUTO_TEST_CASE(SmartEstimateAfterFeesFall)
{
    ChunkEstimatorHarness test;
    std::vector<MemPoolChunk> expensive, cheap;
    for (uint64_t id = 0; id < 200; ++id) {
        expensive.push_back(MakeChunk(id, 1000, 400)); // 10 sat/vB
        cheap.push_back(MakeChunk(id + 200, 100, 400)); // 1 sat/vB
    }
    test.Update(100, {}, expensive);
    test.Confirm(101, expensive);
    for (unsigned int height = 102; height <= 120; ++height) test.Block(height);
    test.Update(120, {}, cheap);
    test.Confirm(121, cheap);
    for (unsigned int height = 122; height <= 124; ++height) test.Block(height);

    // Early confirmations immediately support both longer targets.
    EstimationResult raw;
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(4, .95, FeeEstimateHorizon::SHORT_HALFLIFE).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(6, .95, FeeEstimateHorizon::SHORT_HALFLIFE, &raw).GetFeePerK(), 1000);
    BOOST_CHECK_GT(raw.pass.Total(), 90);
    BOOST_CHECK_EQUAL(raw.pass.Lower(), 1);

    FeeCalculation two, three;
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(2, &two, false).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(3, &three, false).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(three.desiredTarget, 3);
    BOOST_CHECK_EQUAL(three.returnedTarget, 3);
    BOOST_CHECK(three.reason == two.reason);
    BOOST_CHECK_EQUAL(three.est.target, two.est.target);
    BOOST_CHECK_EQUAL(three.est.pass.success, two.est.pass.success);
    BOOST_CHECK_EQUAL(three.est.pass.start, two.est.pass.start);
    BOOST_CHECK_EQUAL(three.est.pass.end, two.est.pass.end);

    // Equal quotes retain the requested target as the observations age.
    for (unsigned int height = 125; height <= 128; ++height) test.Block(height);
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(4, &three, false).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(three.desiredTarget, 4);
    BOOST_CHECK_EQUAL(three.returnedTarget, 4);
}

BOOST_AUTO_TEST_CASE(UnknownOnlyHistoryDoesNotWarmUpSmartEstimates)
{
    ChunkEstimatorHarness test;
    const auto unknown = MakeChunk(0);
    test.Update(100, {}, {unknown});
    test.Block(101, {unknown}); // Ends without a usable confirmation or a known miss.
    for (unsigned int height{102}; height <= 120; ++height) test.Block(height);

    std::vector<MemPoolChunk> confirmed;
    for (uint64_t id{1}; id <= 20; ++id) confirmed.push_back(MakeChunk(id, 100, 400));
    test.Update(120, {}, confirmed);
    test.Confirm(121, confirmed);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(2, .95, FeeEstimateHorizon::SHORT_HALFLIFE).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(2, nullptr, false).GetFeePerK(), 0);

    // Smart estimates require four blocks of history after the first known
    // outcome. The preceding unknown-only history must not satisfy that gate.
    for (unsigned int height{122}; height <= 124; ++height) {
        test.Block(height);
        BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(2, nullptr, false).GetFeePerK(), 0);
    }
    test.Block(125);
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(2, nullptr, false).GetFeePerK(), 1000);
}

BOOST_AUTO_TEST_CASE(SmartEstimateOrderingAcrossHorizons)
{
    ChunkEstimatorHarness test;
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(1008, nullptr, false).GetFeePerK(), 0);
    std::vector<MemPoolChunk> expensive, cheap;
    for (uint64_t id = 0; id < 1000; ++id) {
        expensive.push_back(MakeChunk(id, 1000, 400));
        cheap.push_back(MakeChunk(id + 1000, 100, 400));
    }
    test.Update(100, {}, expensive);
    test.Confirm(101, expensive);
    for (unsigned int height = 102; height <= 2200; ++height) test.Block(height);
    test.Update(2200, {}, cheap);
    test.Confirm(2201, cheap);
    for (unsigned int height = 2202; height <= 2204; ++height) test.Block(height);

    // Exercise both sides of the half/actual/double component horizon switches,
    // including targets that require medium or long history.
    for (const bool conservative : {false, true}) {
        CAmount previous = std::numeric_limits<CAmount>::max();
        for (const int target : {2, 3, 4, 6, 7, 12, 13, 24, 25, 48, 49, 96, 97, 504, 505, 1008}) {
            FeeCalculation calc;
            const auto fee = test.estimator.estimateSmartFee(target, &calc, conservative).GetFeePerK();
            BOOST_CHECK_GT(fee, 0);
            BOOST_CHECK_LE(fee, previous);
            BOOST_CHECK_EQUAL(calc.desiredTarget, target);
            BOOST_CHECK_LE(calc.returnedTarget, target);
            if (conservative) BOOST_CHECK_GE(fee, test.estimator.estimateSmartFee(target, nullptr, false).GetFeePerK());
            previous = fee;
        }
    }
    FeeCalculation calc;
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(1, &calc, false).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(calc.desiredTarget, 1);
    BOOST_CHECK_EQUAL(calc.returnedTarget, 2);
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(1009, nullptr, false).GetFeePerK(), 0);
}

BOOST_AUTO_TEST_CASE(ConservativeEstimateWithUnavailableLongerRows)
{
    ChunkEstimatorHarness test;
    const std::vector<MemPoolChunk> warmup{MakeChunk(0, 100, 400)};
    test.Update(80, {}, warmup);
    test.Confirm(81, warmup);
    for (unsigned int height = 82; height <= 111; ++height) test.Block(height);

    // Fourteen successes support the short horizon, but not the larger sample
    // requirements of either longer horizon. Both modes must retain the quote.
    std::vector<MemPoolChunk> cheap;
    for (uint64_t id = 1; id <= 14; ++id) cheap.push_back(MakeChunk(id, 100, 400));
    test.Update(111, {}, cheap);
    test.Confirm(112, cheap);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(3, .60, FeeEstimateHorizon::SHORT_HALFLIFE).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(7, .85, FeeEstimateHorizon::SHORT_HALFLIFE).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(12, .95, FeeEstimateHorizon::SHORT_HALFLIFE).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(14, .95, FeeEstimateHorizon::MED_HALFLIFE).GetFeePerK(), 0);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(14, .95, FeeEstimateHorizon::LONG_HALFLIFE).GetFeePerK(), 0);
    FeeCalculation economical, conservative;
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(7, &economical, false).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(7, &conservative, true).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(conservative.desiredTarget, 7);
    BOOST_CHECK_EQUAL(conservative.returnedTarget, 7);
    BOOST_CHECK_EQUAL(conservative.est.pass.success, economical.est.pass.success);
}

BOOST_AUTO_TEST_CASE(ConservativeEstimateRetainsLongerHistory)
{
    ChunkEstimatorHarness test;
    std::vector<MemPoolChunk> expensive, cheap;
    for (uint64_t id = 0; id < 200; ++id) expensive.push_back(MakeChunk(id, 1000, 400));
    for (uint64_t id = 200; id < 240; ++id) cheap.push_back(MakeChunk(id, 100, 400));
    test.Update(100, {}, expensive);
    test.Confirm(101, expensive);
    for (unsigned int height = 102; height <= 120; ++height) test.Block(height);
    test.Update(120, {}, cheap);
    test.Confirm(121, cheap);

    // The new cheap successes support the short and medium horizons at once.
    // The long horizon still needs the older expensive population for support.
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(6, .95, FeeEstimateHorizon::SHORT_HALFLIFE).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(14, .95, FeeEstimateHorizon::MED_HALFLIFE).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(14, .95, FeeEstimateHorizon::LONG_HALFLIFE).GetFeePerK(), 10000);
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(7, nullptr, false).GetFeePerK(), 1000);
    BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(7, nullptr, true).GetFeePerK(), 10000);
    CAmount previous_economical{std::numeric_limits<CAmount>::max()};
    CAmount previous_conservative{std::numeric_limits<CAmount>::max()};
    for (int target = 2; target <= 10; ++target) {
        const auto economical_rate = test.estimator.estimateSmartFee(target, nullptr, false).GetFeePerK();
        const auto conservative_rate = test.estimator.estimateSmartFee(target, nullptr, true).GetFeePerK();
        BOOST_CHECK_GT(economical_rate, 0);
        BOOST_CHECK_GE(conservative_rate, economical_rate);
        BOOST_CHECK_LE(economical_rate, previous_economical);
        BOOST_CHECK_LE(conservative_rate, previous_conservative);
        previous_economical = economical_rate;
        previous_conservative = conservative_rate;
    }
}

BOOST_AUTO_TEST_CASE(SmartEstimateZeroRateUsesUnavailableFallback)
{
    ChunkEstimatorHarness test;
    std::vector<MemPoolChunk> older, expensive, free_chunks;
    for (uint64_t id = 0; id < 200; ++id) older.push_back(MakeChunk(id, 500, 400));
    for (uint64_t id = 200; id < 214; ++id) expensive.push_back(MakeChunk(id, 1000, 400));
    for (uint64_t id = 214; id < 234; ++id) free_chunks.push_back(MakeChunk(id, 0, 400));
    test.Update(1, {}, older);
    test.Confirm(2, older);
    for (unsigned int height = 3; height <= 100; ++height) test.Block(height);
    test.Update(100, {}, expensive);
    test.Confirm(101, expensive);
    test.Block(102);
    test.Update(102, {}, free_chunks);
    test.Confirm(103, free_chunks);
    for (unsigned int height = 104; height <= 106; ++height) test.Block(height);

    // The recent zero-rate population supports the short horizon immediately.
    // Zero is unavailable to selection, so both modes must use the positive
    // longer-history fallback rather than return an unusable zero quote.
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(4, .95, FeeEstimateHorizon::SHORT_HALFLIFE).GetFeePerK(), 0);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(6, .95, FeeEstimateHorizon::SHORT_HALFLIFE).GetFeePerK(), 0);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(4, .95, FeeEstimateHorizon::LONG_HALFLIFE).GetFeePerK(), 5000);
    for (bool mode : {false, true}) {
        FeeCalculation calc;
        BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(2, &calc, mode).GetFeePerK(), 5000);
        BOOST_CHECK(calc.reason == BlockPolicyEstimateReason::CONSERVATIVE);
        BOOST_CHECK_EQUAL(test.estimator.estimateSmartFee(3, &calc, mode).GetFeePerK(), 5000);
        BOOST_CHECK_EQUAL(calc.desiredTarget, 3);
        BOOST_CHECK_EQUAL(calc.returnedTarget, 3);
    }
}

BOOST_AUTO_TEST_CASE(ChunkFullConfirmation)
{
    ChunkEstimatorHarness test;
    const auto chunk = MakeChunk(1);
    test.Update(100, {}, {chunk});
    test.Confirm(101, {chunk});
    const auto counts = test.Counts();
    BOOST_CHECK_EQUAL(counts.total, 1);
    BOOST_CHECK_EQUAL(counts.success, 1);
    BOOST_CHECK_EQUAL(counts.pending, 0);
    BOOST_CHECK_EQUAL(counts.failure, 0);
}

BOOST_AUTO_TEST_CASE(ChunkPartialConfirmationAndSurvivorAge)
{
    ChunkEstimatorHarness test;
    const auto parent_child = MakeChunk(1);
    const auto child = MakeChunk(2);
    test.Update(100, {}, {parent_child});
    // Only the parent was mined. There is no full-confirmation evidence for
    // the old chunk; the surviving child starts a new observation at 101.
    auto block = test.MakeUpdate(101, {parent_child}, {child}, MemPoolUpdateCause::BLOCK);
    block.ending_reasons.emplace(parent_child.m_chunk_hash, MemPoolChunkEndReason::PARTIAL_CONFIRMATION);
    test.Send(block);
    BOOST_CHECK_EQUAL(test.Counts().total, 1);
    BOOST_CHECK_EQUAL(test.Counts().failure, 0);
    BOOST_CHECK_EQUAL(test.Counts().unknown, 1);
    test.Confirm(102, {child});
    BOOST_CHECK_CLOSE_FRACTION(test.Counts().total, 1 + .962, 1e-12);
    BOOST_CHECK_EQUAL(test.Counts().success, 1);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts().unknown, .962, 1e-12);
}

BOOST_AUTO_TEST_CASE(UnchangedChunkRetainsAge)
{
    ChunkEstimatorHarness test;
    const auto chunk = MakeChunk(1);
    test.Update(100, {}, {chunk});
    test.Block(101);
    test.Update(101, {chunk}, {chunk});
    BOOST_CHECK_EQUAL(test.Counts().pending, 1);
    BOOST_CHECK_EQUAL(test.Counts().failure, 1);
    test.Confirm(102, {chunk});
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(1).total, .962, 1e-12);
    BOOST_CHECK_EQUAL(test.Counts(1).success, 0);
    BOOST_CHECK_EQUAL(test.Counts(2).success, 1);
}

BOOST_AUTO_TEST_CASE(UnchangedChunkInBlockUpdateIsNotConfirmed)
{
    ChunkEstimatorHarness test;
    const auto survivor = MakeChunk(1);
    const auto mined = MakeChunk(2);
    test.Update(100, {}, {survivor, mined});
    test.Block(101, {survivor, mined}, {survivor}, {mined.m_chunk_hash});
    BOOST_CHECK_EQUAL(test.Counts().total, 2);
    BOOST_CHECK_EQUAL(test.Counts().pending, 1);
    BOOST_CHECK_EQUAL(test.Counts().failure, 1);
    test.Confirm(102, {survivor});
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(1).total, 2 * .962, 1e-12);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(1).success, .962, 1e-12);
    // The first confirmation was credited at 101 and has decayed for one block.
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(2).success, 1 + .962, 1e-12);
}

BOOST_AUTO_TEST_CASE(ChangedFeeStartsNewObservation)
{
    ChunkEstimatorHarness test;
    const auto original = MakeChunk(1);
    auto changed = original;
    changed.m_fee_rate.fee *= 2;
    test.Update(100, {}, {original});
    test.Block(101);
    test.Update(101, {original}, {changed}, MemPoolUpdateCause::PRIORITISATION);
    BOOST_CHECK_EQUAL(test.Counts().failure, 1);
    test.Confirm(102, {changed});
    BOOST_CHECK_CLOSE_FRACTION(test.Counts().total, 1 + .962, 1e-12);
    BOOST_CHECK_EQUAL(test.Counts().success, 1);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
}

BOOST_AUTO_TEST_CASE(ChangedWeightStartsNewObservation)
{
    ChunkEstimatorHarness test;
    const auto original = MakeChunk(1);
    auto changed = original;
    changed.m_fee_rate.fee *= 2;
    changed.m_fee_rate.size *= 2;
    test.Update(100, {}, {original});
    test.Block(101);
    // Equal ratios alone do not establish an unchanged observation.
    test.Update(101, {original}, {changed});
    test.Confirm(102, {changed});
    BOOST_CHECK_CLOSE_FRACTION(test.Counts().total, 1 + .962, 1e-12);
    BOOST_CHECK_EQUAL(test.Counts().success, 1);
}

BOOST_AUTO_TEST_CASE(EligibilityTransitions)
{
    ChunkEstimatorHarness test;
    const auto eligible = MakeChunk(1);
    auto ineligible = eligible;
    ineligible.m_fee_estimation_eligible = false;
    test.Update(100, {}, {eligible});
    test.Block(101);
    test.Update(101, {eligible}, {ineligible}, MemPoolUpdateCause::PRIORITISATION);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
    BOOST_CHECK_EQUAL(test.Counts().failure, 1);
    test.Block(102);
    test.Update(102, {ineligible}, {eligible}, MemPoolUpdateCause::PRIORITISATION);
    test.Confirm(103, {eligible});
    BOOST_CHECK_CLOSE_FRACTION(test.Counts().total, 1 + .962 * .962, 1e-12);
    BOOST_CHECK_EQUAL(test.Counts().success, 1);
}

BOOST_AUTO_TEST_CASE(AdmissionRequiresEligibilityAndCurrentContext)
{
    ChunkEstimatorHarness test;
    const auto ineligible = MakeChunk(1, 2000, 800, false);
    const auto stale = MakeChunk(2);
    test.Update(100, {}, {ineligible});
    test.Update(100, {}, {stale}, MemPoolUpdateCause::TRANSACTIONS, {}, false);
    test.Confirm(101, {ineligible, stale});
    BOOST_CHECK_EQUAL(test.Counts().total, 0);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
    BOOST_CHECK_EQUAL(test.Counts().failure, 0);
}

BOOST_AUTO_TEST_CASE(UnknownContextCancelsAffectedObservations)
{
    ChunkEstimatorHarness test;
    const auto chunk = MakeChunk(1);
    const auto unknown = MakeChunk(2);
    test.Update(100, {}, {chunk});
    test.Update(std::nullopt, {chunk}, {chunk, unknown});
    test.Confirm(101, {chunk, unknown});
    BOOST_CHECK_EQUAL(test.Counts().total, 0);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
    BOOST_CHECK_EQUAL(test.Counts().failure, 0);
}

BOOST_AUTO_TEST_CASE(ZeroAgeConfirmationStillRetiresObservation)
{
    ChunkEstimatorHarness test;
    const auto chunk = MakeChunk(1);
    test.Update(100, {}, {chunk});
    test.Confirm(100, {chunk});
    test.Block(101);
    BOOST_CHECK_EQUAL(test.Counts().total, 0);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
    BOOST_CHECK_EQUAL(test.Counts().failure, 0);
}

BOOST_AUTO_TEST_CASE(StaleBlockContextCannotRecordSuccess)
{
    ChunkEstimatorHarness test;
    const auto chunk = MakeChunk(1);
    test.Update(100, {}, {chunk});
    test.Update(101, {chunk}, {}, MemPoolUpdateCause::BLOCK, {chunk.m_chunk_hash}, false);
    test.Block(102);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts().unknown, .962, 1e-12);
    BOOST_CHECK_EQUAL(test.Counts().success, 0);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
}

BOOST_AUTO_TEST_CASE(RemovalPreservesOnlyElapsedFailures)
{
    ChunkEstimatorHarness test;
    const auto chunk = MakeChunk(1);
    test.Update(100, {}, {chunk});
    test.Block(101);
    // Losing current-chain eligibility does not erase the one deadline already
    // observed at this same height, nor invent a second missed deadline.
    test.Update(101, {chunk}, {}, MemPoolUpdateCause::REMOVAL, {}, false);
    BOOST_CHECK_EQUAL(test.Counts(1).failure, 1);
    BOOST_CHECK_EQUAL(test.Counts(2).failure, 0);
    BOOST_CHECK_EQUAL(test.Counts().total, 1);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
    test.Block(102);
    BOOST_CHECK_EQUAL(test.Counts(2).unknown, 1);
}

BOOST_AUTO_TEST_CASE(ConfirmationAtEveryRingBoundary)
{
    const std::array horizons{
        std::pair{FeeEstimateHorizon::SHORT_HALFLIFE, 12U},
        std::pair{FeeEstimateHorizon::MED_HALFLIFE, 48U},
        std::pair{FeeEstimateHorizon::LONG_HALFLIFE, 1008U},
    };
    for (const auto& [horizon, window] : horizons) {
        ChunkEstimatorHarness test;
        const auto chunk = MakeChunk(1);
        test.Update(100, {}, {chunk});
        for (unsigned int height = 101; height < 100 + window; ++height) test.Block(height);
        test.Confirm(100 + window, {chunk});
        const auto counts = test.Counts(window, horizon);
        BOOST_CHECK_EQUAL(counts.total, 1);
        BOOST_CHECK_EQUAL(counts.success, 1);
        BOOST_CHECK_EQUAL(counts.pending, 0);
        BOOST_CHECK_EQUAL(counts.failure, 0);
        test.Block(101 + window);
        BOOST_CHECK_EQUAL(test.Counts(window, horizon).pending, 0);
    }
}

BOOST_AUTO_TEST_CASE(HeightGapCancelsPendingWithoutInventingOutcomes)
{
    ChunkEstimatorHarness test;
    const auto lost = MakeChunk(1);
    const auto fresh = MakeChunk(2);
    test.Update(100, {}, {lost});
    // Heights 101 and 102 were not observed; the old wait is no longer usable.
    test.Block(103, {lost}, {fresh}, {lost.m_chunk_hash});
    BOOST_CHECK_EQUAL(test.Counts().total, 0);
    BOOST_CHECK_EQUAL(test.Counts().failure, 0);
    test.Confirm(104, {fresh});
    BOOST_CHECK_EQUAL(test.Counts().total, 1);
    BOOST_CHECK_EQUAL(test.Counts().success, 1);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
}

BOOST_AUTO_TEST_CASE(SequenceGapsDuplicatesAndOlderEvents)
{
    ChunkEstimatorHarness test;
    const auto lost = MakeChunk(1);
    const auto fresh = MakeChunk(2);
    const auto first = test.MakeUpdate(100, {}, {lost});
    test.Send(first);
    test.Send(first); // Duplicate publication must not start another observation.

    const auto old = test.MakeUpdate(101, {lost}, {}, MemPoolUpdateCause::BLOCK, {lost.m_chunk_hash});
    const auto after_gap = test.MakeUpdate(100, {}, {fresh});
    test.Send(after_gap); // Sequence 2 was not delivered: cancel pending state.
    test.Send(old);       // A late sequence 2 cannot change the now-current state.
    test.Confirm(101, {lost, fresh});
    BOOST_CHECK_EQUAL(test.Counts().total, 1);
    BOOST_CHECK_EQUAL(test.Counts().success, 1);
    BOOST_CHECK_EQUAL(test.Counts().failure, 0);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
}

BOOST_AUTO_TEST_CASE(ReorgColdResetDropsHistoryAndRestartsClocks)
{
    ChunkEstimatorHarness test;
    const auto mined = MakeChunk(1), pending = MakeChunk(2);
    test.Update(100, {}, {mined});
    test.Confirm(101, {mined});
    test.Update(101, {}, {pending});
    BOOST_CHECK_EQUAL(test.Counts(1).success, 1);
    auto reset = test.MakeUpdate(99, {pending}, {pending}, MemPoolUpdateCause::REORG);
    reset.reset_observations = true;
    test.Send(reset);
    BOOST_CHECK_EQUAL(test.Counts().total, 0);
    BOOST_CHECK_EQUAL(test.Counts().pending, 1);
    test.Block(100);
    test.Confirm(101, {pending});
    BOOST_CHECK_EQUAL(test.Counts(1).success, 0);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(1).failure, .962, 1e-12);
    BOOST_CHECK_EQUAL(test.Counts(2).success, 1);
}

BOOST_AUTO_TEST_CASE(PersistenceRoundTripClearsRuntimeObservations)
{
    ChunkEstimatorHarness test;
    const auto confirmed = MakeChunk(1);
    const auto pending = MakeChunk(2);
    test.Update(100, {}, {confirmed});
    test.Confirm(101, {confirmed});
    test.Update(101, {}, {pending});
    test.Block(102);
    BOOST_CHECK_EQUAL(test.Counts().pending, 1);
    const double saved_confirmed = test.Counts().total;

    AutoFile file{std::tmpfile()};
    BOOST_REQUIRE(!file.IsNull());
    BOOST_REQUIRE(test.estimator.Write(file));
    file.seek(0, SEEK_SET);
    int version;
    file >> version;
    BOOST_CHECK_EQUAL(version, 309904);
    file.seek(0, SEEK_SET);

    BOOST_REQUIRE(test.estimator.Read(file));
    test.estimator.SanityCheck();
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts().total, saved_confirmed, 1e-12);

    // Live identities are not resumed; future target outcomes remain unknown.
    test.Confirm(103, {pending});
    BOOST_CHECK_CLOSE_FRACTION(test.Counts().total, saved_confirmed * .962, 1e-12);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
    BOOST_REQUIRE_EQUAL(file.fclose(), 0);
}

BOOST_AUTO_TEST_CASE(PreviousModelFilesAreRejectedWithoutChangingRuntimeState)
{
    ChunkEstimatorHarness test;
    const auto chunk = MakeChunk(1);
    test.Update(100, {}, {chunk});
    test.Block(101);
    for (const int version : {309900, 309902, 309903}) {
        AutoFile file{std::tmpfile()};
        BOOST_REQUIRE(!file.IsNull());
        BOOST_REQUIRE(test.estimator.Write(file));
        file.seek(0, SEEK_SET);
        file << version;
        file.seek(0, SEEK_SET);
        BOOST_CHECK(!test.estimator.Read(file));
        test.estimator.SanityCheck();
        BOOST_CHECK_EQUAL(test.Counts().pending, 1);
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }
    test.Confirm(102, {chunk});
    BOOST_CHECK_EQUAL(test.Counts(2).total, 1);
    BOOST_CHECK_EQUAL(test.Counts(2).success, 1);
}

BOOST_AUTO_TEST_CASE(MalformedChunkEconomicsAreIgnored)
{
    ChunkEstimatorHarness test;
    const std::vector<MemPoolChunk> malformed{
        MakeChunk(1, std::numeric_limits<CAmount>::max()),
        MakeChunk(2, -1),
        MakeChunk(3, 2000, 0),
        MakeChunk(4, 2000, -1),
    };
    test.Update(100, {}, malformed);
    test.Block(101);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);
    test.Confirm(102, malformed);
    BOOST_CHECK_EQUAL(test.Counts().total, 0);
    BOOST_CHECK_EQUAL(test.Counts().failure, 0);
    BOOST_CHECK_EQUAL(test.Counts().pending, 0);

    const auto valid = MakeChunk(5);
    test.Update(102, {}, {valid});
    test.Confirm(103, {valid});
    BOOST_CHECK_EQUAL(test.Counts().total, 1);
    BOOST_CHECK_EQUAL(test.Counts().success, 1);
}

BOOST_AUTO_TEST_CASE(EarlyEndingsRemainUnknownForLaterTargets)
{
    ChunkEstimatorHarness test;
    std::vector<MemPoolChunk> all, withdrawn, survivors;
    for (uint64_t i{1}; i <= 1000; ++i) {
        all.push_back(MakeChunk(i));
        (i <= 900 ? withdrawn : survivors).push_back(all.back());
    }
    test.Update(100, {}, all);
    test.Block(101);
    test.Update(101, withdrawn, {}, MemPoolUpdateCause::REMOVAL);
    for (unsigned int h{102}; h < 106; ++h) test.Block(h);
    BOOST_CHECK_EQUAL(test.Counts(6).total, 0);
    test.Confirm(106, survivors);
    const auto c = test.Counts(6);
    BOOST_CHECK_EQUAL(c.total, 1000);
    BOOST_CHECK_EQUAL(c.success, 100);
    BOOST_CHECK_EQUAL(c.failure, 0);
    BOOST_CHECK_EQUAL(c.unknown, 900);
    EstimationResult stats;
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(6, .95, FeeEstimateHorizon::SHORT_HALFLIFE, &stats).GetFeePerK(), 10000);
    BOOST_CHECK_EQUAL(stats.pass.success, 100);
    BOOST_CHECK_EQUAL(stats.pass.Unknown(), 900);
    BOOST_CHECK_CLOSE_FRACTION(stats.all.Lower(), .1, 1e-12);
    BOOST_CHECK_EQUAL(stats.all.Upper(), 1);
    BOOST_CHECK_EQUAL(stats.all.unknown[static_cast<size_t>(MemPoolChunkEndReason::REPLACED)], 900);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(1).failure, 1000 * std::pow(.962, 5), 1e-12);
    BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(1, .95, FeeEstimateHorizon::SHORT_HALFLIFE).GetFeePerK(), 0);
}

BOOST_AUTO_TEST_CASE(MissedDeadlineWeightIgnoresLaterEnding)
{
    ChunkEstimatorHarness early, late, pending, confirmed;
    const auto a = MakeChunk(1);
    for (auto* test : {&early, &late, &pending, &confirmed}) {
        test->Update(100, {}, {a});
        test->Block(101);
    }
    early.Update(101, {a}, {}, MemPoolUpdateCause::REMOVAL);
    for (unsigned int h{102}; h <= 110; ++h) {
        early.Block(h);
        late.Block(h);
        pending.Block(h);
        if (h == 110) confirmed.Confirm(h, {a}); else confirmed.Block(h);
    }
    late.Update(110, {a}, {}, MemPoolUpdateCause::REMOVAL);
    for (const auto* test : {&early, &late, &pending, &confirmed}) {
        BOOST_CHECK_CLOSE_FRACTION(test->Counts(1).failure, std::pow(.962, 9), 1e-12);
        BOOST_CHECK_CLOSE_FRACTION(test->Counts(1).total, std::pow(.962, 9), 1e-12);
    }
    BOOST_CHECK_EQUAL(confirmed.Counts(10).success, 1);
    BOOST_CHECK_EQUAL(late.Counts(10).failure, 1);
    BOOST_CHECK_CLOSE_FRACTION(early.Counts(6).unknown, std::pow(.962, 4), 1e-12);
}

BOOST_AUTO_TEST_CASE(EarlySuccessImmediatelySupportsLongerTargets)
{
    ChunkEstimatorHarness test;
    std::vector<MemPoolChunk> chunks;
    for (uint64_t id = 0; id < 200; ++id) chunks.push_back(MakeChunk(id, 100, 400));
    test.Update(100, {}, chunks);
    test.Confirm(101, chunks);
    for (const auto& [target, horizon] : std::array{
             std::pair{6, FeeEstimateHorizon::SHORT_HALFLIFE},
             std::pair{48, FeeEstimateHorizon::MED_HALFLIFE},
             std::pair{1008, FeeEstimateHorizon::LONG_HALFLIFE}}) {
        BOOST_CHECK_EQUAL(test.Counts(target, horizon).success, 200);
        BOOST_CHECK_EQUAL(test.Counts(target, horizon).pending, 0);
        BOOST_CHECK_EQUAL(test.estimator.estimateRawFee(target, .95, horizon).GetFeePerK(), 1000);
    }

    // Passing the original deadline must only decay, not record success again.
    for (unsigned int h{102}; h <= 106; ++h) test.Block(h);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(6).success, 200 * std::pow(.962, 5), 1e-12);
}

BOOST_AUTO_TEST_CASE(AmbiguousBlockPreservesOnlyEarlierMisses)
{
    for (auto reason : {MemPoolChunkEndReason::UNSEEN_SPONSOR, MemPoolChunkEndReason::PARTIAL_CONFIRMATION, MemPoolChunkEndReason::BLOCK_CONFLICT}) {
        ChunkEstimatorHarness test;
        const auto chunk = MakeChunk(1);
        test.Update(100, {}, {chunk});
        test.Block(101);
        auto update = test.MakeUpdate(102, {chunk}, {}, MemPoolUpdateCause::BLOCK, {chunk.m_chunk_hash});
        update.ending_reasons.emplace(chunk.m_chunk_hash, reason);
        test.Send(update);
        BOOST_CHECK_CLOSE_FRACTION(test.Counts(1).failure, .962, 1e-12);
        BOOST_CHECK_EQUAL(test.Counts(2).success, 0);
        BOOST_CHECK_EQUAL(test.Counts(2).failure, 0);
        BOOST_CHECK_EQUAL(test.Counts(2).unknown, 1);
    }
}

BOOST_AUTO_TEST_CASE(EachEndingReasonRetainsUnknownTargets)
{
    for (size_t i{1}; i < NUM_CHUNK_END_REASONS; ++i) {
        ChunkEstimatorHarness test;
        const auto chunk = MakeChunk(1);
        test.Update(100, {}, {chunk});
        test.Block(101);
        auto update = test.MakeUpdate(101, {chunk}, {});
        update.ending_reasons.emplace(chunk.m_chunk_hash, static_cast<MemPoolChunkEndReason>(i));
        test.Send(update);
        test.Block(102);
        EstimationResult stats;
        test.estimator.estimateRawFee(2, .95, FeeEstimateHorizon::SHORT_HALFLIFE, &stats);
        BOOST_CHECK_EQUAL(stats.all.unknown[i], 1);
        BOOST_CHECK_EQUAL(stats.endings[i], 1U);
        BOOST_CHECK_CLOSE_FRACTION(test.Counts(1).failure, .962, 1e-12);
    }
}

BOOST_AUTO_TEST_CASE(ObservationGapPreservesPastMissAndUnknownFuture)
{
    ChunkEstimatorHarness test;
    const auto chunk = MakeChunk(1);
    test.Update(100, {}, {chunk});
    test.Block(101);
    // Missing heights do not establish a new failure or confirmation.
    test.Confirm(106, {chunk});
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(1).failure, std::pow(.962, 5), 1e-12);
    BOOST_CHECK_EQUAL(test.Counts(6).unknown, 1);
    BOOST_CHECK_EQUAL(test.Counts(6).success, 0);
}

BOOST_AUTO_TEST_CASE(PersistenceRetainsImmediateSuccessAndFutureUnknown)
{
    ChunkEstimatorHarness test;
    const auto success = MakeChunk(1), pending = MakeChunk(2), newborn = MakeChunk(3);
    test.Update(100, {}, {success, pending});
    test.Confirm(101, {success});
    test.Update(101, {}, {newborn});
    AutoFile file{std::tmpfile()};
    BOOST_REQUIRE(test.estimator.Write(file));
    // Saving only changes the persisted view, including zero-opportunity samples.
    BOOST_CHECK_EQUAL(test.Counts().pending, 2);
    file.seek(0, SEEK_SET);
    BOOST_REQUIRE(test.estimator.Read(file));
    test.estimator.SanityCheck();
    for (unsigned int h{102}; h <= 106; ++h) test.Block(h);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(6).success, std::pow(.962, 5), 1e-12);
    BOOST_CHECK_EQUAL(test.Counts(6).unknown, 1);
    BOOST_CHECK_EQUAL(test.Counts(6).failure, 0);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(1).success, std::pow(.962, 5), 1e-12);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(1).failure, std::pow(.962, 5), 1e-12);
    test.Block(107);
    // The newborn had no block opportunity before the save; it must not add U.
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(6).unknown, .962, 1e-12);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(6).success, std::pow(.962, 6), 1e-12);
    BOOST_REQUIRE_EQUAL(file.fclose(), 0);
}

BOOST_AUTO_TEST_CASE(CohortRetentionIsBoundedAndScaledDeadlinesAreExact)
{
    ChunkEstimatorHarness test;
    const auto chunk = MakeChunk(1);
    test.Update(100, {}, {chunk});
    for (unsigned int h{101}; h <= 1110; ++h) test.Block(h);
    EstimationResult stats;
    test.estimator.estimateRawFee(1008, .95, FeeEstimateHorizon::LONG_HALFLIFE, &stats);
    BOOST_CHECK_EQUAL(stats.cohort_heights, 0U);
    BOOST_CHECK_EQUAL(stats.active_observations, 1U);
    BOOST_CHECK_CLOSE_FRACTION(stats.all.failure, std::pow(.99931, 2), 1e-12);
    test.Update(1110, {chunk}, {}, MemPoolUpdateCause::REMOVAL);
    BOOST_CHECK_CLOSE_FRACTION(test.Counts(1008, FeeEstimateHorizon::LONG_HALFLIFE).failure, std::pow(.99931, 2), 1e-12);
}

BOOST_AUTO_TEST_CASE(AggregatedCohortsMatchIndividualEpisodeReference)
{
    struct Episode {
        MemPoolChunk chunk;
        unsigned int start;
        unsigned int end;
        bool confirms;
    };
    std::vector<Episode> episodes;
    for (unsigned int i{0}; i < 80; ++i) {
        const unsigned int start = 100 + i % 20;
        const unsigned int duration = i % 17;
        episodes.push_back({MakeChunk(2000 + i), start, start + duration, duration != 0 && i % 3 == 0});
    }
    ChunkEstimatorHarness test;
    test.Update(100);
    for (unsigned int height{100}; height <= 200; ++height) {
        std::vector<MemPoolChunk> added, removed, confirmed;
        for (const auto& e : episodes) {
            if (e.start == height) added.push_back(e.chunk);
            if (e.end == height) (e.confirms ? confirmed : removed).push_back(e.chunk);
        }
        if (height > 100) test.Confirm(height, confirmed);
        if (!added.empty()) test.Update(height, {}, added);
        if (!removed.empty()) test.Update(height, removed, {}, MemPoolUpdateCause::REMOVAL);
        for (const auto& [target, horizon, decay] : std::array{
                 std::tuple{1U, FeeEstimateHorizon::SHORT_HALFLIFE, .962},
                 std::tuple{6U, FeeEstimateHorizon::SHORT_HALFLIFE, .962},
                 std::tuple{2U, FeeEstimateHorizon::MED_HALFLIFE, .9952},
                 std::tuple{48U, FeeEstimateHorizon::MED_HALFLIFE, .9952},
                 std::tuple{24U, FeeEstimateHorizon::LONG_HALFLIFE, .99931},
                 std::tuple{72U, FeeEstimateHorizon::LONG_HALFLIFE, .99931}}) {
            double success{0}, failure{0}, unknown{0};
            for (const auto& e : episodes) {
                const auto deadline = e.start + target;
                if (e.end == e.start) continue;
                if (e.confirms && e.end <= deadline) {
                    if (height >= e.end) success += std::pow(decay, height - e.end);
                    continue;
                }
                if (height < deadline) continue;
                const auto weight = std::pow(decay, height - deadline);
                if (!e.confirms && e.end < deadline) unknown += weight;
                else failure += weight;
            }
            const auto actual = test.Counts(target, horizon);
            BOOST_CHECK_SMALL(actual.success - success, 1e-10);
            BOOST_CHECK_SMALL(actual.failure - failure, 1e-10);
            BOOST_CHECK_SMALL(actual.unknown - unknown, 1e-10);
            BOOST_CHECK_SMALL(actual.total - success - failure - unknown, 1e-10);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
