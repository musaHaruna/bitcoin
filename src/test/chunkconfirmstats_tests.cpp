// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <kernel/mempool_removal_reason.h>
#include <policy/fees/chunk_confirm_stats.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>

#include <cstdio>
#include <map>
#include <vector>

namespace {
struct StatsFixture {
    const std::vector<double> buckets{1000, 2000, 1e99};
    const std::map<double, unsigned int> bucket_map{{1000, 0}, {2000, 1}, {1e99, 2}};
    ChunkConfirmStats stats{buckets, bucket_map, /*periods=*/4, /*decay=*/0.5, /*scale=*/1};

    ChunkConfirmStats::Result At(unsigned int target) const
    {
        ChunkConfirmStats::Result result;
        stats.EstimateMedianVal(target, /*sufficient=*/0.01, /*threshold=*/0.95, &result);
        return result;
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(chunkconfirmstats_tests, StatsFixture)

BOOST_AUTO_TEST_CASE(confirmations_enter_immediately_other_outcomes_at_deadlines)
{
    const auto bucket = stats.NewChunk(100, 1000);
    stats.NewChunk(100, 1000);
    stats.NewChunk(100, 1000);
    stats.EndChunk(100, 101, bucket, 1000, MemPoolChunkEndReason::CONFIRMED);
    stats.EndChunk(100, 101, bucket, 1000, MemPoolChunkEndReason::EXPIRY);
    BOOST_CHECK_EQUAL(At(1).all.success, 1);
    BOOST_CHECK_EQUAL(At(2).all.success, 1);
    BOOST_CHECK_EQUAL(At(4).all.success, 1);
    BOOST_CHECK(stats.Mature(100, 101));
    const auto first = At(1).all;
    BOOST_CHECK_EQUAL(first.success, 1);
    BOOST_CHECK_EQUAL(first.failure, 1);
    BOOST_CHECK_EQUAL(first.Unknown(), 1);
    BOOST_CHECK_CLOSE_FRACTION(first.Lower(), 1.0 / 3, 1e-12);
    BOOST_CHECK_CLOSE_FRACTION(first.Upper(), 2.0 / 3, 1e-12);
    BOOST_CHECK_EQUAL(At(2).all.Total(), 1);

    // A later confirmation changes target two, but not the established miss at one.
    stats.UpdateMovingAverages(1);
    stats.EndChunk(100, 102, bucket, 1000, MemPoolChunkEndReason::CONFIRMED);
    BOOST_CHECK(!stats.Mature(101, 102));
    BOOST_CHECK_EQUAL(At(1).all.failure, 0.5);
    BOOST_CHECK_EQUAL(At(1).all.success, 0.5);
    BOOST_CHECK_EQUAL(At(2).all.success, 1.5);
    BOOST_CHECK_EQUAL(At(2).all.failure, 0);
    BOOST_CHECK_EQUAL(At(2).all.Unknown(), 1);
    BOOST_CHECK_EQUAL(stats.EstimateMedianVal(2, 0.01, 0.95, nullptr), 1000);
    BOOST_CHECK_EQUAL(stats.EstimateMedianVal(1, 0.01, 0.95, nullptr), -1);
    BOOST_CHECK_EQUAL(stats.EstimateMedianVal(1, 0.01, 0.50, nullptr), 1000);
}

BOOST_AUTO_TEST_CASE(unknown_endings_do_not_change_known_outcome_fees)
{
    const auto bucket = stats.NewChunk(100, 900);
    BOOST_REQUIRE_EQUAL(stats.NewChunk(100, 1000), bucket);
    BOOST_REQUIRE_EQUAL(stats.NewChunk(100, 600), bucket);
    stats.EndChunk(100, 101, bucket, 900, MemPoolChunkEndReason::CONFIRMED);
    stats.EndChunk(100, 101, bucket, 600, MemPoolChunkEndReason::EXPIRY);
    stats.Mature(100, 101);
    BOOST_CHECK_EQUAL(stats.EstimateMedianVal(2, 0.01, 0.95, nullptr), 900);
    BOOST_CHECK_EQUAL(stats.EstimateMedianVal(1, 0.01, 0.50, nullptr), 950);

    stats.UpdateMovingAverages(1);
    stats.EndChunk(100, 102, bucket, 1000, MemPoolChunkEndReason::CONFIRMED);
    stats.Mature(101, 102);
    // The unknown remains visible, but contributes neither fee nor weight to
    // the quote. Target one retains the known miss from the late confirmation.
    BOOST_CHECK_EQUAL(At(2).all.Unknown(), 1);
    BOOST_CHECK_EQUAL(stats.EstimateMedianVal(2, 0.01, 0.95, nullptr), (900 * 0.5 + 1000) / 1.5);
    BOOST_CHECK_EQUAL(stats.EstimateMedianVal(1, 0.01, 0.50, nullptr), 950);
}

BOOST_AUTO_TEST_CASE(unknown_outcomes_do_not_supply_estimation_support)
{
    for (unsigned int known{0}; known <= 2; ++known) {
        StatsFixture test;
        for (unsigned int i{0}; i < known; ++i) {
            const auto bucket = test.stats.NewChunk(100, 900);
            test.stats.EndChunk(100, 101, bucket, 900, MemPoolChunkEndReason::CONFIRMED);
        }
        for (unsigned int i{0}; i < 20; ++i) {
            const auto bucket = test.stats.NewChunk(100, 600);
            test.stats.EndChunk(100, 101, bucket, 600, MemPoolChunkEndReason::EXPIRY);
        }
        BOOST_CHECK(!test.stats.Mature(100, 101));
        BOOST_CHECK_EQUAL(test.At(1).all.Unknown(), 20);
        BOOST_CHECK_EQUAL(test.At(1).all.success, known);
        // With decay 0.5, sufficient=1 requires two known outcomes. Even a
        // zero success threshold cannot make unknown-only evidence sufficient.
        BOOST_CHECK_EQUAL(test.stats.EstimateMedianVal(1, 1, 0, nullptr), known == 2 ? 900 : -1);
    }
}

BOOST_AUTO_TEST_CASE(unknown_outcomes_do_not_move_the_median_bucket)
{
    for (unsigned int i{0}; i < 4; ++i) {
        const double rate = i < 3 ? 900 : 1900;
        const auto bucket = stats.NewChunk(100, rate);
        stats.EndChunk(100, 101, bucket, rate, MemPoolChunkEndReason::CONFIRMED);
    }
    for (unsigned int i{0}; i < 10; ++i) {
        const auto bucket = stats.NewChunk(100, 1800);
        stats.EndChunk(100, 101, bucket, 1800, MemPoolChunkEndReason::REPLACED);
    }
    stats.Mature(100, 101);
    ChunkConfirmStats::Result result;
    // The range needs all four known samples; three of them are in the lower
    // bucket. The ten unknowns must not provide support or change its median.
    BOOST_CHECK_EQUAL(stats.EstimateMedianVal(1, 2, 0.95, &result), 900);
    BOOST_CHECK_EQUAL(result.pass.success, 4);
    BOOST_CHECK_EQUAL(result.pass.Unknown(), 10);
    BOOST_CHECK_CLOSE_FRACTION(result.pass.Lower(), 4.0 / 14, 1e-12);
}

BOOST_AUTO_TEST_CASE(ending_time_does_not_change_past_weights)
{
    StatsFixture ended;
    const auto bucket = stats.NewChunk(100, 1000);
    ended.stats.NewChunk(100, 1000);
    for (unsigned int height{101}; height <= 103; ++height) {
        stats.UpdateMovingAverages(1);
        ended.stats.UpdateMovingAverages(1);
        if (height == 103) ended.stats.EndChunk(100, height, bucket, 1000, MemPoolChunkEndReason::EVICTION);
        stats.Mature(height - 1, height);
        ended.stats.Mature(height - 1, height);
    }
    BOOST_CHECK_EQUAL(At(1).all.failure, 0.25);
    BOOST_CHECK_EQUAL(ended.At(1).all.failure, At(1).all.failure);
    BOOST_CHECK_EQUAL(ended.At(2).all.failure, At(2).all.failure);
    BOOST_CHECK_EQUAL(At(3).all.failure, 1);
    BOOST_CHECK_EQUAL(ended.At(3).all.failure, 0);
    BOOST_CHECK_EQUAL(ended.At(3).all.Unknown(), 1);
    BOOST_CHECK_EQUAL(ended.stats.EstimateMedianVal(1, 0.01, 0, nullptr), 1000);
    BOOST_CHECK_EQUAL(ended.stats.EstimateMedianVal(3, 0.01, 0, nullptr), -1);
}

BOOST_AUTO_TEST_CASE(same_height_endings_do_not_train)
{
    const auto bucket = stats.NewChunk(100, 1000);
    stats.NewChunk(100, 1000);
    stats.EndChunk(100, 100, bucket, 1000, MemPoolChunkEndReason::REPLACED);
    stats.EndChunk(100, 100, bucket, 1000, MemPoolChunkEndReason::CONFIRMED);
    BOOST_CHECK_EQUAL(stats.CohortHeights(), 0U);
    BOOST_CHECK(!stats.Mature(100, 104));
    BOOST_CHECK_EQUAL(At(1).all.Total(), 0);
    BOOST_CHECK_EQUAL(At(4).all.Total(), 0);
}

BOOST_AUTO_TEST_CASE(scaled_deadlines_and_bounded_retention)
{
    ChunkConfirmStats scaled{buckets, bucket_map, /*periods=*/3, /*decay=*/0.5, /*scale=*/2};
    const auto bucket = scaled.NewChunk(100, 1000);
    scaled.NewChunk(100, 1000);
    scaled.EndChunk(100, 101, bucket, 1000, MemPoolChunkEndReason::CONFIRMED);
    BOOST_CHECK(!scaled.Mature(100, 101));
    ChunkConfirmStats::Result result;
    scaled.EstimateMedianVal(1, 0.01, 0.95, &result);
    BOOST_CHECK_EQUAL(result.target, 2U);
    BOOST_CHECK_EQUAL(result.all.success, 1);
    BOOST_CHECK_EQUAL(scaled.CohortHeights(), 1U);

    // The remaining observation stays until the longest deadline, while the
    // confirmed one must not be recorded again when any deadline is reached.
    scaled.UpdateMovingAverages(1);
    BOOST_CHECK(scaled.Mature(101, 102));
    scaled.EstimateMedianVal(1, 0.01, 0.95, &result);
    BOOST_CHECK_EQUAL(result.all.success, 0.5);
    BOOST_CHECK_EQUAL(result.all.failure, 1);
    BOOST_CHECK_EQUAL(scaled.CohortHeights(), 1U);
    scaled.UpdateMovingAverages(4);
    BOOST_CHECK(scaled.Mature(102, 106));
    BOOST_CHECK_EQUAL(scaled.CohortHeights(), 0U);
    scaled.EstimateMedianVal(6, 0.01, 0.95, &result);
    BOOST_CHECK_EQUAL(result.all.success, 0.03125);
    BOOST_CHECK_EQUAL(result.all.failure, 1);
    scaled.Reset();
    scaled.EstimateMedianVal(6, 0.01, 0.95, &result);
    BOOST_CHECK_EQUAL(result.all.Total(), 0);
}

BOOST_AUTO_TEST_CASE(saved_pending_outcomes_become_unknown)
{
    const auto bucket = stats.NewChunk(100, 900);
    stats.NewChunk(100, 600);
    stats.EndChunk(100, 101, bucket, 900, MemPoolChunkEndReason::CONFIRMED);
    stats.Mature(100, 101);
    stats.NewChunk(101, 1000);
    AutoFile file{std::tmpfile()};
    BOOST_REQUIRE(!file.IsNull());
    stats.Write(file, 101);
    file.seek(0, SEEK_SET);
    StatsFixture restored;
    restored.stats.Read(file, buckets.size(), 101);
    restored.stats.CheckPending({}, 101);
    BOOST_CHECK_EQUAL(restored.stats.CohortHeights(), 1U);
    BOOST_CHECK_EQUAL(restored.At(1).all.success, 1);
    BOOST_CHECK_EQUAL(restored.At(1).all.failure, 1);
    BOOST_CHECK_EQUAL(restored.stats.EstimateMedianVal(1, 0.01, 0.50, nullptr), 750);
    restored.stats.UpdateMovingAverages(1);
    restored.stats.Mature(101, 102);
    BOOST_CHECK_EQUAL(restored.At(2).all.success, 0.5);
    BOOST_CHECK_EQUAL(restored.At(2).all.failure, 0);
    BOOST_CHECK_EQUAL(restored.At(2).all.Unknown(), 1);
    BOOST_CHECK_EQUAL(restored.stats.EstimateMedianVal(2, 0.01, 0.95, nullptr), 900);

    // Saving must leave live identities and their future outcomes untouched.
    stats.CheckPending({{100, {{bucket, 1}}}, {101, {{bucket, 1}}}}, 101);
    stats.UpdateMovingAverages(1);
    stats.Mature(101, 102);
    BOOST_CHECK_EQUAL(At(2).all.failure, 1);
    BOOST_CHECK_EQUAL(At(2).all.Unknown(), 0);
    BOOST_CHECK_EQUAL(stats.EstimateMedianVal(2, 0.01, 0.30, nullptr), 700);

    // Once the saved pending cohort expires, the already saved success must
    // only have decayed; it must never be resurrected at a later deadline.
    restored.stats.UpdateMovingAverages(2);
    restored.stats.Mature(102, 104);
    BOOST_CHECK_EQUAL(restored.stats.CohortHeights(), 0U);
    BOOST_CHECK_EQUAL(restored.At(4).all.success, 0.125);
    BOOST_CHECK_EQUAL(restored.At(4).all.Unknown(), 1);
    BOOST_CHECK_EQUAL(restored.stats.EstimateMedianVal(4, 0.01, 0.95, nullptr), 900);
    BOOST_REQUIRE_EQUAL(file.fclose(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
