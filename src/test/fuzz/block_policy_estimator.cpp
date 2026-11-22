// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/fees/block_policy_estimator.h>

#include <crypto/common.h>
#include <kernel/mempool_entry.h>
#include <policy/fees/estimator_args.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>

#include <cassert>
#include <cstdint>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <utility>

namespace {
const BasicTestingSetup* g_setup;
} // namespace

void initialize_block_policy_estimator()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
    g_setup = testing_setup.get();
}

FUZZ_TARGET(block_policy_estimator, .init = initialize_block_policy_estimator)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    CBlockPolicyEstimator block_policy_estimator{BlockPolicyFeeEstPath(*g_setup->m_node.args), DEFAULT_ACCEPT_STALE_FEE_ESTIMATES};

    // Retain identities across transitions, so the fuzzer exercises observations
    // being preserved, changed, retired, and confirmed instead of unrelated hashes.
    std::map<uint256, MemPoolChunk> chunks;
    uint64_t next_chunk_id{1};
    uint64_t sequence{0};
    unsigned int current_height{fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(0, 999'000)};
    const auto make_chunk = [&] {
        uint256 hash;
        WriteLE64(hash.begin(), next_chunk_id++);
        return MemPoolChunk{
            FeeFrac{fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 100'000'000),
                    fuzzed_data_provider.ConsumeIntegralInRange<int32_t>(4, 400'000)},
            hash,
            fuzzed_data_provider.ConsumeBool()};
    };
    const auto pick_chunk = [&] {
        assert(!chunks.empty());
        return std::next(chunks.begin(), fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, chunks.size() - 1));
    };
    const auto add_overlap = [&](MemPoolChunksUpdate& update, const uint256& excluded) {
        if (chunks.empty() || !fuzzed_data_provider.ConsumeBool()) return;
        const auto it = pick_chunk();
        if (it->first == excluded) return;
        update.old_chunks.push_back(it->second);
        update.new_chunks.push_back(it->second);
    };
    const auto publish = [&](MemPoolChunksUpdate update) {
        update.sequence = ++sequence;
        update.observation_height = current_height;
        update.chainstate_is_current = true;
        block_policy_estimator.processMempoolUpdate(update);
        block_policy_estimator.SanityCheck();
        assert(chunks.size() <= 64);
    };

    // Establish an explicit clock even when there are no observed chunks yet.
    publish(MemPoolChunksUpdate{.old_chunks = {}, .new_chunks = {}, .reason = MemPoolRemovalReason::REPLACED});

    if (fuzzed_data_provider.ConsumeBool()) {
        // Exercise the consumer's input guards without inserting malformed
        // descriptions into the model of valid, live chunk configurations.
        auto malformed = make_chunk();
        malformed.m_fee_estimation_eligible = true;
        switch (fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(0, 3)) {
        case 0:
            malformed.m_fee_rate.fee = std::numeric_limits<int64_t>::max();
            break;
        case 1:
            malformed.m_fee_rate.fee = fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(std::numeric_limits<int64_t>::min(), -1);
            break;
        case 2:
            malformed.m_fee_rate = FeeFrac{0, 0};
            break;
        case 3:
            malformed.m_fee_rate = FeeFrac{0, fuzzed_data_provider.ConsumeIntegralInRange<int32_t>(std::numeric_limits<int32_t>::min(), -1)};
            break;
        }
        publish(MemPoolChunksUpdate{
            .old_chunks = {}, .new_chunks = {malformed}, .reason = MemPoolRemovalReason::REPLACED});
        publish(MemPoolChunksUpdate{
            .old_chunks = {malformed}, .new_chunks = {}, .reason = MemPoolRemovalReason::EXPIRY,
            .cause = MemPoolUpdateCause::REMOVAL});
    }

    LIMITED_WHILE (fuzzed_data_provider.remaining_bytes() > 0 &&
                   fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(0, 31) != 0, 1'000) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                if (chunks.size() == 64) return;
                const auto chunk = make_chunk();
                MemPoolChunksUpdate update{.old_chunks = {}, .new_chunks = {}, .reason = MemPoolRemovalReason::REPLACED};
                add_overlap(update, chunk.m_chunk_hash);
                update.new_chunks.push_back(chunk);
                chunks.emplace(chunk.m_chunk_hash, chunk);
                publish(std::move(update));
            },
            [&] {
                if (chunks.empty()) return;
                const auto& chunk = pick_chunk()->second;
                // Affected-cluster snapshots may contain an entirely unchanged chunk.
                publish(MemPoolChunksUpdate{
                    .old_chunks = {chunk},
                    .new_chunks = {chunk},
                    .reason = MemPoolRemovalReason::REPLACED,
                    .cause = MemPoolUpdateCause::REORDERING});
            },
            [&] {
                if (chunks.empty()) return;
                const auto it = pick_chunk();
                MemPoolChunksUpdate update{
                    .old_chunks = {it->second},
                    .new_chunks = {},
                    .reason = MemPoolRemovalReason::REPLACED,
                    .cause = MemPoolUpdateCause::PRIORITISATION};
                add_overlap(update, it->first);
                // Membership is unchanged, but either economics or eligibility changes.
                if (fuzzed_data_provider.ConsumeBool()) {
                    it->second.m_fee_rate.fee = (it->second.m_fee_rate.fee + 1) % 100'000'001;
                    it->second.m_fee_estimation_eligible = false;
                } else {
                    it->second.m_fee_estimation_eligible = !it->second.m_fee_estimation_eligible;
                }
                update.new_chunks.push_back(it->second);
                publish(std::move(update));
            },
            [&] {
                if (chunks.empty()) return;
                const auto it = pick_chunk();
                MemPoolChunksUpdate update{
                    .old_chunks = {it->second},
                    .new_chunks = {},
                    .reason = MemPoolRemovalReason::REPLACED};
                add_overlap(update, it->first);
                chunks.erase(it);
                const auto replacement = make_chunk();
                chunks.emplace(replacement.m_chunk_hash, replacement);
                update.new_chunks.push_back(replacement);
                publish(std::move(update));
            },
            [&] {
                if (chunks.empty()) return;
                const auto it = pick_chunk();
                MemPoolChunksUpdate update{
                    .old_chunks = {it->second},
                    .new_chunks = {},
                    .reason = fuzzed_data_provider.PickValueInArray({
                        MemPoolRemovalReason::EXPIRY, MemPoolRemovalReason::SIZELIMIT,
                        MemPoolRemovalReason::CONFLICT, MemPoolRemovalReason::REPLACED}),
                    .cause = MemPoolUpdateCause::REMOVAL};
                add_overlap(update, it->first);
                chunks.erase(it);
                publish(std::move(update));
            },
            [&] {
                ++current_height;
                MemPoolChunksUpdate update{
                    .old_chunks = {},
                    .new_chunks = {},
                    .reason = MemPoolRemovalReason::BLOCK,
                    .block_height = current_height,
                    .cause = MemPoolUpdateCause::BLOCK};
                if (!chunks.empty() && fuzzed_data_provider.ConsumeBool()) {
                    const auto it = pick_chunk();
                    const auto old_chunk = it->second;
                    update.old_chunks.push_back(old_chunk);
                    add_overlap(update, it->first);
                    chunks.erase(it);
                    if (old_chunk.m_fee_rate.size > 1 && fuzzed_data_provider.ConsumeBool()) {
                        // Only part of the old membership confirms. The remainder
                        // starts a new configuration, and the old chunk is not a success.
                        auto remainder = make_chunk();
                        remainder.m_fee_rate = FeeFrac{
                            fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, old_chunk.m_fee_rate.fee),
                            fuzzed_data_provider.ConsumeIntegralInRange<int32_t>(1, old_chunk.m_fee_rate.size - 1)};
                        remainder.m_fee_estimation_eligible = old_chunk.m_fee_estimation_eligible;
                        chunks.emplace(remainder.m_chunk_hash, remainder);
                        update.new_chunks.push_back(remainder);
                        update.ending_reasons.emplace(old_chunk.m_chunk_hash, MemPoolChunkEndReason::PARTIAL_CONFIRMATION);
                    } else {
                        // Only a completely removed old chunk is declared fully mined.
                        update.fully_confirmed_chunks.push_back(old_chunk.m_chunk_hash);
                        if (fuzzed_data_provider.ConsumeBool()) update.ending_reasons.emplace(old_chunk.m_chunk_hash, MemPoolChunkEndReason::UNSEEN_SPONSOR);
                    }
                }
                // An empty block transition must still advance the estimator's clock.
                publish(std::move(update));
            },
            [&] {
                // Usually reset at the same height so later transitions can
                // observe live chunks; occasional shallow reorgs test recovery.
                if (current_height > 0 && fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(0, 7) == 0) --current_height;
                MemPoolChunksUpdate update{
                    .old_chunks = {},
                    .new_chunks = {},
                    .reason = MemPoolRemovalReason::REORG,
                    .cause = MemPoolUpdateCause::REORG,
                    .reset_observations = true};
                // A reorg publishes a full replacement snapshot, including identities
                // that remain present but must not retain observations across the reset.
                for (auto it = chunks.begin(); it != chunks.end();) {
                    if (fuzzed_data_provider.ConsumeBool()) {
                        it = chunks.erase(it);
                    } else {
                        update.new_chunks.push_back(it->second);
                        ++it;
                    }
                }
                publish(std::move(update));
            });
        (void)block_policy_estimator.estimateFee(fuzzed_data_provider.ConsumeIntegral<int>());
        EstimationResult result;
        auto conf_target = fuzzed_data_provider.ConsumeIntegral<int>();
        auto success_threshold = fuzzed_data_provider.ConsumeFloatingPoint<double>();
        auto horizon = fuzzed_data_provider.PickValueInArray(ALL_FEE_ESTIMATE_HORIZONS);
        auto* result_ptr = fuzzed_data_provider.ConsumeBool() ? &result : nullptr;
        (void)block_policy_estimator.estimateRawFee(conf_target, success_threshold, horizon, result_ptr);
        if (result.target) {
            assert(result.all.success >= 0 && result.all.failure >= 0 && result.all.Unknown() >= 0);
            assert(result.all.Lower() <= result.all.Upper());
            assert(result.all.Lower() >= 0 && result.all.Upper() <= 1);
            assert(result.cohort_heights <= block_policy_estimator.HighestTargetTracked(horizon));
        }

        FeeCalculation fee_calculation;
        conf_target = fuzzed_data_provider.ConsumeIntegral<int>();
        auto* fee_calc_ptr = fuzzed_data_provider.ConsumeBool() ? &fee_calculation : nullptr;
        auto conservative = fuzzed_data_provider.ConsumeBool();
        (void)block_policy_estimator.estimateSmartFee(conf_target, fee_calc_ptr, conservative);

        (void)block_policy_estimator.HighestTargetTracked(fuzzed_data_provider.PickValueInArray(ALL_FEE_ESTIMATE_HORIZONS));
    }
    {
        FuzzedFileProvider fuzzed_file_provider{fuzzed_data_provider};
        AutoFile fuzzed_auto_file{fuzzed_file_provider.open()};
        block_policy_estimator.Write(fuzzed_auto_file);
        block_policy_estimator.Read(fuzzed_auto_file);
        (void)fuzzed_auto_file.fclose();
    }
}
