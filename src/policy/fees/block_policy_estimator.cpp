// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/fees/block_policy_estimator.h>

#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <kernel/mempool_entry.h>
#include <policy/feerate.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/log.h>
#include <util/serfloat.h>
#include <util/syserror.h>
#include <util/time.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>

// Immediate confirmations are stored in target rows, not pending cohorts.
constexpr int CURRENT_FEES_FILE_VERSION{309903};

static constexpr double INF_FEERATE = 1e99;

std::string StringForFeeEstimateHorizon(FeeEstimateHorizon horizon)
{
    switch (horizon) {
    case FeeEstimateHorizon::SHORT_HALFLIFE: return "short";
    case FeeEstimateHorizon::MED_HALFLIFE: return "medium";
    case FeeEstimateHorizon::LONG_HALFLIFE: return "long";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

std::string StringForBlockPolicyEstimateReason(BlockPolicyEstimateReason reason)
{
    switch (reason) {
    case BlockPolicyEstimateReason::NONE:
        return "None";
    case BlockPolicyEstimateReason::HALF_ESTIMATE:
        return "Half Target 60% Threshold";
    case BlockPolicyEstimateReason::FULL_ESTIMATE:
        return "Target 85% Threshold";
    case BlockPolicyEstimateReason::DOUBLE_ESTIMATE:
        return "Double Target 95% Threshold";
    case BlockPolicyEstimateReason::CONSERVATIVE:
        return "Conservative Double Target longer horizon";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

namespace {

struct EncodedDoubleFormatter
{
    template<typename Stream> void Ser(Stream &s, double v)
    {
        s << EncodeDouble(v);
    }

    template<typename Stream> void Unser(Stream& s, double& v)
    {
        uint64_t encoded;
        s >> encoded;
        v = DecodeDouble(encoded);
    }
};

} // namespace

std::string StringForChunkEndReason(MemPoolChunkEndReason reason)
{
    static constexpr std::array<const char*, NUM_CHUNK_END_REASONS> names{
        "confirmed", "replaced", "package_changed", "expiry", "eviction",
        "partial_confirmation", "unseen_sponsor", "block_conflict", "local_policy",
        "reordering", "observation_lost"};
    return names.at(static_cast<size_t>(reason));
}


void CBlockPolicyEstimator::ClearUnconfirmed()
{
    AssertLockHeld(m_cs_fee_estimator);
    while (!mapMemPoolChunks.empty()) EndChunk(mapMemPoolChunks.begin()->first, MemPoolChunkEndReason::OBSERVATION_LOST);
}

void CBlockPolicyEstimator::ResetHistory(unsigned int height)
{
    AssertLockHeld(m_cs_fee_estimator);
    mapMemPoolChunks.clear();
    for (auto* stats : {feeStats.get(), shortStats.get(), longStats.get()}) stats->Reset();
    nBestSeenHeight = m_resolved_height = height;
    LogDebug(BCLog::ESTIMATEFEE, "PKGFEE reset height=%u\n", height);
    firstRecordedHeight = historicalFirst = historicalBest = 0;
    m_observation_height = height;
}

void CBlockPolicyEstimator::AdvanceClock(unsigned int height)
{
    AssertLockHeld(m_cs_fee_estimator);
    if (height <= nBestSeenHeight) return;
    const unsigned int elapsed = height - nBestSeenHeight;
    assert(elapsed == 1 || mapMemPoolChunks.empty());
    nBestSeenHeight = height;
    for (auto* stats : {feeStats.get(), shortStats.get(), longStats.get()}) stats->UpdateMovingAverages(elapsed);
}

void CBlockPolicyEstimator::StartChunk(const MemPoolChunk& chunk, unsigned int height)
{
    AssertLockHeld(m_cs_fee_estimator);
    assert(height == nBestSeenHeight);
    if (!chunk.m_fee_estimation_eligible || chunk.m_fee_rate.size <= 0 || !MoneyRange(chunk.m_fee_rate.fee)) return;
    const int64_t vsize = (int64_t{chunk.m_fee_rate.size} + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    if (vsize > std::numeric_limits<int32_t>::max()) return;
    const double rate = CFeeRate(chunk.m_fee_rate.fee, vsize).GetFeePerK();
    const auto bucket = feeStats->NewChunk(height, rate);
    const auto short_bucket = shortStats->NewChunk(height, rate);
    const auto long_bucket = longStats->NewChunk(height, rate);
    assert(bucket == short_bucket && bucket == long_bucket);
    const auto [it, inserted] = mapMemPoolChunks.emplace(chunk.m_chunk_hash,
        ChunkStatsInfo{height, bucket, chunk.m_fee_rate, ++m_next_observation_id});
    assert(inserted);
    LogDebug(BCLog::ESTIMATEFEE, "PKGFEE start id=%u height=%u fee=%d vsize=%d members=%u hash=%s\n",
             it->second.observation_id, height, chunk.m_fee_rate.fee, vsize, chunk.m_member_count, chunk.m_chunk_hash.ToString());
}

bool CBlockPolicyEstimator::EndChunk(const uint256& hash, MemPoolChunkEndReason outcome)
{
    AssertLockHeld(m_cs_fee_estimator);
    const auto it = mapMemPoolChunks.find(hash);
    if (it == mapMemPoolChunks.end()) return false;
    const auto& observation = it->second;
    assert(observation.blockHeight <= nBestSeenHeight);
    const auto& observed = observation.observed_fee_weight;
    const int64_t vsize = (int64_t{observed.size} + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    const double rate = CFeeRate(observed.fee, vsize).GetFeePerK();
    bool recorded{false};
    for (auto* stats : {feeStats.get(), shortStats.get(), longStats.get()}) {
        recorded |= stats->EndChunk(observation.blockHeight, nBestSeenHeight, observation.bucketIndex, rate, outcome);
    }
    if (recorded && firstRecordedHeight == 0) firstRecordedHeight = nBestSeenHeight;
    LogDebug(BCLog::ESTIMATEFEE, "PKGFEE end id=%u height=%u known_through=%u reason=%s\n",
             observation.observation_id, nBestSeenHeight, m_resolved_height, StringForChunkEndReason(outcome));
    ++m_endings.at(static_cast<size_t>(outcome));
    mapMemPoolChunks.erase(it);
    return outcome == MemPoolChunkEndReason::CONFIRMED;
}

CBlockPolicyEstimator::CBlockPolicyEstimator(const fs::path& estimation_filepath, const bool read_stale_estimates)
    : m_estimation_filepath{estimation_filepath}
{
    LogDebug(BCLog::ESTIMATEFEE, "PKGFEE session format=1\n");
    static_assert(MIN_BUCKET_FEERATE > 0, "Min feerate must be nonzero");
    size_t bucketIndex = 0;

    for (double bucketBoundary = MIN_BUCKET_FEERATE; bucketBoundary <= MAX_BUCKET_FEERATE; bucketBoundary *= FEE_SPACING, bucketIndex++) {
        buckets.push_back(bucketBoundary);
        bucketMap[bucketBoundary] = bucketIndex;
    }
    buckets.push_back(INF_FEERATE);
    bucketMap[INF_FEERATE] = bucketIndex;
    assert(bucketMap.size() == buckets.size());

    feeStats = std::unique_ptr<ChunkConfirmStats>(new ChunkConfirmStats(buckets, bucketMap, MED_BLOCK_PERIODS, MED_DECAY, MED_SCALE));
    shortStats = std::unique_ptr<ChunkConfirmStats>(new ChunkConfirmStats(buckets, bucketMap, SHORT_BLOCK_PERIODS, SHORT_DECAY, SHORT_SCALE));
    longStats = std::unique_ptr<ChunkConfirmStats>(new ChunkConfirmStats(buckets, bucketMap, LONG_BLOCK_PERIODS, LONG_DECAY, LONG_SCALE));

    AutoFile est_file{fsbridge::fopen(m_estimation_filepath, "rb")};

    if (est_file.IsNull()) {
        LogInfo("%s is not found. Continue anyway.", fs::PathToString(m_estimation_filepath));
        return;
    }

    std::chrono::hours file_age = GetFeeEstimatorFileAge();
    if (file_age > MAX_FILE_AGE && !read_stale_estimates) {
        LogWarning("Fee estimation file %s too old (age=%lld > %lld hours) and will not be used to avoid serving stale estimates.", fs::PathToString(m_estimation_filepath), Ticks<std::chrono::hours>(file_age), Ticks<std::chrono::hours>(MAX_FILE_AGE));
        return;
    }

    if (!Read(est_file)) {
        LogWarning("Failed to read fee estimates from %s. Continue anyway.", fs::PathToString(m_estimation_filepath));
    }
}

CBlockPolicyEstimator::~CBlockPolicyEstimator() = default;

void CBlockPolicyEstimator::processMempoolUpdate(const MemPoolChunksUpdate& update)
{
    LOCK(m_cs_fee_estimator);
    // A listener can attach after publication began. Once attached, reject
    // replay and cancel pending samples if an event was lost.
    if (update.sequence == 0 || (m_last_sequence && update.sequence <= *m_last_sequence)) return;
    const bool sequence_gap = m_last_sequence && update.sequence - *m_last_sequence != 1;
    m_last_sequence = update.sequence;
    if (update.reset_observations) ResetHistory(update.observation_height.value_or(nBestSeenHeight));
    else if (sequence_gap) ClearUnconfirmed();

    const bool block = update.cause == MemPoolUpdateCause::BLOCK;
    if (!update.observation_height ||
        (block && (!update.block_height || update.block_height != update.observation_height))) {
        ClearUnconfirmed();
        m_observation_height.reset();
        return;
    }
    const unsigned int height = *update.observation_height;
    if (height < nBestSeenHeight) ResetHistory(height);
    const bool new_block = block && height > nBestSeenHeight;
    const bool continuous = m_observation_height && *m_observation_height == nBestSeenHeight;
    if (!continuous || (height > nBestSeenHeight && (!block || height - nBestSeenHeight != 1))) {
        ClearUnconfirmed();
    }
    // Decay existing rows first; resolve new deadlines after block evidence.
    const unsigned int previous_height = nBestSeenHeight;
    AdvanceClock(height);
    const auto mature = [&]() EXCLUSIVE_LOCKS_REQUIRED(m_cs_fee_estimator) {
        bool recorded{false};
        for (auto* stats : {feeStats.get(), shortStats.get(), longStats.get()}) recorded |= stats->Mature(previous_height, height);
        if (recorded && firstRecordedHeight == 0) firstRecordedHeight = height;
        m_resolved_height = height;
    };
    m_observation_height = height;
    if (block && !update.chainstate_is_current) ClearUnconfirmed();

    std::map<uint256, const MemPoolChunk*> next;
    for (const auto& chunk : update.new_chunks) {
        if (!next.emplace(chunk.m_chunk_hash, &chunk).second) {
            ClearUnconfirmed();
            mature();
            return;
        }
    }
    const std::set<uint256> confirmed(update.fully_confirmed_chunks.begin(), update.fully_confirmed_chunks.end());
    const bool learn_block = new_block && continuous && !sequence_gap &&
        !update.reset_observations && update.chainstate_is_current;
    // Conflicts may refer to an otherwise unchanged chunk that will be removed
    // after this block notification. Close it before resolving this deadline.
    if (block) for (const auto& [hash, reason] : update.ending_reasons) {
        if (reason == MemPoolChunkEndReason::UNSEEN_SPONSOR ||
            reason == MemPoolChunkEndReason::PARTIAL_CONFIRMATION ||
            reason == MemPoolChunkEndReason::BLOCK_CONFLICT) {
            EndChunk(hash, learn_block ? reason : MemPoolChunkEndReason::OBSERVATION_LOST);
        }
    }
    unsigned int counted{0};
    for (const auto& old : update.old_chunks) {
        const auto tracked = mapMemPoolChunks.find(old.m_chunk_hash);
        if (tracked == mapMemPoolChunks.end()) continue;
        const bool same_observed = old.m_fee_estimation_eligible &&
            tracked->second.observed_fee_weight == old.m_fee_rate;
        const auto replacement = next.find(old.m_chunk_hash);
        if (same_observed && replacement != next.end() &&
            replacement->second->m_fee_estimation_eligible &&
            replacement->second->m_fee_rate == old.m_fee_rate) {
            continue; // Preserve the original age and pending bucket.
        }
        auto outcome = MemPoolChunkEndReason::OBSERVATION_LOST;
        if (same_observed && (!block || learn_block)) {
            const auto evidence = update.ending_reasons.find(old.m_chunk_hash);
            if (block && confirmed.contains(old.m_chunk_hash) &&
                (evidence == update.ending_reasons.end() || evidence->second == MemPoolChunkEndReason::CONFIRMED)) {
                outcome = MemPoolChunkEndReason::CONFIRMED;
            } else if (evidence != update.ending_reasons.end() && evidence->second != MemPoolChunkEndReason::CONFIRMED) {
                outcome = evidence->second;
            } else {
                outcome = MemPoolChunkEndReason::PACKAGE_CHANGED;
                if (update.cause == MemPoolUpdateCause::PRIORITISATION) outcome = MemPoolChunkEndReason::LOCAL_POLICY;
                if (update.cause == MemPoolUpdateCause::REORDERING) outcome = MemPoolChunkEndReason::REORDERING;
                if (update.cause == MemPoolUpdateCause::REMOVAL) {
                    switch (update.reason) {
                    case MemPoolRemovalReason::REPLACED: outcome = MemPoolChunkEndReason::REPLACED; break;
                    case MemPoolRemovalReason::EXPIRY: outcome = MemPoolChunkEndReason::EXPIRY; break;
                    case MemPoolRemovalReason::SIZELIMIT: outcome = MemPoolChunkEndReason::EVICTION; break;
                    case MemPoolRemovalReason::CONFLICT: outcome = MemPoolChunkEndReason::BLOCK_CONFLICT; break;
                    case MemPoolRemovalReason::REORG: outcome = MemPoolChunkEndReason::OBSERVATION_LOST; break;
                    case MemPoolRemovalReason::BLOCK: break;
                    }
                }
            }
        }
        counted += EndChunk(old.m_chunk_hash, outcome);
    }
    for (const auto& chunk : update.new_chunks) {
        if (const auto tracked = mapMemPoolChunks.find(chunk.m_chunk_hash); tracked != mapMemPoolChunks.end()) {
            if (chunk.m_fee_estimation_eligible && tracked->second.observed_fee_weight == chunk.m_fee_rate) continue;
            // An inconsistent producer snapshot must not change an observation
            // in place or pair a new rate with its previous age.
            EndChunk(chunk.m_chunk_hash, MemPoolChunkEndReason::OBSERVATION_LOST);
        }
        const auto ending = update.ending_reasons.find(chunk.m_chunk_hash);
        const bool excluded = block && ending != update.ending_reasons.end() &&
            (ending->second == MemPoolChunkEndReason::BLOCK_CONFLICT || ending->second == MemPoolChunkEndReason::UNSEEN_SPONSOR);
        if (update.chainstate_is_current && !excluded) StartChunk(chunk, height);
    }
    // Confirmation/ambiguity at the deadline takes precedence over a miss.
    mature();
    if (block) {
        LogDebug(BCLog::ESTIMATEFEE, "PKGFEE block height=%u continuous=%d\n", height, learn_block);
        LogDebug(BCLog::ESTIMATEFEE, "Blockpolicy estimates updated by %u chunks at height %u, pending %u\n",
                 counted, height, mapMemPoolChunks.size());
    }
}

void CBlockPolicyEstimator::SanityCheck() const
{
    LOCK(m_cs_fee_estimator);
    std::map<unsigned int, std::map<unsigned int, uint64_t>> expected;
    for (const auto& [hash, observation] : mapMemPoolChunks) {
        assert(observation.blockHeight <= nBestSeenHeight);
        assert(observation.bucketIndex < buckets.size());
        const auto& observed = observation.observed_fee_weight;
        assert(observed.size > 0 && MoneyRange(observed.fee));
        const int64_t vsize = (int64_t{observed.size} + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
        const double rate = CFeeRate(observed.fee, vsize).GetFeePerK();
        assert(bucketMap.lower_bound(rate)->second == observation.bucketIndex);
        ++expected[observation.blockHeight][observation.bucketIndex];
    }
    feeStats->CheckPending(expected, nBestSeenHeight);
    shortStats->CheckPending(expected, nBestSeenHeight);
    longStats->CheckPending(expected, nBestSeenHeight);
}

CFeeRate CBlockPolicyEstimator::estimateFee(int confTarget) const
{
    // It's not possible to get reasonable estimates for confTarget of 1
    if (confTarget <= 1)
        return CFeeRate(0);

    return estimateRawFee(confTarget, DOUBLE_SUCCESS_PCT, FeeEstimateHorizon::MED_HALFLIFE);
}

CFeeRate CBlockPolicyEstimator::estimateRawFee(int confTarget, double successThreshold, FeeEstimateHorizon horizon, EstimationResult* result) const
{
    LOCK(m_cs_fee_estimator);
    ChunkConfirmStats* stats = nullptr;
    double sufficientChunks = SUFFICIENT_FEE_CHUNKS;
    switch (horizon) {
    case FeeEstimateHorizon::SHORT_HALFLIFE: {
        stats = shortStats.get();
        sufficientChunks = SUFFICIENT_CHUNKS_SHORT;
        break;
    }
    case FeeEstimateHorizon::MED_HALFLIFE: {
        stats = feeStats.get();
        break;
    }
    case FeeEstimateHorizon::LONG_HALFLIFE: {
        stats = longStats.get();
        break;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(stats);

    // Return failure if trying to analyze a target we're not tracking
    if (confTarget <= 0 || (unsigned int)confTarget > stats->GetMaxConfirms())
        return CFeeRate(0);
    if (!std::isfinite(successThreshold) || successThreshold < 0 || successThreshold > 1)
        return CFeeRate(0);

    double median = stats->EstimateMedianVal(confTarget, sufficientChunks, successThreshold, result);
    if (result) {
        result->active_observations = mapMemPoolChunks.size();
        result->endings = m_endings;
    }

    if (median < 0)
        return CFeeRate(0);

    return CFeeRate(llround(median));
}

unsigned int CBlockPolicyEstimator::HighestTargetTracked(FeeEstimateHorizon horizon) const
{
    LOCK(m_cs_fee_estimator);
    switch (horizon) {
    case FeeEstimateHorizon::SHORT_HALFLIFE: {
        return shortStats->GetMaxConfirms();
    }
    case FeeEstimateHorizon::MED_HALFLIFE: {
        return feeStats->GetMaxConfirms();
    }
    case FeeEstimateHorizon::LONG_HALFLIFE: {
        return longStats->GetMaxConfirms();
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

unsigned int CBlockPolicyEstimator::BlockSpan() const
{
    if (firstRecordedHeight == 0) return 0;
    assert(nBestSeenHeight >= firstRecordedHeight);

    return nBestSeenHeight - firstRecordedHeight;
}

unsigned int CBlockPolicyEstimator::HistoricalBlockSpan() const
{
    if (historicalFirst == 0) return 0;
    assert(historicalBest >= historicalFirst);

    if (nBestSeenHeight - historicalBest > OLDEST_ESTIMATE_HISTORY) return 0;

    return historicalBest - historicalFirst;
}

unsigned int CBlockPolicyEstimator::MaxUsableEstimate() const
{
    // Block spans are divided by 2 to make sure there are enough potential failing data points for the estimate
    return std::min(longStats->GetMaxConfirms(), std::max(BlockSpan(), HistoricalBlockSpan()) / 2);
}

/** A candidate smart estimate takes the maximum of the feerates calculated with
 * a 60% threshold at target / 2, an 85% threshold at target and a 95% threshold
 * at 2 * target. Conservative candidates retain that estimate as a floor and
 * also check the 95% threshold at 2 * target over longer time horizons.
 * Return the lowest valid candidate at
 * the requested target or a tighter target, so allowing more time cannot
 * increase the estimate.
 */
CFeeRate CBlockPolicyEstimator::estimateSmartFee(int confTarget, FeeCalculation *feeCalc, bool conservative) const
{
    LOCK(m_cs_fee_estimator);

    FeeCalculation temp_fee_calc;
    if (!feeCalc) feeCalc = &temp_fee_calc;

    feeCalc->desiredTarget = confTarget;
    feeCalc->returnedTarget = confTarget;
    feeCalc->best_height = nBestSeenHeight;

    // Return failure if trying to analyze a target we're not tracking
    if (confTarget <= 0 || (unsigned int)confTarget > longStats->GetMaxConfirms()) {
        return CFeeRate(0);  // error condition
    }

    // It's not possible to get reasonable estimates for confTarget of 1
    if (confTarget == 1) confTarget = 2;

    unsigned int maxUsableEstimate = MaxUsableEstimate();
    if ((unsigned int)confTarget > maxUsableEstimate) {
        confTarget = maxUsableEstimate;
    }
    feeCalc->returnedTarget = confTarget;

    if (confTarget <= 1) return CFeeRate(0); // error condition

    struct Horizon {
        const ChunkConfirmStats& stats;
        unsigned int scale;
        double sufficient;
        std::map<std::pair<unsigned int, double>, double> cache;
    };
    Horizon short_horizon{*shortStats, SHORT_SCALE, SUFFICIENT_CHUNKS_SHORT, {}};
    Horizon medium_horizon{*feeStats, MED_SCALE, SUFFICIENT_FEE_CHUNKS, {}};
    Horizon long_horizon{*longStats, LONG_SCALE, SUFFICIENT_FEE_CHUNKS, {}};

    struct Estimate {
        double median{-1};
        const Horizon* horizon{nullptr};
        unsigned int target{0};
        double threshold{0};
    };
    // Different targets can use the same row. Cache its scalar estimate for
    // each threshold, limiting candidate bucket scans to (12 + 24 + 42) * 3.
    const auto estimate = [](Horizon& horizon, unsigned int target, double threshold) {
        const unsigned int effective_target = ((target + horizon.scale - 1) / horizon.scale) * horizon.scale;
        auto [it, inserted] = horizon.cache.try_emplace({effective_target, threshold});
        if (inserted) {
            it->second = horizon.stats.EstimateMedianVal(effective_target, horizon.sufficient, threshold, nullptr);
        }
        return Estimate{it->second, &horizon, effective_target, threshold};
    };
    // Use the shortest horizon which tracks the target, optionally allowing
    // its shorter horizons' maximum targets to lower the estimate.
    const auto combined = [&](unsigned int target, double threshold, bool check_shorter) {
        if (target < 1 || target > long_horizon.stats.GetMaxConfirms()) return Estimate{};
        auto& horizon = target <= short_horizon.stats.GetMaxConfirms() ? short_horizon :
                        target <= medium_horizon.stats.GetMaxConfirms() ? medium_horizon : long_horizon;
        auto result = estimate(horizon, target, threshold);
        if (check_shorter) {
            for (auto* shorter : {&medium_horizon, &short_horizon}) {
                const auto max_target = shorter->stats.GetMaxConfirms();
                if (target <= max_target) continue;
                const auto shorter_estimate = estimate(*shorter, max_target, threshold);
                if (shorter_estimate.median > 0 && (result.median == -1 || shorter_estimate.median < result.median)) {
                    result = shorter_estimate;
                }
            }
        }
        return result;
    };
    // Conservative candidates also require the double-target threshold over
    // every longer horizon, without substituting shorter-horizon estimates.
    const auto conservative_estimate = [&](unsigned int double_target) {
        Estimate result;
        if (double_target <= short_horizon.stats.GetMaxConfirms()) {
            result = estimate(medium_horizon, double_target, DOUBLE_SUCCESS_PCT);
        }
        if (double_target <= medium_horizon.stats.GetMaxConfirms()) {
            const auto longer = estimate(long_horizon, double_target, DOUBLE_SUCCESS_PCT);
            if (longer.median > result.median) result = longer;
        }
        return result;
    };

    Estimate best;
    // Target rows can contain different populations, so complete candidate
    // estimates need not decrease with the target. A valid tighter candidate
    // can satisfy a looser request. Descending order keeps the largest target
    // on ties, and unavailable candidates cannot replace a valid estimate.
    for (int target = confTarget; target >= 2; --target) {
        auto candidate = combined(target / 2, HALF_SUCCESS_PCT, true);
        auto reason = BlockPolicyEstimateReason::HALF_ESTIMATE;
        const auto consider = [&](const Estimate& next, BlockPolicyEstimateReason next_reason) {
            if (next.median > candidate.median) {
                candidate = next;
                reason = next_reason;
            }
        };
        consider(combined(target, SUCCESS_PCT, true), BlockPolicyEstimateReason::FULL_ESTIMATE);
        consider(combined(2 * target, DOUBLE_SUCCESS_PCT, true), BlockPolicyEstimateReason::DOUBLE_ESTIMATE);
        // Complete the economical candidate, including its fallback when no
        // positive estimate is available. Zero is unavailable to selection too.
        if (candidate.median <= 0) {
            consider(conservative_estimate(2 * target), BlockPolicyEstimateReason::CONSERVATIVE);
        }
        if (conservative) {
            // Keep the economical candidate as a floor even when the longer
            // target rows are unavailable. Adding checks can only raise each
            // candidate, so taking the minimum preserves the ordering of modes.
            consider(combined(2 * target, DOUBLE_SUCCESS_PCT, false), BlockPolicyEstimateReason::DOUBLE_ESTIMATE);
            consider(conservative_estimate(2 * target), BlockPolicyEstimateReason::CONSERVATIVE);
        }
        if (target == confTarget || (candidate.median > 0 && (best.median <= 0 || candidate.median < best.median))) {
            best = candidate;
            feeCalc->reason = reason;
            feeCalc->returnedTarget = target;
        }
    }

    // Recompute only the winner's diagnostics instead of caching a full
    // EstimationResult for every row. Keep requested-target diagnostics on failure.
    assert(best.horizon);
    EstimationResult result;
    best.horizon->stats.EstimateMedianVal(best.target, best.horizon->sufficient, best.threshold, &result);
    feeCalc->est = result;
    if (best.median <= 0) return CFeeRate(0); // error condition

    LogDebug(BCLog::ESTIMATEFEE, "estimateSmartFee feerate=%g requested=%d returned=%d reason=%s lower=%g upper=%g total=%g unknown=%g\n",
             best.median, feeCalc->desiredTarget, feeCalc->returnedTarget, StringForBlockPolicyEstimateReason(feeCalc->reason),
             feeCalc->est.pass.Lower(), feeCalc->est.pass.Upper(), feeCalc->est.pass.Total(), feeCalc->est.pass.Unknown());

    return CFeeRate(llround(best.median));
}

util::Expected<FeeRateEstimation, FeeRateEstimationError> CBlockPolicyEstimator::EstimateFeeRate(int target, bool conservative) const
{
    FeeCalculation fee_calc;
    CFeeRate feerate{estimateSmartFee(target, &fee_calc, conservative)};
    if (feerate == CFeeRate(0)) {
        return EstimationError(FeeRateEstimatorType::BLOCK_POLICY, fee_calc.returnedTarget, "Insufficient data or no feerate found");
    }
    return FeeRateEstimation{FeeRateEstimatorType::BLOCK_POLICY, feerate.GetFeePerVSize(), fee_calc.returnedTarget};
}

unsigned int CBlockPolicyEstimator::MaximumTarget() const
{
    return HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE);
}

void CBlockPolicyEstimator::Flush() {
    FlushUnconfirmed();
    FlushFeeEstimates();
}

void CBlockPolicyEstimator::FlushFeeEstimates()
{
    if (!m_estimation_filepath.parent_path().empty()) {
        std::error_code error;
        fs::create_directories(m_estimation_filepath.parent_path(), error);
        if (error) {
            LogWarning("Failed to create fee estimates directory %s: %s. Continue anyway.", fs::PathToString(m_estimation_filepath.parent_path()), error.message());
            return;
        }
    }

    AutoFile est_file{fsbridge::fopen(m_estimation_filepath, "wb")};
    if (est_file.IsNull() || !Write(est_file)) {
        LogWarning("Failed to write fee estimates to %s. Continue anyway.", fs::PathToString(m_estimation_filepath));
        (void)est_file.fclose();
        return;
    }
    if (est_file.fclose() != 0) {
        LogWarning("Failed to close fee estimates file %s: %s. Continuing anyway.", fs::PathToString(m_estimation_filepath), SysErrorString(errno));
        return;
    }
    LogDebug(BCLog::ESTIMATEFEE, "Flushed fee estimates to %s.", fs::PathToString(m_estimation_filepath));
}

bool CBlockPolicyEstimator::Write(AutoFile& fileout) const
{
    try {
        LOCK(m_cs_fee_estimator);
        fileout << CURRENT_FEES_FILE_VERSION;
        fileout << nBestSeenHeight;
        if (BlockSpan() > HistoricalBlockSpan()/2) {
            fileout << firstRecordedHeight << nBestSeenHeight;
        }
        else {
            fileout << historicalFirst << historicalBest;
        }
        fileout << Using<VectorFormatter<EncodedDoubleFormatter>>(buckets);
        feeStats->Write(fileout, nBestSeenHeight);
        shortStats->Write(fileout, nBestSeenHeight);
        longStats->Write(fileout, nBestSeenHeight);
    }
    catch (const std::exception&) {
        LogWarning("Unable to write policy estimator data (non-fatal)");
        return false;
    }
    return true;
}

bool CBlockPolicyEstimator::Read(AutoFile& filein)
{
    try {
        LOCK(m_cs_fee_estimator);
        int nVersionRequired;
        filein >> nVersionRequired;
        if (nVersionRequired > CURRENT_FEES_FILE_VERSION) {
            throw std::runtime_error{strprintf("File version (%d) too high to be read.", nVersionRequired)};
        }
        if (nVersionRequired < CURRENT_FEES_FILE_VERSION) {
            throw std::runtime_error{strprintf("File version (%d) incompatible: Too old to be read", nVersionRequired)};
        }

        // Read fee estimates file into temporary variables so existing data
        // structures aren't corrupted if there is an exception.
        unsigned int nFileBestSeenHeight;
        filein >> nFileBestSeenHeight;

        // nVersionRequired == CURRENT_FEES_FILE_VERSION
        unsigned int nFileHistoricalFirst, nFileHistoricalBest;
        filein >> nFileHistoricalFirst >> nFileHistoricalBest;
        if (nFileHistoricalFirst > nFileHistoricalBest || nFileHistoricalBest > nFileBestSeenHeight) {
            throw std::runtime_error("Corrupt estimates file. Historical block range for estimates is invalid");
        }
        std::vector<double> fileBuckets;
        filein >> Using<VectorFormatter<EncodedDoubleFormatter>>(fileBuckets);
        size_t numBuckets = fileBuckets.size();
        if (numBuckets <= 1 || numBuckets > 1000) {
            throw std::runtime_error("Corrupt estimates file. Must have between 2 and 1000 feerate buckets");
        }
        if (fileBuckets.back() != INF_FEERATE ||
            std::ranges::any_of(fileBuckets, [](double value) { return !std::isfinite(value) || value <= 0; }) ||
            std::adjacent_find(fileBuckets.begin(), fileBuckets.end(), std::greater_equal<double>{}) != fileBuckets.end()) {
            throw std::runtime_error("Corrupt estimates file. Invalid fee bucket boundaries");
        }

        std::unique_ptr<ChunkConfirmStats> fileFeeStats(new ChunkConfirmStats(buckets, bucketMap, MED_BLOCK_PERIODS, MED_DECAY, MED_SCALE));
        std::unique_ptr<ChunkConfirmStats> fileShortStats(new ChunkConfirmStats(buckets, bucketMap, SHORT_BLOCK_PERIODS, SHORT_DECAY, SHORT_SCALE));
        std::unique_ptr<ChunkConfirmStats> fileLongStats(new ChunkConfirmStats(buckets, bucketMap, LONG_BLOCK_PERIODS, LONG_DECAY, LONG_SCALE));
        fileFeeStats->Read(filein, numBuckets, nFileBestSeenHeight);
        fileShortStats->Read(filein, numBuckets, nFileBestSeenHeight);
        fileLongStats->Read(filein, numBuckets, nFileBestSeenHeight);

        // Fee estimates file parsed correctly
        // Copy buckets from file and refresh our bucketmap
        buckets = fileBuckets;
        bucketMap.clear();
        for (unsigned int i = 0; i < buckets.size(); i++) {
            bucketMap[buckets[i]] = i;
        }

        // Destroy old ChunkConfirmStats and point to new ones that already reference buckets and bucketMap
        feeStats = std::move(fileFeeStats);
        shortStats = std::move(fileShortStats);
        longStats = std::move(fileLongStats);

        mapMemPoolChunks.clear();
        m_observation_height.reset();
        m_last_sequence.reset();
        firstRecordedHeight = 0;
        nBestSeenHeight = m_resolved_height = nFileBestSeenHeight;
        historicalFirst = nFileHistoricalFirst;
        historicalBest = nFileHistoricalBest;
    }
    catch (const std::exception& e) {
        LogWarning("Unable to read policy estimator data (non-fatal): %s", e.what());
        return false;
    }
    return true;
}

void CBlockPolicyEstimator::FlushUnconfirmed()
{
    const auto startclear{SteadyClock::now()};
    LOCK(m_cs_fee_estimator);
    size_t num_entries = mapMemPoolChunks.size();
    // Remove every entry in mapMemPoolChunks
    while (!mapMemPoolChunks.empty()) {
        auto mi = mapMemPoolChunks.begin();
        EndChunk(mi->first, MemPoolChunkEndReason::OBSERVATION_LOST);
    }
    const auto endclear{SteadyClock::now()};
    LogDebug(BCLog::ESTIMATEFEE, "Recorded %u unconfirmed chunks from mempool in %.3fs\n", num_entries, Ticks<SecondsDouble>(endclear - startclear));
}

std::chrono::hours CBlockPolicyEstimator::GetFeeEstimatorFileAge()
{
    auto file_time{fs::last_write_time(m_estimation_filepath)};
    auto now{fs::file_time_type::clock::now()};
    return std::chrono::duration_cast<std::chrono::hours>(now - file_time);
}

static std::set<double> MakeFeeSet(const CFeeRate& min_incremental_fee,
                                   double max_filter_fee_rate,
                                   double fee_filter_spacing)
{
    std::set<double> fee_set;

    const CAmount min_fee_limit{std::max(CAmount(1), min_incremental_fee.GetFeePerK() / 2)};
    fee_set.insert(0);
    for (double bucket_boundary = min_fee_limit;
         bucket_boundary <= max_filter_fee_rate;
         bucket_boundary *= fee_filter_spacing) {

        fee_set.insert(bucket_boundary);
    }

    return fee_set;
}

FeeFilterRounder::FeeFilterRounder(const CFeeRate& minIncrementalFee, FastRandomContext& rng)
    : m_fee_set{MakeFeeSet(minIncrementalFee, MAX_FILTER_FEERATE, FEE_FILTER_SPACING)},
      insecure_rand{rng}
{
}

CAmount FeeFilterRounder::round(CAmount currentMinFee)
{
    AssertLockNotHeld(m_insecure_rand_mutex);
    std::set<double>::iterator it = m_fee_set.lower_bound(currentMinFee);
    if (it == m_fee_set.end() ||
        (it != m_fee_set.begin() &&
         WITH_LOCK(m_insecure_rand_mutex, return insecure_rand.rand32()) % 3 != 0)) {
        --it;
    }
    return static_cast<CAmount>(*it);
}
