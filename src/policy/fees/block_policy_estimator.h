// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_POLICY_FEES_BLOCK_POLICY_ESTIMATOR_H
#define BITCOIN_POLICY_FEES_BLOCK_POLICY_ESTIMATOR_H

#include <consensus/amount.h>
#include <kernel/mempool_removal_reason.h>
#include <policy/feerate.h>
#include <policy/fees/chunk_confirm_stats.h>
#include <random.h>
#include <sync.h>
#include <uint256.h>
#include <util/expected.h>
#include <util/feefrac.h>
#include <util/fees.h>
#include <util/fs.h>

#include <array>
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>


/** Block policy estimate files that are more than 60 hours (2.5 days) old will not be read,
 * as fee estimates are based on historical data and may be inaccurate if
 * network activity has changed.
 */
inline constexpr std::chrono::hours MAX_FILE_AGE{60};

// Whether we allow importing a fee_estimates file older than MAX_FILE_AGE.
inline constexpr bool DEFAULT_ACCEPT_STALE_FEE_ESTIMATES{false};

class AutoFile;
struct MemPoolChunk;
struct MemPoolChunksUpdate;

/* Identifier for each of the 3 different ChunkConfirmStats which will track
 * history over different time horizons. */
enum class FeeEstimateHorizon {
    SHORT_HALFLIFE,
    MED_HALFLIFE,
    LONG_HALFLIFE,
};

inline constexpr auto ALL_FEE_ESTIMATE_HORIZONS = std::array{
    FeeEstimateHorizon::SHORT_HALFLIFE,
    FeeEstimateHorizon::MED_HALFLIFE,
    FeeEstimateHorizon::LONG_HALFLIFE,
};

std::string StringForFeeEstimateHorizon(FeeEstimateHorizon horizon);

/* Enumeration of reason for returned fee estimate */
enum class BlockPolicyEstimateReason {
    NONE,
    HALF_ESTIMATE,
    FULL_ESTIMATE,
    DOUBLE_ESTIMATE,
    CONSERVATIVE,
};

std::string StringForBlockPolicyEstimateReason(BlockPolicyEstimateReason reason);

std::string StringForChunkEndReason(MemPoolChunkEndReason reason);

using EstimatorBucket = ChunkConfirmStats::Bucket;
using EstimationResult = ChunkConfirmStats::Result;

struct FeeCalculation
{
    EstimationResult est;
    BlockPolicyEstimateReason reason = BlockPolicyEstimateReason::NONE;
    int desiredTarget = 0;
    int returnedTarget = 0;
    unsigned int best_height{0};
};

/** Estimate confirmation fees from continuously observed mempool chunks.
 *
 * Each eligible chunk is one observation: its exact membership, aggregate
 * fee/weight, and the height when that configuration became observable.
 * Unchanged configurations retain their original age. Only a producer-proven
 * usable full confirmation immediately records success for every target it met.
 * Remaining observations enter each target at start+target: a known miss is a
 * failure; an earlier ending is unknown. Successes decay from confirmation;
 * failures and unknowns decay from their deadline. Aggregated cohorts retain
 * unresolved targets for at most 1008 blocks. Gaps close active
 * observations as unknown; reorgs cold-reset historical and pending evidence.
 * Estimates use successes and known failures. Unknowns are diagnostic only and
 * do not contribute to the success ratio, sample support, or average feerates.
 *
 * processMempoolUpdate is the sole clock input, including empty block updates.
 */
class CBlockPolicyEstimator
{
private:
    /** Track confirm delays up to 12 blocks for short horizon */
    static constexpr unsigned int SHORT_BLOCK_PERIODS = 12;
    static constexpr unsigned int SHORT_SCALE = 1;
    /** Track confirm delays up to 48 blocks for medium horizon */
    static constexpr unsigned int MED_BLOCK_PERIODS = 24;
    static constexpr unsigned int MED_SCALE = 2;
    /** Track confirm delays up to 1008 blocks for long horizon */
    static constexpr unsigned int LONG_BLOCK_PERIODS = 42;
    static constexpr unsigned int LONG_SCALE = 24;
    /** Historical estimates that are older than this aren't valid */
    static constexpr unsigned int OLDEST_ESTIMATE_HISTORY{6 * 1008};

    /** Decay of .962 is a half-life of 18 blocks or about 3 hours */
    static constexpr double SHORT_DECAY = .962;
    /** Decay of .9952 is a half-life of 144 blocks or about 1 day */
    static constexpr double MED_DECAY = .9952;
    /** Decay of .99931 is a half-life of 1008 blocks or about 1 week */
    static constexpr double LONG_DECAY = .99931;

    /** Require greater than 60% of X feerate chunks to be confirmed within Y/2 blocks*/
    static constexpr double HALF_SUCCESS_PCT = .6;
    /** Require greater than 85% of X feerate chunks to be confirmed within Y blocks*/
    static constexpr double SUCCESS_PCT = .85;
    /** Require greater than 95% of X feerate chunks to be confirmed within 2 * Y blocks*/
    static constexpr double DOUBLE_SUCCESS_PCT = .95;

    /** Require an avg of 0.1 chunk in the combined feerate bucket per block to have stat significance */
    static constexpr double SUFFICIENT_FEE_CHUNKS = 0.1;
    /** Require an avg of 0.5 chunk when using short decay since there are fewer blocks considered*/
    static constexpr double SUFFICIENT_CHUNKS_SHORT = 0.5;

    /** Minimum and Maximum values for tracking feerates
     * The MIN_BUCKET_FEERATE should just be set to the lowest reasonable feerate.
     * MIN_BUCKET_FEERATE has historically inherited DEFAULT_MIN_RELAY_TX_FEE.
     * It is hardcoded because changing it is disruptive, as it invalidates existing fee
     * estimate files.
     *
     * Whenever DEFAULT_MIN_RELAY_TX_FEE changes, this value should be updated
     * accordingly. At the same time CURRENT_FEES_FILE_VERSION should be bumped.
     */
    static constexpr double MIN_BUCKET_FEERATE = 100;
    static constexpr double MAX_BUCKET_FEERATE = 1e7;

    /** Spacing of FeeRate buckets
     * We have to lump chunks into buckets based on feerate, but we want to be able
     * to give accurate estimates over a large range of potential feerates
     * Therefore it makes sense to exponentially space the buckets
     */
    static constexpr double FEE_SPACING = 1.05;

    const fs::path m_estimation_filepath;
public:
    /** Create new BlockPolicyEstimator and initialize stats tracking classes with default values */
    CBlockPolicyEstimator(const fs::path& estimation_filepath, bool read_stale_estimates);
    virtual ~CBlockPolicyEstimator();

    /** Consume an owned, ordered chunk transition, advancing block statistics once. */
    void processMempoolUpdate(const MemPoolChunksUpdate& update)
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** Check pending counters against live observations; intended for tests/fuzzing. */
    void SanityCheck() const EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** DEPRECATED. Return a feerate estimate */
    CFeeRate estimateFee(int confTarget) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** Estimate the feerate needed to confirm within confTarget blocks.
     *  After normalizing and limiting the target to available history, return
     *  the lowest valid smart estimate at that target or any tighter target
     *  down to 2. This prevents a looser target from raising the estimate.
     *  feeCalc reports the winning target and its calculation, preferring the
     *  largest target on ties. 'conservative' candidates retain the economical
     *  estimate as a floor and also check longer time horizons, so their quote
     *  cannot be lower. Return zero if no candidate gives a positive estimate.
     */
    virtual CFeeRate estimateSmartFee(int confTarget, FeeCalculation *feeCalc, bool conservative) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** Return a specific fee estimate calculation with a given success
     * threshold and time horizon, and optionally return detailed data about
     * calculation
     */
    CFeeRate estimateRawFee(int confTarget, double successThreshold, FeeEstimateHorizon horizon,
                            EstimationResult* result = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** Write estimation data to a file */
    bool Write(AutoFile& fileout) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** Read estimation data from a file */
    bool Read(AutoFile& filein)
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** End active observations as observation loss, preserving their established target outcomes. */
    void FlushUnconfirmed()
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** Calculation of highest target that estimates are tracked for */
    virtual unsigned int HighestTargetTracked(FeeEstimateHorizon horizon) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** Drop still unconfirmed chunks and record current estimations, if the fee estimation file is present. */
    void Flush()
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** Record current fee estimations. */
    void FlushFeeEstimates()
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** Calculates the age of the file, since last modified */
    std::chrono::hours GetFeeEstimatorFileAge();

    /** Return the highest confirmation target for which an estimate can be provided. */
    unsigned int MaximumTarget() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);

    /** Estimate the feerate needed to confirm within @p target blocks; wraps estimateSmartFee into a FeeRateEstimation. */
    util::Expected<FeeRateEstimation, FeeRateEstimationError> EstimateFeeRate(int target, bool conservative) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_cs_fee_estimator);


private:
    mutable Mutex m_cs_fee_estimator;

    unsigned int nBestSeenHeight GUARDED_BY(m_cs_fee_estimator){0};
    unsigned int firstRecordedHeight GUARDED_BY(m_cs_fee_estimator){0};
    unsigned int historicalFirst GUARDED_BY(m_cs_fee_estimator){0};
    unsigned int historicalBest GUARDED_BY(m_cs_fee_estimator){0};

    struct ChunkStatsInfo
    {
        unsigned int blockHeight;
        unsigned int bucketIndex;
        FeeFrac observed_fee_weight;
        uint64_t observation_id;
    };

    // Membership hash -> the economic configuration under observation.
    std::map<uint256, ChunkStatsInfo> mapMemPoolChunks GUARDED_BY(m_cs_fee_estimator);
    std::optional<uint64_t> m_last_sequence GUARDED_BY(m_cs_fee_estimator);
    std::optional<unsigned int> m_observation_height GUARDED_BY(m_cs_fee_estimator);
    std::array<uint64_t, NUM_CHUNK_END_REASONS> m_endings GUARDED_BY(m_cs_fee_estimator){};
    uint64_t m_next_observation_id GUARDED_BY(m_cs_fee_estimator){0};
    unsigned int m_resolved_height GUARDED_BY(m_cs_fee_estimator){0};

    /** Classes to track historical data on chunk confirmations */
    std::unique_ptr<ChunkConfirmStats> feeStats PT_GUARDED_BY(m_cs_fee_estimator);
    std::unique_ptr<ChunkConfirmStats> shortStats PT_GUARDED_BY(m_cs_fee_estimator);
    std::unique_ptr<ChunkConfirmStats> longStats PT_GUARDED_BY(m_cs_fee_estimator);

    std::vector<double> buckets GUARDED_BY(m_cs_fee_estimator); // The upper-bound of the range for the bucket (inclusive)
    std::map<double, unsigned int> bucketMap GUARDED_BY(m_cs_fee_estimator); // Map of bucket upper-bound to index into all vectors by bucket

    /** Number of blocks of data recorded while fee estimates have been running */
    unsigned int BlockSpan() const EXCLUSIVE_LOCKS_REQUIRED(m_cs_fee_estimator);
    /** Number of blocks of recorded fee estimate data represented in saved data file */
    unsigned int HistoricalBlockSpan() const EXCLUSIVE_LOCKS_REQUIRED(m_cs_fee_estimator);
    /** Calculation of highest target that reasonable estimate can be provided for */
    unsigned int MaxUsableEstimate() const EXCLUSIVE_LOCKS_REQUIRED(m_cs_fee_estimator);

    void ClearUnconfirmed() EXCLUSIVE_LOCKS_REQUIRED(m_cs_fee_estimator);
    void ResetHistory(unsigned int height) EXCLUSIVE_LOCKS_REQUIRED(m_cs_fee_estimator);
    void AdvanceClock(unsigned int height) EXCLUSIVE_LOCKS_REQUIRED(m_cs_fee_estimator);
    void StartChunk(const MemPoolChunk& chunk, unsigned int height) EXCLUSIVE_LOCKS_REQUIRED(m_cs_fee_estimator);
    bool EndChunk(const uint256& hash, MemPoolChunkEndReason outcome) EXCLUSIVE_LOCKS_REQUIRED(m_cs_fee_estimator);
};

class FeeFilterRounder
{
private:
    static constexpr double MAX_FILTER_FEERATE = 1e7;
    /** FEE_FILTER_SPACING is just used to provide some quantization of fee
     * filter results.  Historically it reused FEE_SPACING, but it is completely
     * unrelated, and was made a separate constant so the two concepts are not
     * tied together */
    static constexpr double FEE_FILTER_SPACING = 1.1;

public:
    /** Create new FeeFilterRounder */
    explicit FeeFilterRounder(const CFeeRate& min_incremental_fee, FastRandomContext& rng);

    /** Quantize a minimum fee for privacy purpose before broadcast. */
    CAmount round(CAmount currentMinFee) EXCLUSIVE_LOCKS_REQUIRED(!m_insecure_rand_mutex);

private:
    const std::set<double> m_fee_set;
    Mutex m_insecure_rand_mutex;
    FastRandomContext& insecure_rand GUARDED_BY(m_insecure_rand_mutex);
};

#endif // BITCOIN_POLICY_FEES_BLOCK_POLICY_ESTIMATOR_H
