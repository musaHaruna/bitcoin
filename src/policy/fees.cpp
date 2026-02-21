// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/fees.h>

#include <common/system.h>
#include <consensus/amount.h>
#include <kernel/mempool_entry.h>
#include <logging.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/serfloat.h>
#include <util/time.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <stdexcept>
#include <utility>

// The current format written, and the version required to read. Must be
// increased to at least 289900+1 on the next breaking change.
constexpr int CURRENT_FEES_FILE_VERSION{149900};

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

/**
 * We will instantiate an instance of this class to track transactions that were
 * included in a block. We will lump transactions into a bucket according to their
 * approximate feerate and then track how long it took for those txs to be included in a block
 *
 * The tracking of unconfirmed (mempool) transactions is completely independent of the
 * historical tracking of transactions that have been confirmed in a block.
 */
class TxConfirmStats
{
private:
    //Define the buckets we will group transactions into
    const std::vector<double>& buckets;              // The upper-bound of the range for the bucket (inclusive)
    const std::map<double, unsigned int>& bucketMap; // Map of bucket upper-bound to index into all vectors by bucket

    // For each bucket X:
    // Count the total # of txs in each bucket
    // Track the historical moving average of this total over blocks
    std::vector<double> txCtAvg;

    // Count the total # of txs confirmed within Y blocks in each bucket
    // Track the historical moving average of these totals over blocks
    std::vector<std::vector<double>> confAvg; // confAvg[Y][X]

    // Track moving avg of txs which have been evicted from the mempool
    // after failing to be confirmed within Y blocks
    std::vector<std::vector<double>> failAvg; // failAvg[Y][X]

    // Sum the total feerate of all tx's in each bucket
    // Track the historical moving average of this total over blocks
    std::vector<double> m_feerate_avg;

    // Combine the conf counts with tx counts to calculate the confirmation % for each Y,X
    // Combine the total value with the tx counts to calculate the avg feerate per bucket

    double decay;

    // Resolution (# of blocks) with which confirmations are tracked
    unsigned int scale;

    // Mempool counts of outstanding transactions
    // For each bucket X, track the number of transactions in the mempool
    // that are unconfirmed for each possible confirmation value Y
    std::vector<std::vector<int> > unconfTxs;  //unconfTxs[Y][X]
    // transactions still unconfirmed after GetMaxConfirms for each bucket
    std::vector<int> oldUnconfTxs;

    void resizeInMemoryCounters(size_t newbuckets);

public:
    /**
     * Create new TxConfirmStats. This is called by BlockPolicyEstimator's
     * constructor with default values.
     * @param defaultBuckets contains the upper limits for the bucket boundaries
     * @param maxPeriods max number of periods to track
     * @param decay how much to decay the historical moving average per block
     */
    TxConfirmStats(const std::vector<double>& defaultBuckets, const std::map<double, unsigned int>& defaultBucketMap,
                   unsigned int maxPeriods, double decay, unsigned int scale);

    /** Roll the circular buffer for unconfirmed txs*/
    void ClearCurrent(unsigned int nBlockHeight);

    /**
     * Record a new transaction data point in the current block stats
     * @param blocksToConfirm the number of blocks it took this transaction to confirm
     * @param val the feerate of the transaction
     * @warning blocksToConfirm is 1-based and has to be >= 1
     */
    void Record(int blocksToConfirm, double val);

    /** Record a new transaction entering the mempool*/
    unsigned int NewTx(unsigned int nBlockHeight, double val);

    /** Remove a transaction from mempool tracking stats*/
    void removeTx(unsigned int entryHeight, unsigned int nBestSeenHeight,
                  unsigned int bucketIndex, bool inBlock);

    /** Update our estimates by decaying our historical moving average and updating
        with the data gathered from the current block */
    void UpdateMovingAverages();

    /**
     * Calculate a feerate estimate.  Find the lowest value bucket (or range of buckets
     * to make sure we have enough data points) whose transactions still have sufficient likelihood
     * of being confirmed within the target number of confirmations
     * @param confTarget target number of confirmations
     * @param sufficientTxVal required average number of transactions per block in a bucket range
     * @param minSuccess the success probability we require
     * @param nBlockHeight the current block height
     */
    double EstimateMedianVal(int confTarget, double sufficientTxVal,
                             double minSuccess, unsigned int nBlockHeight,
                             EstimationResult *result = nullptr) const;

    /** Return the max number of confirms we're tracking */
    unsigned int GetMaxConfirms() const { return scale * confAvg.size(); }

    /** Write state of estimation data to a file*/
    void Write(AutoFile& fileout) const;

    /**
     * Read saved state of estimation data from a file and replace all internal data structures and
     * variables with this state.
     */
    void Read(AutoFile& filein, size_t numBuckets);
};


TxConfirmStats::TxConfirmStats(const std::vector<double>& defaultBuckets,
                                const std::map<double, unsigned int>& defaultBucketMap,
                               unsigned int maxPeriods, double _decay, unsigned int _scale)
    : buckets(defaultBuckets), bucketMap(defaultBucketMap), decay(_decay), scale(_scale)
{
    assert(_scale != 0 && "_scale must be non-zero");
    confAvg.resize(maxPeriods);
    failAvg.resize(maxPeriods);
    for (unsigned int i = 0; i < maxPeriods; i++) {
        confAvg[i].resize(buckets.size());
        failAvg[i].resize(buckets.size());
    }

    txCtAvg.resize(buckets.size());
    m_feerate_avg.resize(buckets.size());

    resizeInMemoryCounters(buckets.size());
}

void TxConfirmStats::resizeInMemoryCounters(size_t newbuckets) {
    // newbuckets must be passed in because the buckets referred to during Read have not been updated yet.
    unconfTxs.resize(GetMaxConfirms());
    for (unsigned int i = 0; i < unconfTxs.size(); i++) {
        unconfTxs[i].resize(newbuckets);
    }
    oldUnconfTxs.resize(newbuckets);
}

// Roll the unconfirmed txs circular buffer
void TxConfirmStats::ClearCurrent(unsigned int nBlockHeight)
{
    for (unsigned int j = 0; j < buckets.size(); j++) {
        oldUnconfTxs[j] += unconfTxs[nBlockHeight % unconfTxs.size()][j];
        unconfTxs[nBlockHeight%unconfTxs.size()][j] = 0;
    }
}


void TxConfirmStats::Record(int blocksToConfirm, double feerate)
{
    // blocksToConfirm is 1-based
    if (blocksToConfirm < 1)
        return;
    int periodsToConfirm = (blocksToConfirm + scale - 1) / scale;
    unsigned int bucketindex = bucketMap.lower_bound(feerate)->second;
    for (size_t i = periodsToConfirm; i <= confAvg.size(); i++) {
        confAvg[i - 1][bucketindex]++;
    }
    txCtAvg[bucketindex]++;
    m_feerate_avg[bucketindex] += feerate;
}

void TxConfirmStats::UpdateMovingAverages()
{
    assert(confAvg.size() == failAvg.size());
    for (unsigned int j = 0; j < buckets.size(); j++) {
        for (unsigned int i = 0; i < confAvg.size(); i++) {
            confAvg[i][j] *= decay;
            failAvg[i][j] *= decay;
        }
        m_feerate_avg[j] *= decay;
        txCtAvg[j] *= decay;
    }
}

// returns -1 on error conditions
double TxConfirmStats::EstimateMedianVal(int confTarget, double sufficientTxVal,
                                         double successBreakPoint, unsigned int nBlockHeight,
                                         EstimationResult *result) const
{
    // High-level start log
    LogDebug(BCLog::ESTIMATEFEE,
        "EstimateMedianVal START: confTarget=%d, sufficientTxVal=%.2f, successBreakPoint=%.2f, nBlockHeight=%u, scale=%u, numBuckets=%zu\n",
        confTarget, sufficientTxVal, successBreakPoint, nBlockHeight, scale, buckets.size());
    LogDebug(BCLog::ESTIMATEFEE,
        "Interpretation: confTarget=%d means we want transactions to confirm within %d block(s). "
        "scale=%u means confirmation data are stored at resolution=%u (periods are coarser/finer accordingly).\n",
        confTarget, confTarget, scale, scale);
    // Counters for a bucket (or range of buckets)
    double nConf = 0; // Number of tx's confirmed within the confTarget
    double totalNum = 0; // Total number of tx's that were ever confirmed
    int extraNum = 0;  // Number of tx's still in mempool for confTarget or longer
    double failNum = 0; // Number of tx's that were never confirmed but removed from the mempool after confTarget
    const int periodTarget = (confTarget + scale - 1) / scale;
    const int maxbucketindex = buckets.size() - 1;

    LogDebug(BCLog::ESTIMATEFEE,
        "confTarget=%d blocks → periodTarget=%d (which period in historical stats we use for this target).",
        confTarget, periodTarget);

    // We'll combine buckets until we have enough samples.
    // The near and far variables will define the range we've combined
    // The best variables are the last range we saw which still had a high
    // enough confirmation rate to count as success.
    // The cur variables are the current range we're counting.
    unsigned int curNearBucket = maxbucketindex;
    unsigned int bestNearBucket = maxbucketindex;
    unsigned int curFarBucket = maxbucketindex;
    unsigned int bestFarBucket = maxbucketindex;

    // Minimum-data threshold 
    double neededPerRange = sufficientTxVal / (1 - decay);
    LogDebug(BCLog::ESTIMATEFEE,
    "Sampling check: We want at least %.2f transactions in this feerate range to trust the estimate. "
    "Older data is weighted by decay=%.5f, so after adjusting for that we need about %.2f effective historical transactions.\n",
    sufficientTxVal, decay, neededPerRange);
    // We'll always group buckets into sets that meet sufficientTxVal --
    // this ensures that we're using consistent groups between different
    // confirmation targets.
    double partialNum = 0;

    bool foundAnswer = false;
    unsigned int bins = unconfTxs.size();
    bool newBucketRange = true;
    bool passing = true;
    EstimatorBucket passBucket;
    EstimatorBucket failBucket;

    // Start counting from highest feerate transactions
    for (int bucket = maxbucketindex; bucket >= 0; --bucket) {
        if (newBucketRange) {
            curNearBucket = bucket;
            newBucketRange = false;
            //Starting bucket
            LogDebug(BCLog::ESTIMATEFEE,
            "Analyzing a new set of transaction buckets starting at index %d. "
            "Transactions in this starting bucket have fees up to %.8g satoshis per virtual byte.\n",
            curNearBucket, buckets[curNearBucket]);
        }
        curFarBucket = bucket;
        nConf += confAvg[periodTarget - 1][bucket];
        partialNum += txCtAvg[bucket];
        totalNum += txCtAvg[bucket];
        failNum += failAvg[periodTarget - 1][bucket];
        for (unsigned int confct = confTarget; confct < GetMaxConfirms(); confct++)
            extraNum += unconfTxs[(nBlockHeight - confct) % bins][bucket];
        extraNum += oldUnconfTxs[bucket];
        // If we have enough transaction data points in this range of buckets,
        // we can test for success
        // (Only count the confirmed data points, so that each confirmation count
        // will be looking at the same amount of data and same bucket breaks)

        // Show info about the current fee bucket we are analyzing
        LogDebug(BCLog::ESTIMATEFEE,
            "Checking bucket %d (transactions with fees up to %.8g sats/vB): "
            "historical transactions ~%.2f, confirmed within target ~%.2f, "
            "dropped after target ~%.2f, currently still unconfirmed for target=%d, "
            "older unconfirmed transactions=%d",
            bucket,                  // Bucket index
            buckets[bucket],         // Max fee in this bucket
            txCtAvg[bucket],         // Average number of tx historically in this bucket
            confAvg[periodTarget-1][bucket], // Number confirmed within target
            failAvg[periodTarget-1][bucket], // Number dropped after target
            unconfTxs[(nBlockHeight - confTarget) % bins][bucket], // Still waiting in mempool
            oldUnconfTxs[bucket]);   // Old unconfirmed txs from previous periods

        // What each important value above means 
        LogDebug(BCLog::ESTIMATEFEE,
            "Explanation: txCtAvg=%.2f is the average number of transactions historically seen in this fee range. "
            "confAvg=%.2f is how many of those confirmed within the target number of blocks. "
            "failAvg=%.2f is how many left the mempool unconfirmed after the target. "
            "Currently unconfirmed in mempool = %d",
            txCtAvg[bucket], confAvg[periodTarget-1][bucket], failAvg[periodTarget-1][bucket],
            unconfTxs[(nBlockHeight - confTarget) % bins][bucket]);
                
        // Show the cumulative range of buckets currently being considered for fee estimation
        LogDebug(BCLog::ESTIMATEFEE,
            "Current bucket range from %d to %d: total historical tx units in this range = %.2f, "
            "minimum required for stable estimate = %.2f",
            curNearBucket, curFarBucket, partialNum, neededPerRange);
        // If we don't have enough samples yet, continue accumulating more buckets.
        if (partialNum < sufficientTxVal / (1 - decay)) {
            // the buckets we've added in this round aren't sufficient
            // so keep adding
            double missing = neededPerRange - partialNum;
            LogDebug(BCLog::ESTIMATEFEE,
                "Not enough historical data in current bucket range %d-%d: need ~%.2f more 'historical tx units' before we can test success probability. Continuing to add lower-fee buckets.\n",
                curNearBucket, curFarBucket, missing);
            continue;
        } else {
            partialNum = 0; // reset for the next range we'll add

            double curPct = nConf / (totalNum + failNum + extraNum);
            // Show the raw numbers for the current fee bucket range being tested
            LogDebug(BCLog::ESTIMATEFEE,
                "Checking fee bucket range %d to %d (higher fees first):\n"
                "  Transactions confirmed within target (%d blocks): %.2f\n"
                "  Total transactions ever confirmed in this range: %.2f\n"
                "  Transactions that left the mempool unconfirmed after target: %.2f\n"
                "  Transactions currently still waiting in mempool beyond target: %d\n",
                curNearBucket, curFarBucket, confTarget,
                nConf, totalNum, failNum, extraNum);

            // The success percentage (curPct)
            LogDebug(BCLog::ESTIMATEFEE,
                "Calculated success rate for this fee range (curPct) = %.4f which %.2f%%\n in percent"
                "Explanation: Based on historical confirmations, transactions that left unconfirmed, "
                "and those still pending, a transaction paying this fee has roughly %.2f%% chance "
                "of confirming within %d block(s).\n",
                curPct, 100.0 * curPct, 100.0 * curPct, confTarget);
            // Check to see if we are no longer getting confirmed at the success rate
            if (curPct < successBreakPoint) {
                if (passing == true) {
                    // First time we hit a failure record the failed bucket
                    LogDebug(BCLog::ESTIMATEFEE,
                    "FAIL: The transaction fee range from bucket %d to %d did NOT meet the target confirmation rate.\n"
                    "      Current success rate = %.2f (%.2f%%), which is below the required %.2f (%.2f%%).\n",
                    curNearBucket, curFarBucket, curPct, 100.0 * curPct, successBreakPoint, 100.0 * successBreakPoint);
                    unsigned int failMinBucket = std::min(curNearBucket, curFarBucket);
                    unsigned int failMaxBucket = std::max(curNearBucket, curFarBucket);
                    failBucket.start = failMinBucket ? buckets[failMinBucket - 1] : 0;
                    failBucket.end = buckets[failMaxBucket];
                    failBucket.withinTarget = nConf;
                    failBucket.totalConfirmed = totalNum;
                    failBucket.inMempool = extraNum;
                    failBucket.leftMempool = failNum;
                    LogDebug(BCLog::ESTIMATEFEE,
                        "Why it may have failed:\n"
                        "  - Not enough historical transaction data in this fee range (small sample size, noisy data).\n"
                        "  - Many transactions are still unconfirmed in the mempool (extraNum=%d), lowering the effective success rate.\n",
                        extraNum);
                    passing = false;
                }
                continue;
            }
            // Otherwise update the cumulative stats, and the bucket variables
            // and reset the counters
            else {
                failBucket = EstimatorBucket(); // Reset any failed bucket, currently passing
                foundAnswer = true;
                passing = true;
                passBucket.withinTarget = nConf;
                nConf = 0;
                passBucket.totalConfirmed = totalNum;
                totalNum = 0;
                passBucket.inMempool = extraNum;
                passBucket.leftMempool = failNum;
                failNum = 0;
                extraNum = 0;
                bestNearBucket = curNearBucket;
                bestFarBucket = curFarBucket;
                newBucketRange = true;
                LogDebug(BCLog::ESTIMATEFEE,
                    "PASS BucketRange %d-%d: This fee range meets success requirements (curPct=%.4f >= %.4f).\n"
                    "Interpretation: historically, a transaction paying a fee within (%.8g - %.8g) sats/vB "
                    "had roughly a %.2f%% chance to confirm within %d block(s) (including outstanding & evicted txs in calculation).\n",
                    curNearBucket, curFarBucket, curPct, successBreakPoint,
                    (curNearBucket ? buckets[curNearBucket - 1] : 0.0), buckets[curFarBucket],
                    100.0 * (passBucket.withinTarget / (passBucket.totalConfirmed + passBucket.inMempool + passBucket.leftMempool)),
                    confTarget);
            }
        }
    }

    double median = -1;
    double txSum = 0;

    // Calculate the "average" feerate of the best bucket range that met success conditions
    // Find the bucket with the median transaction and then report the average feerate from that bucket
    // This is a compromise between finding the median which we can't since we don't save all tx's
    // and reporting the average which is less accurate
    unsigned int minBucket = std::min(bestNearBucket, bestFarBucket);
    unsigned int maxBucket = std::max(bestNearBucket, bestFarBucket);
    for (unsigned int j = minBucket; j <= maxBucket; j++) {
        txSum += txCtAvg[j];
    }
    if (foundAnswer && txSum != 0) {
        txSum = txSum / 2;
        for (unsigned int j = minBucket; j <= maxBucket; j++) {
            if (txCtAvg[j] < txSum)
                txSum -= txCtAvg[j];
            else { // we're in the right bucket
                // We pick the average feerate recorded for bucket j as the median approximation
                median = m_feerate_avg[j] / txCtAvg[j];
                LogDebug(BCLog::ESTIMATEFEE,
                    "Median selection: the middle transaction falls in bucket index %u, "
                    "which includes all transactions paying up to %.8g sats/vB.\n"
                    "This bucket has %.2f 'historical transaction units', meaning the midpoint of all past transactions landed here.\n"
                    "Calculated median fee for this bucket = total fees in bucket / number of transactions = %.8f sats/vB.\n",
                j, buckets[j], txCtAvg[j], median);
                break;
            }
        }

        passBucket.start = minBucket ? buckets[minBucket-1] : 0;
        passBucket.end = buckets[maxBucket];
        LogDebug(BCLog::ESTIMATEFEE,
            "Final passing range: (%.8g - %.8g) sats/vB. Approximate median for that range: %.8f sats/vB\n",
            passBucket.start, passBucket.end, median);
    } else {
        if (!foundAnswer) {
            LogDebug(BCLog::ESTIMATEFEE,
                "Fee estimation could not find any reliable fee range.\n"
                "Possible reasons:\n"
                "  - Not enough historical transactions in any fee bucket to make a confident estimate.\n"
                "  - The required success rate (successBreakPoint = %.2f) is higher than what we ever observed.\n"
                "  - Many transactions are still unconfirmed in the mempool, lowering the success rate.\n"
                "  - The node has little or no historical data (recent startup or reindex).\n"
                "  - Unusual miner behavior or full blocks affected the observed data.\n",
                successBreakPoint);
        } else {
            // foundAnswer==true but txSum==0 (degenerate); explain this improbable case
            LogDebug(BCLog::ESTIMATEFEE,
                "Warning: A fee range passed the success threshold, but no historical transactions were recorded in that range (txSum = 0). "
                "This suggests an internal data issue or missing statistics; median fee cannot be computed reliably.\n");
        }
    }

    // If we were passing until we reached last few buckets with insufficient data, then report those as failed
    if (passing && !newBucketRange) {
        unsigned int failMinBucket = std::min(curNearBucket, curFarBucket);
        unsigned int failMaxBucket = std::max(curNearBucket, curFarBucket);
        failBucket.start = failMinBucket ? buckets[failMinBucket - 1] : 0;
        failBucket.end = buckets[failMaxBucket];
        failBucket.withinTarget = nConf;
        failBucket.totalConfirmed = totalNum;
        failBucket.inMempool = extraNum;
        failBucket.leftMempool = failNum;
        LogDebug(BCLog::ESTIMATEFEE,
            "Edge case detected: the loop ended while a fee range was still passing, "
            "but a new range was not started. For diagnostic purposes, reporting this trailing range as failed: %.8g - %.8g sats/vB.\n",
            failBucket.start, failBucket.end);
    }

    float passed_within_target_perc = 0.0;
    float failed_within_target_perc = 0.0;
    if ((passBucket.totalConfirmed + passBucket.inMempool + passBucket.leftMempool)) {
        passed_within_target_perc = 100 * passBucket.withinTarget / (passBucket.totalConfirmed + passBucket.inMempool + passBucket.leftMempool);
    }
    if ((failBucket.totalConfirmed + failBucket.inMempool + failBucket.leftMempool)) {
        failed_within_target_perc = 100 * failBucket.withinTarget / (failBucket.totalConfirmed + failBucket.inMempool + failBucket.leftMempool);
    }

    // Final debug line summarizing what the estimator concluded with plain English aids
    LogDebug(BCLog::ESTIMATEFEE,
        "FeeEst Summary: target=%d required_success=%.0f%% decay=%.5f -> estimated median: %g sats/vB\n"
        "Passing range: (%.8g - %.8g) sats/vB -> success rate ~%.2f%% (%g/%g total+mem+left)\n"
        "Failing range: (%.8g - %.8g) sats/vB -> success rate ~%.2f%% (%g/%g total+mem+left)\n",
        confTarget, 100.0 * successBreakPoint, decay,
        median,
        passBucket.start, passBucket.end, passed_within_target_perc,
        passBucket.withinTarget, (passBucket.totalConfirmed + passBucket.inMempool + passBucket.leftMempool),
        failBucket.start, failBucket.end, failed_within_target_perc,
        failBucket.withinTarget, (failBucket.totalConfirmed + failBucket.inMempool + failBucket.leftMempool)
    );

    // Extra node message on failure vs success with suggestions
    if (!foundAnswer) {
        LogPrintf("EstimateMedianVal FAILED: confTarget=%d, scale=%u, no bucket range met successBreakPoint.\n"
                  "Suggestions: check node's mempool state, ensure node has enough historical blocks (not just recently started),\n"
                  "try a lower success threshold or use a shorter horizon (shortStats) if you want a more reactive estimate.\n",
                  confTarget, scale);
    } else {
        LogPrintf("EstimateMedianVal SUCCESS: confTarget=%d, scale=%u, medianFee=%.8f sats/vB\n", confTarget, scale, median);
    }
    if (result) {
        result->pass = passBucket;
        result->fail = failBucket;
        result->decay = decay;
        result->scale = scale;
    }
    return median;
}

void TxConfirmStats::Write(AutoFile& fileout) const
{
    fileout << Using<EncodedDoubleFormatter>(decay);
    fileout << scale;
    fileout << Using<VectorFormatter<EncodedDoubleFormatter>>(m_feerate_avg);
    fileout << Using<VectorFormatter<EncodedDoubleFormatter>>(txCtAvg);
    fileout << Using<VectorFormatter<VectorFormatter<EncodedDoubleFormatter>>>(confAvg);
    fileout << Using<VectorFormatter<VectorFormatter<EncodedDoubleFormatter>>>(failAvg);
}

void TxConfirmStats::Read(AutoFile& filein, size_t numBuckets)
{
    // Read data file and do some very basic sanity checking
    // buckets and bucketMap are not updated yet, so don't access them
    // If there is a read failure, we'll just discard this entire object anyway
    size_t maxConfirms, maxPeriods;

    // The current version will store the decay with each individual TxConfirmStats and also keep a scale factor
    filein >> Using<EncodedDoubleFormatter>(decay);
    if (decay <= 0 || decay >= 1) {
        throw std::runtime_error("Corrupt estimates file. Decay must be between 0 and 1 (non-inclusive)");
    }
    filein >> scale;
    if (scale == 0) {
        throw std::runtime_error("Corrupt estimates file. Scale must be non-zero");
    }

    filein >> Using<VectorFormatter<EncodedDoubleFormatter>>(m_feerate_avg);
    if (m_feerate_avg.size() != numBuckets) {
        throw std::runtime_error("Corrupt estimates file. Mismatch in feerate average bucket count");
    }
    filein >> Using<VectorFormatter<EncodedDoubleFormatter>>(txCtAvg);
    if (txCtAvg.size() != numBuckets) {
        throw std::runtime_error("Corrupt estimates file. Mismatch in tx count bucket count");
    }
    filein >> Using<VectorFormatter<VectorFormatter<EncodedDoubleFormatter>>>(confAvg);
    maxPeriods = confAvg.size();
    maxConfirms = scale * maxPeriods;

    if (maxConfirms <= 0 || maxConfirms > 6 * 24 * 7) { // one week
        throw std::runtime_error("Corrupt estimates file.  Must maintain estimates for between 1 and 1008 (one week) confirms");
    }
    for (unsigned int i = 0; i < maxPeriods; i++) {
        if (confAvg[i].size() != numBuckets) {
            throw std::runtime_error("Corrupt estimates file. Mismatch in feerate conf average bucket count");
        }
    }

    filein >> Using<VectorFormatter<VectorFormatter<EncodedDoubleFormatter>>>(failAvg);
    if (maxPeriods != failAvg.size()) {
        throw std::runtime_error("Corrupt estimates file. Mismatch in confirms tracked for failures");
    }
    for (unsigned int i = 0; i < maxPeriods; i++) {
        if (failAvg[i].size() != numBuckets) {
            throw std::runtime_error("Corrupt estimates file. Mismatch in one of failure average bucket counts");
        }
    }

    // Resize the current block variables which aren't stored in the data file
    // to match the number of confirms and buckets
    resizeInMemoryCounters(numBuckets);

    LogDebug(BCLog::ESTIMATEFEE, "Reading estimates: %u buckets counting confirms up to %u blocks\n",
             numBuckets, maxConfirms);
}

unsigned int TxConfirmStats::NewTx(unsigned int nBlockHeight, double val)
{
    unsigned int bucketindex = bucketMap.lower_bound(val)->second;
    unsigned int blockIndex = nBlockHeight % unconfTxs.size();
    unconfTxs[blockIndex][bucketindex]++;
    return bucketindex;
}

void TxConfirmStats::removeTx(unsigned int entryHeight, unsigned int nBestSeenHeight, unsigned int bucketindex, bool inBlock)
{
    //nBestSeenHeight is not updated yet for the new block
    int blocksAgo = nBestSeenHeight - entryHeight;
    if (nBestSeenHeight == 0)  // the BlockPolicyEstimator hasn't seen any blocks yet
        blocksAgo = 0;
    if (blocksAgo < 0) {
        LogDebug(BCLog::ESTIMATEFEE, "Blockpolicy error, blocks ago is negative for mempool tx\n");
        return;  //This can't happen because we call this with our best seen height, no entries can have higher
    }

    if (blocksAgo >= (int)unconfTxs.size()) {
        if (oldUnconfTxs[bucketindex] > 0) {
            oldUnconfTxs[bucketindex]--;
        } else {
            LogDebug(BCLog::ESTIMATEFEE, "Blockpolicy error, mempool tx removed from >25 blocks,bucketIndex=%u already\n",
                     bucketindex);
        }
    }
    else {
        unsigned int blockIndex = entryHeight % unconfTxs.size();
        if (unconfTxs[blockIndex][bucketindex] > 0) {
            unconfTxs[blockIndex][bucketindex]--;
        } else {
            LogDebug(BCLog::ESTIMATEFEE, "Blockpolicy error, mempool tx removed from blockIndex=%u,bucketIndex=%u already\n",
                     blockIndex, bucketindex);
        }
    }
    if (!inBlock && (unsigned int)blocksAgo >= scale) { // Only counts as a failure if not confirmed for entire period
        assert(scale != 0);
        unsigned int periodsAgo = blocksAgo / scale;
        for (size_t i = 0; i < periodsAgo && i < failAvg.size(); i++) {
            failAvg[i][bucketindex]++;
        }
    }
}

bool CBlockPolicyEstimator::removeTx(uint256 hash)
{
    LOCK(m_cs_fee_estimator);
    return _removeTx(hash, /*inBlock=*/false);
}

bool CBlockPolicyEstimator::_removeTx(const uint256& hash, bool inBlock)
{
    AssertLockHeld(m_cs_fee_estimator);
    std::map<uint256, TxStatsInfo>::iterator pos = mapMemPoolTxs.find(hash);
    if (pos != mapMemPoolTxs.end()) {
        feeStats->removeTx(pos->second.blockHeight, nBestSeenHeight, pos->second.bucketIndex, inBlock);
        shortStats->removeTx(pos->second.blockHeight, nBestSeenHeight, pos->second.bucketIndex, inBlock);
        longStats->removeTx(pos->second.blockHeight, nBestSeenHeight, pos->second.bucketIndex, inBlock);
        mapMemPoolTxs.erase(hash);
        return true;
    } else {
        return false;
    }
}

CBlockPolicyEstimator::CBlockPolicyEstimator(const fs::path& estimation_filepath, const bool read_stale_estimates)
    : m_estimation_filepath{estimation_filepath}
{
    static_assert(MIN_BUCKET_FEERATE > 0, "Min feerate must be nonzero");
    size_t bucketIndex = 0;

    for (double bucketBoundary = MIN_BUCKET_FEERATE; bucketBoundary <= MAX_BUCKET_FEERATE; bucketBoundary *= FEE_SPACING, bucketIndex++) {
        buckets.push_back(bucketBoundary);
        bucketMap[bucketBoundary] = bucketIndex;
    }
    buckets.push_back(INF_FEERATE);
    bucketMap[INF_FEERATE] = bucketIndex;
    assert(bucketMap.size() == buckets.size());

    feeStats = std::unique_ptr<TxConfirmStats>(new TxConfirmStats(buckets, bucketMap, MED_BLOCK_PERIODS, MED_DECAY, MED_SCALE));
    shortStats = std::unique_ptr<TxConfirmStats>(new TxConfirmStats(buckets, bucketMap, SHORT_BLOCK_PERIODS, SHORT_DECAY, SHORT_SCALE));
    longStats = std::unique_ptr<TxConfirmStats>(new TxConfirmStats(buckets, bucketMap, LONG_BLOCK_PERIODS, LONG_DECAY, LONG_SCALE));

    AutoFile est_file{fsbridge::fopen(m_estimation_filepath, "rb")};

    if (est_file.IsNull()) {
        LogPrintf("%s is not found. Continue anyway.\n", fs::PathToString(m_estimation_filepath));
        return;
    }

    std::chrono::hours file_age = GetFeeEstimatorFileAge();
    if (file_age > MAX_FILE_AGE && !read_stale_estimates) {
        LogPrintf("Fee estimation file %s too old (age=%lld > %lld hours) and will not be used to avoid serving stale estimates.\n", fs::PathToString(m_estimation_filepath), Ticks<std::chrono::hours>(file_age), Ticks<std::chrono::hours>(MAX_FILE_AGE));
        return;
    }

    if (!Read(est_file)) {
        LogPrintf("Failed to read fee estimates from %s. Continue anyway.\n", fs::PathToString(m_estimation_filepath));
    }
}

CBlockPolicyEstimator::~CBlockPolicyEstimator() = default;

void CBlockPolicyEstimator::TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t /*unused*/)
{
    processTransaction(tx);
}

void CBlockPolicyEstimator::TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason /*unused*/, uint64_t /*unused*/)
{
    removeTx(tx->GetHash());
}

void CBlockPolicyEstimator::MempoolTransactionsRemovedForBlock(const std::vector<RemovedMempoolTransactionInfo>& txs_removed_for_block, unsigned int nBlockHeight)
{
    processBlock(txs_removed_for_block, nBlockHeight);
}

void CBlockPolicyEstimator::processTransaction(const NewMempoolTransactionInfo& tx)
{
    LOCK(m_cs_fee_estimator);
    const unsigned int txHeight = tx.info.txHeight;
    const auto& hash = tx.info.m_tx->GetHash();
    if (mapMemPoolTxs.count(hash)) {
        LogDebug(BCLog::ESTIMATEFEE, "Blockpolicy error mempool tx %s already being tracked\n",
                 hash.ToString());
        return;
    }

    if (txHeight != nBestSeenHeight) {
        // Ignore side chains and re-orgs; assuming they are random they don't
        // affect the estimate.  We'll potentially double count transactions in 1-block reorgs.
        // Ignore txs if BlockPolicyEstimator is not in sync with ActiveChain().Tip().
        // It will be synced next time a block is processed.
        return;
    }
    // This transaction should only count for fee estimation if:
    // - it's not being re-added during a reorg which bypasses typical mempool fee limits
    // - the node is not behind
    // - the transaction is not dependent on any other transactions in the mempool
    // - it's not part of a package.
    const bool validForFeeEstimation = !tx.m_mempool_limit_bypassed && !tx.m_submitted_in_package && tx.m_chainstate_is_current && tx.m_has_no_mempool_parents;

    // Only want to be updating estimates when our blockchain is synced,
    // otherwise we'll miscalculate how many blocks its taking to get included.
    if (!validForFeeEstimation) {
        untrackedTxs++;
        return;
    }
    trackedTxs++;

    // Feerates are stored and reported as BTC-per-kb:
    const CFeeRate feeRate(tx.info.m_fee, tx.info.m_virtual_transaction_size);

    mapMemPoolTxs[hash].blockHeight = txHeight;
    unsigned int bucketIndex = feeStats->NewTx(txHeight, static_cast<double>(feeRate.GetFeePerK()));
    mapMemPoolTxs[hash].bucketIndex = bucketIndex;
    unsigned int bucketIndex2 = shortStats->NewTx(txHeight, static_cast<double>(feeRate.GetFeePerK()));
    assert(bucketIndex == bucketIndex2);
    unsigned int bucketIndex3 = longStats->NewTx(txHeight, static_cast<double>(feeRate.GetFeePerK()));
    assert(bucketIndex == bucketIndex3);
}

bool CBlockPolicyEstimator::processBlockTx(unsigned int nBlockHeight, const RemovedMempoolTransactionInfo& tx)
{
    AssertLockHeld(m_cs_fee_estimator);
    if (!_removeTx(tx.info.m_tx->GetHash(), true)) {
        // This transaction wasn't being tracked for fee estimation
        return false;
    }

    // How many blocks did it take for miners to include this transaction?
    // blocksToConfirm is 1-based, so a transaction included in the earliest
    // possible block has confirmation count of 1
    int blocksToConfirm = nBlockHeight - tx.info.txHeight;
    if (blocksToConfirm <= 0) {
        // This can't happen because we don't process transactions from a block with a height
        // lower than our greatest seen height
        LogDebug(BCLog::ESTIMATEFEE, "Blockpolicy error Transaction had negative blocksToConfirm\n");
        return false;
    }

    // Feerates are stored and reported as BTC-per-kb:
    CFeeRate feeRate(tx.info.m_fee, tx.info.m_virtual_transaction_size);

    feeStats->Record(blocksToConfirm, static_cast<double>(feeRate.GetFeePerK()));
    shortStats->Record(blocksToConfirm, static_cast<double>(feeRate.GetFeePerK()));
    longStats->Record(blocksToConfirm, static_cast<double>(feeRate.GetFeePerK()));
    return true;
}

void CBlockPolicyEstimator::processBlock(const std::vector<RemovedMempoolTransactionInfo>& txs_removed_for_block,
                                         unsigned int nBlockHeight)
{
    LOCK(m_cs_fee_estimator);
    if (nBlockHeight <= nBestSeenHeight) {
        // Ignore side chains and re-orgs; assuming they are random
        // they don't affect the estimate.
        // And if an attacker can re-org the chain at will, then
        // you've got much bigger problems than "attacker can influence
        // transaction fees."
        return;
    }

    // Must update nBestSeenHeight in sync with ClearCurrent so that
    // calls to removeTx (via processBlockTx) correctly calculate age
    // of unconfirmed txs to remove from tracking.
    nBestSeenHeight = nBlockHeight;

    // Update unconfirmed circular buffer
    feeStats->ClearCurrent(nBlockHeight);
    shortStats->ClearCurrent(nBlockHeight);
    longStats->ClearCurrent(nBlockHeight);

    // Decay all exponential averages
    feeStats->UpdateMovingAverages();
    shortStats->UpdateMovingAverages();
    longStats->UpdateMovingAverages();

    unsigned int countedTxs = 0;
    // Update averages with data points from current block
    for (const auto& tx : txs_removed_for_block) {
        if (processBlockTx(nBlockHeight, tx))
            countedTxs++;
    }

    if (firstRecordedHeight == 0 && countedTxs > 0) {
        firstRecordedHeight = nBestSeenHeight;
        LogDebug(BCLog::ESTIMATEFEE, "Blockpolicy first recorded height %u\n", firstRecordedHeight);
    }


    LogDebug(BCLog::ESTIMATEFEE, "Blockpolicy estimates updated by %u of %u block txs, since last block %u of %u tracked, mempool map size %u, max target %u from %s\n",
             countedTxs, txs_removed_for_block.size(), trackedTxs, trackedTxs + untrackedTxs, mapMemPoolTxs.size(),
             MaxUsableEstimate(), HistoricalBlockSpan() > BlockSpan() ? "historical" : "current");

    trackedTxs = 0;
    untrackedTxs = 0;
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
    TxConfirmStats* stats = nullptr;
    double sufficientTxs = SUFFICIENT_FEETXS;
    switch (horizon) {
    case FeeEstimateHorizon::SHORT_HALFLIFE: {
        stats = shortStats.get();
        sufficientTxs = SUFFICIENT_TXS_SHORT;
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

    LOCK(m_cs_fee_estimator);
    // Return failure if trying to analyze a target we're not tracking
    if (confTarget <= 0 || (unsigned int)confTarget > stats->GetMaxConfirms())
        return CFeeRate(0);
    if (successThreshold > 1)
        return CFeeRate(0);

    double median = stats->EstimateMedianVal(confTarget, sufficientTxs, successThreshold, nBestSeenHeight, result);

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

/** Return a fee estimate at the required successThreshold from the shortest
 * time horizon which tracks confirmations up to the desired target.  If
 * checkShorterHorizon is requested, also allow short time horizon estimates
 * for a lower target to reduce the given answer */
double CBlockPolicyEstimator::estimateCombinedFee(unsigned int confTarget, double successThreshold, bool checkShorterHorizon, EstimationResult *result) const
{
    double estimate = -1;
    if (confTarget >= 1 && confTarget <= longStats->GetMaxConfirms()) {
        // Find estimate from shortest time horizon possible
        if (confTarget <= shortStats->GetMaxConfirms()) { // short horizon
            estimate = shortStats->EstimateMedianVal(confTarget, SUFFICIENT_TXS_SHORT, successThreshold, nBestSeenHeight, result);
        }
        else if (confTarget <= feeStats->GetMaxConfirms()) { // medium horizon
            estimate = feeStats->EstimateMedianVal(confTarget, SUFFICIENT_FEETXS, successThreshold, nBestSeenHeight, result);
        }
        else { // long horizon
            estimate = longStats->EstimateMedianVal(confTarget, SUFFICIENT_FEETXS, successThreshold, nBestSeenHeight, result);
        }
        if (checkShorterHorizon) {
            EstimationResult tempResult;
            // If a lower confTarget from a more recent horizon returns a lower answer use it.
            if (confTarget > feeStats->GetMaxConfirms()) {
                double medMax = feeStats->EstimateMedianVal(feeStats->GetMaxConfirms(), SUFFICIENT_FEETXS, successThreshold, nBestSeenHeight, &tempResult);
                if (medMax > 0 && (estimate == -1 || medMax < estimate)) {
                    estimate = medMax;
                    if (result) *result = tempResult;
                }
            }
            if (confTarget > shortStats->GetMaxConfirms()) {
                double shortMax = shortStats->EstimateMedianVal(shortStats->GetMaxConfirms(), SUFFICIENT_TXS_SHORT, successThreshold, nBestSeenHeight, &tempResult);
                if (shortMax > 0 && (estimate == -1 || shortMax < estimate)) {
                    estimate = shortMax;
                    if (result) *result = tempResult;
                }
            }
        }
    }
    return estimate;
}

/** Ensure that for a conservative estimate, the DOUBLE_SUCCESS_PCT is also met
 * at 2 * target for any longer time horizons.
 */
double CBlockPolicyEstimator::estimateConservativeFee(unsigned int doubleTarget, EstimationResult *result) const
{
    double estimate = -1;
    EstimationResult tempResult;
    if (doubleTarget <= shortStats->GetMaxConfirms()) {
        estimate = feeStats->EstimateMedianVal(doubleTarget, SUFFICIENT_FEETXS, DOUBLE_SUCCESS_PCT, nBestSeenHeight, result);
    }
    if (doubleTarget <= feeStats->GetMaxConfirms()) {
        double longEstimate = longStats->EstimateMedianVal(doubleTarget, SUFFICIENT_FEETXS, DOUBLE_SUCCESS_PCT, nBestSeenHeight, &tempResult);
        if (longEstimate > estimate) {
            estimate = longEstimate;
            if (result) *result = tempResult;
        }
    }
    return estimate;
}

/** estimateSmartFee returns the max of the feerates calculated with a 60%
 * threshold required at target / 2, an 85% threshold required at target and a
 * 95% threshold required at 2 * target.  Each calculation is performed at the
 * shortest time horizon which tracks the required target.  Conservative
 * estimates, however, required the 95% threshold at 2 * target be met for any
 * longer time horizons also.
 */
CFeeRate CBlockPolicyEstimator::estimateSmartFee(int confTarget, FeeCalculation *feeCalc, bool conservative) const
{
    LOCK(m_cs_fee_estimator);

    if (feeCalc) {
        feeCalc->desiredTarget = confTarget;
        feeCalc->returnedTarget = confTarget;
    }

    double median = -1;
    EstimationResult tempResult;

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
    if (feeCalc) feeCalc->returnedTarget = confTarget;

    if (confTarget <= 1) return CFeeRate(0); // error condition

    assert(confTarget > 0); //estimateCombinedFee and estimateConservativeFee take unsigned ints
    /** true is passed to estimateCombined fee for target/2 and target so
     * that we check the max confirms for shorter time horizons as well.
     * This is necessary to preserve monotonically increasing estimates.
     * For non-conservative estimates we do the same thing for 2*target, but
     * for conservative estimates we want to skip these shorter horizons
     * checks for 2*target because we are taking the max over all time
     * horizons so we already have monotonically increasing estimates and
     * the purpose of conservative estimates is not to let short term
     * fluctuations lower our estimates by too much.
     */
    double halfEst = estimateCombinedFee(confTarget/2, HALF_SUCCESS_PCT, true, &tempResult);
    if (feeCalc) {
        feeCalc->est = tempResult;
        feeCalc->reason = FeeReason::HALF_ESTIMATE;
    }
    median = halfEst;
    double actualEst = estimateCombinedFee(confTarget, SUCCESS_PCT, true, &tempResult);
    if (actualEst > median) {
        median = actualEst;
        if (feeCalc) {
            feeCalc->est = tempResult;
            feeCalc->reason = FeeReason::FULL_ESTIMATE;
        }
    }
    double doubleEst = estimateCombinedFee(2 * confTarget, DOUBLE_SUCCESS_PCT, !conservative, &tempResult);
    if (doubleEst > median) {
        median = doubleEst;
        if (feeCalc) {
            feeCalc->est = tempResult;
            feeCalc->reason = FeeReason::DOUBLE_ESTIMATE;
        }
    }

    if (conservative || median == -1) {
        double consEst =  estimateConservativeFee(2 * confTarget, &tempResult);
        if (consEst > median) {
            median = consEst;
            if (feeCalc) {
                feeCalc->est = tempResult;
                feeCalc->reason = FeeReason::CONSERVATIVE;
            }
        }
    }

    if (median < 0) return CFeeRate(0); // error condition

    return CFeeRate(llround(median));
}

void CBlockPolicyEstimator::Flush() {
    FlushUnconfirmed();
    FlushFeeEstimates();
}

void CBlockPolicyEstimator::FlushFeeEstimates()
{
    AutoFile est_file{fsbridge::fopen(m_estimation_filepath, "wb")};
    if (est_file.IsNull() || !Write(est_file)) {
        LogPrintf("Failed to write fee estimates to %s. Continue anyway.\n", fs::PathToString(m_estimation_filepath));
    } else {
        LogPrintf("Flushed fee estimates to %s.\n", fs::PathToString(m_estimation_filepath.filename()));
    }
}

bool CBlockPolicyEstimator::Write(AutoFile& fileout) const
{
    try {
        LOCK(m_cs_fee_estimator);
        fileout << CURRENT_FEES_FILE_VERSION;
        fileout << int{0}; // Unused dummy field. Written files may contain any value in [0, 289900]
        fileout << nBestSeenHeight;
        if (BlockSpan() > HistoricalBlockSpan()/2) {
            fileout << firstRecordedHeight << nBestSeenHeight;
        }
        else {
            fileout << historicalFirst << historicalBest;
        }
        fileout << Using<VectorFormatter<EncodedDoubleFormatter>>(buckets);
        feeStats->Write(fileout);
        shortStats->Write(fileout);
        longStats->Write(fileout);
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
        int nVersionRequired, dummy;
        filein >> nVersionRequired >> dummy;
        if (nVersionRequired > CURRENT_FEES_FILE_VERSION) {
            throw std::runtime_error{strprintf("File version (%d) too high to be read.", nVersionRequired)};
        }

        // Read fee estimates file into temporary variables so existing data
        // structures aren't corrupted if there is an exception.
        unsigned int nFileBestSeenHeight;
        filein >> nFileBestSeenHeight;

        if (nVersionRequired < CURRENT_FEES_FILE_VERSION) {
            LogWarning("Incompatible old fee estimation data (non-fatal). Version: %d", nVersionRequired);
        } else { // nVersionRequired == CURRENT_FEES_FILE_VERSION
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

            std::unique_ptr<TxConfirmStats> fileFeeStats(new TxConfirmStats(buckets, bucketMap, MED_BLOCK_PERIODS, MED_DECAY, MED_SCALE));
            std::unique_ptr<TxConfirmStats> fileShortStats(new TxConfirmStats(buckets, bucketMap, SHORT_BLOCK_PERIODS, SHORT_DECAY, SHORT_SCALE));
            std::unique_ptr<TxConfirmStats> fileLongStats(new TxConfirmStats(buckets, bucketMap, LONG_BLOCK_PERIODS, LONG_DECAY, LONG_SCALE));
            fileFeeStats->Read(filein, numBuckets);
            fileShortStats->Read(filein, numBuckets);
            fileLongStats->Read(filein, numBuckets);

            // Fee estimates file parsed correctly
            // Copy buckets from file and refresh our bucketmap
            buckets = fileBuckets;
            bucketMap.clear();
            for (unsigned int i = 0; i < buckets.size(); i++) {
                bucketMap[buckets[i]] = i;
            }

            // Destroy old TxConfirmStats and point to new ones that already reference buckets and bucketMap
            feeStats = std::move(fileFeeStats);
            shortStats = std::move(fileShortStats);
            longStats = std::move(fileLongStats);

            nBestSeenHeight = nFileBestSeenHeight;
            historicalFirst = nFileHistoricalFirst;
            historicalBest = nFileHistoricalBest;
        }
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
    size_t num_entries = mapMemPoolTxs.size();
    // Remove every entry in mapMemPoolTxs
    while (!mapMemPoolTxs.empty()) {
        auto mi = mapMemPoolTxs.begin();
        _removeTx(mi->first, false); // this calls erase() on mapMemPoolTxs
    }
    const auto endclear{SteadyClock::now()};
    LogDebug(BCLog::ESTIMATEFEE, "Recorded %u unconfirmed txs from mempool in %.3fs\n", num_entries, Ticks<SecondsDouble>(endclear - startclear));
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
