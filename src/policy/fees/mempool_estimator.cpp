// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license. See the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/fees/mempool_estimator.h>

#include <logging.h>
#include <node/miner.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <util/check.h>
#include <util/feefrac.h>
#include <util/fees.h>
#include <util/fs.h>
#include <util/syserror.h>
#include <validation.h>

#include <algorithm>
#include <iterator>
#include <numeric>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

constexpr int CURRENT_MEMPOOL_ESTIMATOR_VERSION{1};

namespace {
struct MinedBlockStatsFormatter {
    template <typename Stream>
    void Ser(Stream& s, const MinedBlockStats& v)
    {
        s << v.m_height << v.m_removed_block_txs_weight << v.m_block_weight;
    }
    template <typename Stream>
    void Unser(Stream& s, MinedBlockStats& v)
    {
        s >> v.m_height >> v.m_removed_block_txs_weight >> v.m_block_weight;
    }
};

void AddMinedBlockStats(std::vector<MinedBlockStats>& mined_blocks, MinedBlockStats stats)
{
    const auto stale_begin{std::find_if(mined_blocks.begin(), mined_blocks.end(), [&](const MinedBlockStats& block) {
        return block.m_height >= stats.m_height;
    })};
    const auto stale_count{std::distance(stale_begin, mined_blocks.end())};
    if (stale_count > 0) {
        LogDebug(BCLog::ESTIMATEFEE,
                 "%s: connected block height=%s discards tracked mined-block stats "
                 "from height=%s to height=%s; stale_stats=%s",
                 FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
                 stats.m_height,
                 stale_begin->m_height,
                 mined_blocks.back().m_height,
                 stale_count);
    }
    mined_blocks.erase(stale_begin, mined_blocks.end());
    if (!mined_blocks.empty() && mined_blocks.back().m_height + 1 != stats.m_height) {
        LogDebug(BCLog::ESTIMATEFEE,
                 "%s: clearing mined-block stats after height gap; tracked_stats=%s "
                 "expected_height=%s received_height=%s",
                 FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
                 mined_blocks.size(),
                 mined_blocks.back().m_height + 1,
                 stats.m_height);
        mined_blocks.clear();
    }

    if (mined_blocks.size() == MEMPOOL_HEALTH_WINDOW_BLOCKS) mined_blocks.erase(mined_blocks.begin());
    mined_blocks.push_back(stats);
}

struct ActiveTip {
    int height;
    uint256 hash;
};

std::optional<ActiveTip> GetActiveTip(const ChainstateManager& chainman)
{
    LOCK(::cs_main);
    const CBlockIndex* tip{chainman.ActiveTip()};
    if (!tip) return std::nullopt;
    return ActiveTip{tip->nHeight, tip->GetBlockHash()};
}
} // namespace

MemPoolFeeRateEstimator::Percentiles MemPoolFeeRateEstimator::CalculateMaxWeightPercentiles(std::span<const FeePerVSize> chunk_feerates)
{
    Assume(std::is_sorted(chunk_feerates.begin(), chunk_feerates.end(), [](const auto& a, const auto& b) { return ByRatio{a} > ByRatio{b}; }));
    constexpr int64_t total_weight{DEFAULT_BLOCK_MAX_WEIGHT};
    const int64_t p50_weight{total_weight / 2};
    const int64_t p75_weight{total_weight * 3 / 4};
    Percentiles percentiles{};
    int64_t accumulated_weight{0};
    for (const auto& curr_feerate : chunk_feerates) {
        accumulated_weight += int64_t{curr_feerate.size} * WITNESS_SCALE_FACTOR;
        if (accumulated_weight >= p50_weight && percentiles.p50.IsEmpty()) {
            percentiles.p50 = curr_feerate;
        }
        if (accumulated_weight >= p75_weight && percentiles.p75.IsEmpty()) {
            percentiles.p75 = curr_feerate;
            break;
        }
    }
    return percentiles;
}

bool MemPoolFeeRateEstimatorCache::IsStale() const
{
    return !m_fee_rate_estimation || (m_last_updated + CACHE_LIFE) < NodeClock::now();
}

std::optional<MemPoolFeeRateEstimatorCache::FeeRateEstimate>
MemPoolFeeRateEstimatorCache::GetCachedEstimate(const uint256& tip_hash) const
{
    if (IsStale() || tip_hash != m_tip_hash) return std::nullopt;
    return m_fee_rate_estimation;
}

std::optional<MemPoolFeeRateEstimatorCache::Diagnostics>
MemPoolFeeRateEstimatorCache::GetDiagnostics(const uint256& tip_hash) const
{
    const auto now{NodeClock::now()};
    if (!m_fee_rate_estimation || (m_last_updated + CACHE_LIFE) < now || tip_hash != m_tip_hash) return std::nullopt;
    const auto age{std::max(std::chrono::milliseconds{0},
                            std::chrono::duration_cast<std::chrono::milliseconds>(now - m_last_updated))};
    return Diagnostics{*m_fee_rate_estimation, m_tip_hash, age};
}

void MemPoolFeeRateEstimatorCache::Update(FeePerVSize conservative,
                                          FeePerVSize economical,
                                          const uint256& tip_hash,
                                          bool conservative_used_floor,
                                          bool economical_used_floor)
{
    m_fee_rate_estimation = {conservative, economical, conservative_used_floor, economical_used_floor};
    m_tip_hash = tip_hash;
    m_last_updated = NodeClock::now();
}

void MemPoolFeeRateEstimatorCache::Clear()
{
    m_fee_rate_estimation.reset();
    m_tip_hash.SetNull();
    m_last_updated = {};
}

//! Build the error result for a failed mempool fee rate estimation.
static util::Unexpected<FeeRateEstimationError> EstimationError(std::string error)
{
    return EstimationError(FeeRateEstimatorType::MEMPOOL_POLICY, MEMPOOL_FEE_ESTIMATOR_MAX_TARGET, std::move(error));
}

static std::optional<std::string_view> MempoolHealthError(MemPoolFeeRateEstimator::MempoolHealth health)
{
    switch (health) {
    case MemPoolFeeRateEstimator::MempoolHealth::INSUFFICIENT_DATA:
        return "Not enough recent block data for fee rate estimation";
    case MemPoolFeeRateEstimator::MempoolHealth::LOW_COVERAGE:
        return "Mempool is unreliable for fee rate estimation";
    case MemPoolFeeRateEstimator::MempoolHealth::HEALTHY:
        return std::nullopt;
    }
    Assume(false);
    return std::nullopt;
}

MemPoolFeeRateEstimator::MemPoolFeeRateEstimator(fs::path mempool_estimator_file_path,
                                                 const CTxMemPool& mempool,
                                                 ChainstateManager& chainman)
    : m_mempool(mempool),
      m_chainman(chainman),
      m_mempool_estimator_file_path(std::move(mempool_estimator_file_path))
{
    ReadFromDisk();
}

void MemPoolFeeRateEstimator::ReadFromDisk()
{
    AutoFile file{fsbridge::fopen(m_mempool_estimator_file_path, "rb")};
    if (file.IsNull()) {
        LogDebug(BCLog::ESTIMATEFEE, "%s: %s does not exist. Continuing anyway",
                 FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
                 fs::PathToString(m_mempool_estimator_file_path));
        return;
    }
    if (Read(file)) {
        LogDebug(BCLog::ESTIMATEFEE, "%s: mined-block stats successfully read from %s.",
                 FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
                 fs::PathToString(m_mempool_estimator_file_path));
    }
}

bool MemPoolFeeRateEstimator::Read(AutoFile& file)
{
    try {
        int version_required;
        file >> version_required;
        if (version_required != CURRENT_MEMPOOL_ESTIMATOR_VERSION) {
            LogWarning("%s: file version not supported; continuing anyway",
                       FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY));
            return false;
        }
        // Stage into a local buffer and commit to the member only after validation passes.
        std::vector<MinedBlockStats> blocks;
        file >> Using<VectorFormatter<MinedBlockStatsFormatter>>(blocks);
        uint256 tip_hash;
        file >> tip_hash;
        if (blocks.size() > MEMPOOL_HEALTH_WINDOW_BLOCKS) {
            LogWarning("%s: Number of previously mined blocks read exceeds the maximum of %s; ignoring file",
                       FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
                       MEMPOOL_HEALTH_WINDOW_BLOCKS);
            return false;
        }
        for (size_t i = 1; i < blocks.size(); ++i) {
            if (blocks[i].m_height != blocks[i - 1].m_height + 1) {
                LogWarning("%s: Non-consecutive block heights read, expected height %s but found %s; ignoring file",
                           FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
                           blocks[i - 1].m_height + 1, blocks[i].m_height);
                return false;
            }
        }
        if (!blocks.empty()) {
            const auto& last_block{blocks.back()};
            const std::optional<ActiveTip> active_tip{GetActiveTip(m_chainman)};
            if (!active_tip) {
                LogWarning("%s: Mined-block stats read end at height %s block %s, but there is no active chain tip; ignoring file",
                           FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
                           last_block.m_height, tip_hash.ToString());
                return false;
            }
            if (last_block.m_height != static_cast<uint64_t>(active_tip->height) || tip_hash != active_tip->hash) {
                LogWarning("%s: Mined-block stats read end at height %s block %s, but the active chain tip is height %s block %s; ignoring file",
                           FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
                           last_block.m_height, tip_hash.ToString(),
                           active_tip->height, active_tip->hash.ToString());
                return false;
            }
        }
        LOCK(cs);
        m_prev_mined_blocks = std::move(blocks);
        m_mined_blocks_tip_hash = tip_hash;
        m_cache.Clear();
    } catch (const std::exception&) {
        LogWarning("%s: Unable to read mined-block stats from stream (non-fatal)",
                   FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY));
        return false;
    }
    return true;
}

bool MemPoolFeeRateEstimator::Write(AutoFile& file) const
{
    try {
        LOCK(cs);
        file << CURRENT_MEMPOOL_ESTIMATOR_VERSION;
        file << Using<VectorFormatter<MinedBlockStatsFormatter>>(m_prev_mined_blocks);
        file << m_mined_blocks_tip_hash;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

void MemPoolFeeRateEstimator::FlushMinedBlockStats()
{
    if (!m_mempool_estimator_file_path.parent_path().empty()) {
        std::error_code error;
        fs::create_directories(m_mempool_estimator_file_path.parent_path(), error);
        if (error) {
            LogWarning("%s: failed to create mempool policy estimator directory %s: %s. Continuing anyway",
                       FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
                       fs::PathToString(m_mempool_estimator_file_path.parent_path()), error.message());
            return;
        }
    }
    AutoFile file{fsbridge::fopen(m_mempool_estimator_file_path, "wb")};
    if (file.IsNull()) {
        LogWarning("%s: unable to open %s for writing. Continuing anyway",
                   FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
                   fs::PathToString(m_mempool_estimator_file_path));
        return;
    }
    if (!Write(file)) {
        LogWarning("%s: Unable to write mined-block stats to %s (non-fatal)",
                   FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
                   fs::PathToString(m_mempool_estimator_file_path));
    }
    if (file.fclose() != 0) {
        LogWarning("Failed to close mempool policy estimator file %s: %s. Continuing anyway.",
                   fs::PathToString(m_mempool_estimator_file_path), SysErrorString(errno));
        return;
    }
    LogDebug(BCLog::ESTIMATEFEE, "%s: mined-block stats flushed to %s.",
             FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY),
             fs::PathToString(m_mempool_estimator_file_path));
}


void MemPoolFeeRateEstimator::MempoolTxsRemovedForBlock(const std::shared_ptr<const CBlock>& block,
                                                        const std::vector<RemovedMempoolTransactionInfo>& txs_removed_for_block,
                                                        unsigned int block_height)
{
    LOCK(cs);
    Assert(!block->vtx.empty());
    // Accumulate total block weight and removed mempool tx weight, both excluding the coinbase.
    const auto get_tx_weight = [](const CTransactionRef& tx) {
        return static_cast<uint64_t>(GetTransactionWeight(*tx));
    };
    // Skip vtx[0], which is the coinbase.
    const uint64_t block_weight = std::accumulate(std::next(block->vtx.begin()), block->vtx.end(), uint64_t{0},
                                                  [&](uint64_t acc, const CTransactionRef& tx) {
                                                      return acc + get_tx_weight(tx);
                                                  });
    const uint64_t removed_weight = std::accumulate(
        txs_removed_for_block.begin(), txs_removed_for_block.end(), uint64_t{0},
        [&](uint64_t acc, const RemovedMempoolTransactionInfo& tx) {
            return acc + get_tx_weight(tx.info.m_tx);
        });
    AddMinedBlockStats(m_prev_mined_blocks, {block_height, removed_weight, block_weight});
    m_mined_blocks_tip_hash = block->GetHash();
    m_cache.Clear();
}

// Require at least one block worth of activity across the window before using
// the coverage ratio as a representative mempool health signal.
static constexpr uint64_t MIN_REPRESENTATIVE_WINDOW_WEIGHT{DEFAULT_BLOCK_MAX_WEIGHT};

MemPoolFeeRateEstimator::HealthDiagnostics MemPoolFeeRateEstimator::GetHealthDiagnostics(bool include_blocks) const
{
    LOCK(cs);
    HealthDiagnostics diagnostics;
    diagnostics.tracked_blocks = m_prev_mined_blocks.size();
    if (include_blocks) diagnostics.blocks = m_prev_mined_blocks;
    diagnostics.window_tip_hash = m_mined_blocks_tip_hash;
    diagnostics.minimum_representative_window_weight = MIN_REPRESENTATIVE_WINDOW_WEIGHT;
    const auto estimator_name{FeeRateEstimatorTypeToString(FeeRateEstimatorType::MEMPOOL_POLICY)};
    uint64_t expected_height{m_prev_mined_blocks.empty() ? 0 : m_prev_mined_blocks.front().m_height};
    for (const auto& block : m_prev_mined_blocks) {
        Assume(block.m_height == expected_height);
        ++expected_height;
        diagnostics.total_block_weight += block.m_block_weight;
        diagnostics.total_removed_weight += block.m_removed_block_txs_weight;
    }
    if (diagnostics.total_block_weight > 0) {
        diagnostics.coverage_ratio = static_cast<double>(diagnostics.total_removed_weight) / diagnostics.total_block_weight;
    }
    if (m_prev_mined_blocks.size() < MEMPOOL_HEALTH_WINDOW_BLOCKS) {
        LogDebug(BCLog::ESTIMATEFEE, "%s: mempool health check failed; tracked_blocks=%s required_blocks=%s",
                 estimator_name, m_prev_mined_blocks.size(), MEMPOOL_HEALTH_WINDOW_BLOCKS);
        return diagnostics;
    }
    // Too little block activity for the coverage ratio to be meaningful; skip it.
    if (diagnostics.total_block_weight < MIN_REPRESENTATIVE_WINDOW_WEIGHT) {
        LogDebug(BCLog::ESTIMATEFEE, "%s: mempool health check passed; low activity, total_block_weight=%s minimum=%s",
                 estimator_name, diagnostics.total_block_weight, MIN_REPRESENTATIVE_WINDOW_WEIGHT);
        diagnostics.health = MempoolHealth::HEALTHY;
        diagnostics.low_activity_bypass = true;
        return diagnostics;
    }
    Assume(diagnostics.coverage_ratio.has_value());
    const double representation_ratio{*diagnostics.coverage_ratio};
    LogDebug(BCLog::ESTIMATEFEE,
             "%s: mempool health check %s; removed_weight=%s total_block_weight=%s "
             "coverage=%.2f required_coverage=%.2f",
             estimator_name,
             representation_ratio >= MEMPOOL_REPRESENTATION_THRESHOLD ? "passed" : "failed",
             diagnostics.total_removed_weight,
             diagnostics.total_block_weight,
             representation_ratio,
             MEMPOOL_REPRESENTATION_THRESHOLD);
    diagnostics.health = representation_ratio >= MEMPOOL_REPRESENTATION_THRESHOLD ? MempoolHealth::HEALTHY : MempoolHealth::LOW_COVERAGE;
    return diagnostics;
}

MemPoolFeeRateEstimator::MempoolHealth MemPoolFeeRateEstimator::GetMempoolHealth() const
{
    return GetHealthDiagnostics().health;
}

util::Expected<FeeRateEstimation, FeeRateEstimationError> MemPoolFeeRateEstimator::EstimateFeeRate(bool conservative) const
{
    return EstimateFeeRateWithDiagnostics(conservative).estimate;
}

MemPoolFeeRateEstimator::EstimateResult MemPoolFeeRateEstimator::EstimateFeeRateWithDiagnostics(bool conservative) const
{
    constexpr auto estimator_type{FeeRateEstimatorType::MEMPOOL_POLICY};
    if (!m_mempool.GetLoadTried()) {
        return {EstimationError(strprintf("%s: Mempool not loaded yet, no fee rate estimate available", FeeRateEstimatorTypeToString(estimator_type))),
                std::nullopt,
                false};
    }
    if (auto error{MempoolHealthError(GetMempoolHealth())}) {
        return {EstimationError(strprintf("%s: %s", FeeRateEstimatorTypeToString(estimator_type), *error)), std::nullopt, false};
    }
    // The estimator lock is not held while building a block template, so
    // in a rare edge case concurrent callers may duplicate work.
    //
    // Cached fee rate estimates are tagged with the chain tip they were computed on
    // and only served from the cache while that tip is current.
    //
    // The fee rate estimate returned directly below may still reflect a tip that went
    // stale during the call; that is an accepted tradeoff of not holding
    // locks across block assembly.
    {
        const uint256 tip_hash{WITH_LOCK(::cs_main, return Assume(m_chainman.CurrentChainstate().m_chain.Tip())->GetBlockHash())};
        LOCK(cs);
        auto cache_diagnostics{m_cache.GetDiagnostics(tip_hash)};
        if (cache_diagnostics) {
            const auto cached_feerate{
                conservative ? cache_diagnostics->estimate.m_conservative : cache_diagnostics->estimate.m_economical};
            return {FeeRateEstimation{estimator_type, cached_feerate, MEMPOOL_FEE_ESTIMATOR_MAX_TARGET},
                    std::move(cache_diagnostics),
                    true};
        }
    }
    node::BlockCreateOptions options;
    options.test_block_validity = false;
    const auto blocktemplate = WITH_LOCK(::cs_main, return (node::BlockAssembler{m_chainman.CurrentChainstate(), &m_mempool, options}).CreateNewBlock());
    if (!blocktemplate) {
        return {EstimationError(strprintf("%s: Failed to create block template for fee rate estimation", FeeRateEstimatorTypeToString(estimator_type))),
                std::nullopt,
                false};
    }
    // Sort again because the rounding up when converting from weight to vsize may cause slight misorder.
    std::sort(blocktemplate->m_package_feerates.begin(), blocktemplate->m_package_feerates.end(), [](const auto& a, const auto& b) { return ByRatio{a} > ByRatio{b}; });
    const auto percentiles = CalculateMaxWeightPercentiles(blocktemplate->m_package_feerates);
    // Fall back to a relayable floor (the higher of the min relay fee and the current
    // mempool min fee) for any percentile the mempool was too sparse to fill.
    const FeePerVSize floor{std::max(m_mempool.m_opts.min_relay_feerate, m_mempool.GetMinFee()).GetFeePerVSize()};
    const bool p50_used_floor{percentiles.p50.IsEmpty()};
    const bool p75_used_floor{percentiles.p75.IsEmpty()};
    const FeePerVSize p50{p50_used_floor ? floor : percentiles.p50};
    const FeePerVSize p75{p75_used_floor ? floor : percentiles.p75};
    std::optional<MemPoolFeeRateEstimatorCache::Diagnostics> cache_diagnostics;
    {
        LOCK(cs);
        m_cache.Update(p50, p75, blocktemplate->block.hashPrevBlock, p50_used_floor, p75_used_floor);
        cache_diagnostics = m_cache.GetDiagnostics(blocktemplate->block.hashPrevBlock);
    }
    Assume(cache_diagnostics.has_value());
    LogDebug(BCLog::ESTIMATEFEE, "%s: conservative/economical fee rate: %s/%s %s/kvB",
             FeeRateEstimatorTypeToString(estimator_type), CFeeRate(p50).GetFeePerK(),
             CFeeRate(p75).GetFeePerK(), CURRENCY_ATOM);
    return {FeeRateEstimation{estimator_type, conservative ? p50 : p75, MEMPOOL_FEE_ESTIMATOR_MAX_TARGET},
            std::move(cache_diagnostics),
            false};
}
