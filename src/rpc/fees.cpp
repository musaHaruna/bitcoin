// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/messages.h>
#include <core_io.h>
#include <node/context.h>
#include <policy/feerate.h>
#include <policy/fees/block_policy_estimator.h>
#include <policy/fees/estimator_man.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/fees.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <compare>
#include <optional>
#include <string>
#include <string_view>

using common::FeeModeFromString;
using common::FeeModesDetail;
using common::InvalidEstimateModeErrorMessage;
using node::NodeContext;

namespace {

using FeeRateEstimateResult = util::Expected<FeeRateEstimation, FeeRateEstimationError>;

struct StateSnapshot {
    int tip_height;
    uint256 tip_hash;
    uint64_t mempool_sequence;
};

StateSnapshot GetStateSnapshot(ChainstateManager& chainman, const CTxMemPool& mempool)
{
    LOCK2(chainman.GetMutex(), mempool.cs);
    const CBlockIndex& tip{*CHECK_NONFATAL(chainman.ActiveTip())};
    return {tip.nHeight, tip.GetBlockHash(), mempool.GetSequence()};
}

UniValue FeeRateEstimateDiagnostics(const FeeRateEstimateResult& estimate)
{
    UniValue result{UniValue::VOBJ};
    const FeeRateEstimation& estimation{FeeRateEstimationRef(estimate)};
    result.pushKV("success", estimate.has_value());
    result.pushKV("blocks", estimation.returned_target);
    if (estimate) {
        result.pushKV("feerate_before_rpc_floor", ValueFromAmount(CFeeRate(estimate->feerate).GetFeePerK()));
        result.pushKV("feerate_fee_sats", estimate->feerate.fee);
        result.pushKV("feerate_vsize", estimate->feerate.size);
    } else {
        result.pushKV("error", estimate.error().reason);
    }
    return result;
}

std::string_view MempoolHealthToString(MemPoolFeeRateEstimator::MempoolHealth health)
{
    switch (health) {
    case MemPoolFeeRateEstimator::MempoolHealth::HEALTHY:
        return "healthy";
    case MemPoolFeeRateEstimator::MempoolHealth::INSUFFICIENT_DATA:
        return "insufficient_data";
    case MemPoolFeeRateEstimator::MempoolHealth::LOW_COVERAGE:
        return "low_coverage";
    }
    Assume(false);
}

const FeeRateEstimateResult& RequestedEstimate(const FeeRateEstimatorResults& estimates, FeeRateEstimatorType type)
{
    switch (type) {
    case FeeRateEstimatorType::NONE:
        return estimates.combined;
    case FeeRateEstimatorType::BLOCK_POLICY:
        return estimates.block_policy;
    case FeeRateEstimatorType::MEMPOOL_POLICY:
        return estimates.mempool_policy;
    }
    Assume(false);
}

} // namespace

static RPCMethod estimatesmartfee()
{
    return RPCMethod{
        "estimatesmartfee",
        "Estimates the approximate fee per kilobyte needed for a transaction to begin\n"
        "confirmation within conf_target blocks if possible and return the number of blocks\n"
        "for which the estimate is valid. Uses virtual transaction size as defined\n"
        "in BIP 141 (witness data is discounted).\n",
        {
            {"conf_target", RPCArg::Type::NUM, RPCArg::Optional::NO, "Confirmation target in blocks (1 - 1008)"},
            {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"economical"}, "The fee estimate mode.\n"
              + FeeModesDetail(std::string("default mode will be used"))},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"fee_rate_estimator", RPCArg::Type::STR, RPCArg::Default{"none"},
                     "Selects which fee rate estimator to use.\n"
                     "\"none\" returns the lower of the block policy and mempool estimates. If the mempool\n"
                     "estimate is unavailable, it returns that error instead of falling back to the block\n"
                     "policy estimate; use \"block_policy\" in that case to get the block policy estimate.\n"
                     "\"block_policy\" uses only the block policy fee rate estimator.\n"
                     "\"mempool_policy\" uses only the mempool fee rate estimator.\n"
                     "Unknown values are treated as \"none\"."},
                    {"verbosity", RPCArg::Type::NUM, RPCArg::Default{1},
                     "1 returns feerate or errors. 2 also returns \"mempool_health_statistics\". "
                     "3 also returns \"diagnostics\" with both estimators before the RPC fee floor, "
                     "the manager selection, mempool template percentiles, fee floors, and aggregate health."},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "feerate", /*optional=*/true, "estimate fee rate in " + CURRENCY_UNIT + "/kvB (only present if no errors were encountered)"},
                {RPCResult::Type::STR, "estimator", /*optional=*/true, "the fee estimator used to produce the result (only present for successful estimates when fee_rate_estimator is \"none\")"},
                {RPCResult::Type::ARR, "errors", /*optional=*/true, "Errors encountered during processing (if there are any)",
                    {
                        {RPCResult::Type::STR, "", "error"},
                    }},
                {RPCResult::Type::NUM, "blocks", "the confirmation target in blocks for the returned fee rate estimate.\n"
                "For the block policy fee rate estimator, this is the target the estimate was found at, clamped to at\n"
                "least 2 and at most the estimator's maximum usable target. For the mempool fee rate\n"
                "estimator, it is always 2."},
                {RPCResult::Type::ARR, "mempool_health_statistics", /*optional=*/true, "Health statistics for the most recently mined blocks tracked by the mempool fee rate estimator (only present when verbosity >= 2)",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "block_height", "Block height"},
                                {RPCResult::Type::NUM, "block_weight", "Total weight of non-coinbase transactions in the block"},
                                {RPCResult::Type::NUM, "mempool_txs_weight", "Total weight of transactions removed from the mempool for this block"},
                            }},
                    }},
                {RPCResult::Type::OBJ, "diagnostics", /*optional=*/true, "Fee estimator diagnostics (only present when verbosity >= 3)",
                    {
                        {RPCResult::Type::NUM, "requested_target", "the requested confirmation target"},
                        {RPCResult::Type::STR, "estimate_mode", "the requested estimate mode"},
                        {RPCResult::Type::STR, "requested_estimator", "the requested fee rate estimator"},
                        {RPCResult::Type::NUM, "tip_height_before", "active tip height before estimation"},
                        {RPCResult::Type::STR_HEX, "tip_hash_before", "active tip hash before estimation"},
                        {RPCResult::Type::NUM, "tip_height_after", "active tip height after diagnostics were collected"},
                        {RPCResult::Type::STR_HEX, "tip_hash_after", "active tip hash after diagnostics were collected"},
                        {RPCResult::Type::BOOL, "tip_consistent", "whether the active tip remained unchanged during estimation"},
                        {RPCResult::Type::NUM, "mempool_sequence_before", "mempool sequence before estimation"},
                        {RPCResult::Type::NUM, "mempool_sequence_after", "mempool sequence after diagnostics were collected"},
                        {RPCResult::Type::BOOL, "mempool_consistent", "whether no mempool additions or removals were observed during collection"},
                        {RPCResult::Type::BOOL, "snapshot_consistent", "whether both the active tip and mempool sequence remained unchanged"},
                        {RPCResult::Type::OBJ, "block_policy", "The block policy estimate before the RPC fee floor",
                            {
                                {RPCResult::Type::BOOL, "success", "whether the estimator returned a fee rate"},
                                {RPCResult::Type::NUM, "blocks", "the block policy estimator's returned target"},
                                {RPCResult::Type::NUM, "feerate_before_rpc_floor", /*optional=*/true, "block policy estimate in " + CURRENCY_UNIT + "/kvB before the final RPC floor"},
                                {RPCResult::Type::NUM, "feerate_fee_sats", /*optional=*/true, "exact fee-rate numerator in satoshis"},
                                {RPCResult::Type::NUM, "feerate_vsize", /*optional=*/true, "exact fee-rate denominator in virtual bytes"},
                                {RPCResult::Type::STR, "error", /*optional=*/true, "the estimator error"},
                            }},
                        {RPCResult::Type::OBJ, "mempool_policy", "The requested-mode mempool policy estimate before the RPC fee floor",
                            {
                                {RPCResult::Type::BOOL, "success", "whether the estimator returned a fee rate"},
                                {RPCResult::Type::NUM, "blocks", "the mempool policy estimator's returned target (always 2)"},
                                {RPCResult::Type::NUM, "feerate_before_rpc_floor", /*optional=*/true, "mempool policy estimate in " + CURRENCY_UNIT + "/kvB before the final RPC floor"},
                                {RPCResult::Type::NUM, "feerate_fee_sats", /*optional=*/true, "exact fee-rate numerator in satoshis"},
                                {RPCResult::Type::NUM, "feerate_vsize", /*optional=*/true, "exact fee-rate denominator in virtual bytes"},
                                {RPCResult::Type::STR, "error", /*optional=*/true, "the estimator error"},
                            }},
                        {RPCResult::Type::OBJ, "selection", "The combined manager decision before and after the RPC fee floor",
                            {
                                {RPCResult::Type::BOOL, "success", "whether both estimators succeeded and a selection was made"},
                                {RPCResult::Type::STR, "reason", "why the estimator was selected, or why selection failed"},
                                {RPCResult::Type::STR, "estimator", /*optional=*/true, "the estimator selected by the manager"},
                                {RPCResult::Type::NUM, "blocks", /*optional=*/true, "the selected estimator's returned target"},
                                {RPCResult::Type::NUM, "feerate_before_rpc_floor", /*optional=*/true, "selected estimate in " + CURRENCY_UNIT + "/kvB before the final RPC floor"},
                                {RPCResult::Type::NUM, "feerate_fee_sats", /*optional=*/true, "exact selected fee-rate numerator in satoshis"},
                                {RPCResult::Type::NUM, "feerate_vsize", /*optional=*/true, "exact selected fee-rate denominator in virtual bytes"},
                                {RPCResult::Type::NUM, "feerate_after_rpc_floor", /*optional=*/true, "selected estimate in " + CURRENCY_UNIT + "/kvB after the final RPC floor"},
                                {RPCResult::Type::BOOL, "fee_floor_applied", /*optional=*/true, "whether the RPC fee floor raised the selected estimate"},
                            }},
                        {RPCResult::Type::OBJ, "fee_floor", "The fee floors applied by estimatesmartfee",
                            {
                                {RPCResult::Type::NUM, "mempool_min", "dynamic mempool minimum in " + CURRENCY_UNIT + "/kvB"},
                                {RPCResult::Type::NUM, "min_relay", "minimum relay fee in " + CURRENCY_UNIT + "/kvB"},
                                {RPCResult::Type::NUM, "effective", "higher of the mempool and relay floors in " + CURRENCY_UNIT + "/kvB"},
                            }},
                        {RPCResult::Type::OBJ, "mempool_template", /*optional=*/true, "Exact cached template percentiles used or generated by this invocation after sparse-template fallback; present when the mempool estimate succeeded",
                            {
                                {RPCResult::Type::NUM, "p50", "conservative template estimate in " + CURRENCY_UNIT + "/kvB"},
                                {RPCResult::Type::NUM, "p75", "economical template estimate in " + CURRENCY_UNIT + "/kvB"},
                                {RPCResult::Type::NUM, "p50_fee_sats", "exact p50 fee-rate numerator in satoshis"},
                                {RPCResult::Type::NUM, "p50_vsize", "exact p50 fee-rate denominator in virtual bytes"},
                                {RPCResult::Type::NUM, "p75_fee_sats", "exact p75 fee-rate numerator in satoshis"},
                                {RPCResult::Type::NUM, "p75_vsize", "exact p75 fee-rate denominator in virtual bytes"},
                                {RPCResult::Type::BOOL, "p50_used_fee_floor", "whether the template could not fill p50 and the estimator used its fee floor"},
                                {RPCResult::Type::BOOL, "p75_used_fee_floor", "whether the template could not fill p75 and the estimator used its fee floor"},
                                {RPCResult::Type::BOOL, "cache_hit", "whether this invocation reused cached template percentiles"},
                                {RPCResult::Type::STR_HEX, "tip_hash", "active tip for which the cached template percentiles were generated"},
                                {RPCResult::Type::NUM, "cache_age_ms", "age of the cached template percentiles in milliseconds"},
                                {RPCResult::Type::NUM, "cache_lifetime_ms", "maximum cache lifetime in milliseconds"},
                            }},
                        {RPCResult::Type::OBJ, "mempool_health", "Aggregate health of the tracked mined-block window",
                            {
                                {RPCResult::Type::STR, "status", "healthy, insufficient_data, or low_coverage"},
                                {RPCResult::Type::NUM, "tracked_blocks", "number of recent blocks tracked"},
                                {RPCResult::Type::NUM, "required_blocks", "number of recent blocks required"},
                                {RPCResult::Type::STR_HEX, "window_tip_hash", /*optional=*/true, "tip hash associated with the tracked health window"},
                                {RPCResult::Type::NUM, "total_block_weight", "total non-coinbase weight across tracked blocks"},
                                {RPCResult::Type::NUM, "mempool_txs_weight", "total mined weight previously seen in this node's mempool"},
                                {RPCResult::Type::NUM, "coverage_ratio", /*optional=*/true, "mempool_txs_weight divided by total_block_weight"},
                                {RPCResult::Type::NUM, "required_coverage_ratio", "minimum coverage ratio when the window has enough activity"},
                                {RPCResult::Type::NUM, "minimum_representative_window_weight", "minimum total block weight required before applying the coverage test"},
                                {RPCResult::Type::BOOL, "low_activity_bypass", "whether the coverage test was skipped because the window had too little activity"},
                            }},
                    }},
        }},
        RPCExamples{
            HelpExampleCli("estimatesmartfee", "6") +
            HelpExampleRpc("estimatesmartfee", "6")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            FeeRateEstimatorManager& fee_estimator_man = EnsureAnyFeeEstimatorMan(request.context);
            const NodeContext& node = EnsureAnyNodeContext(request.context);
            const CTxMemPool& mempool = EnsureMemPool(node);

            CHECK_NONFATAL(mempool.m_opts.signals)->SyncWithValidationInterfaceQueue();
            unsigned int max_target = fee_estimator_man.MaximumTarget();
            unsigned int conf_target = ParseConfirmTarget(request.params[0], max_target);
            FeeEstimateMode fee_mode;
            if (!FeeModeFromString(self.Arg<std::string_view>("estimate_mode"), fee_mode)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, InvalidEstimateModeErrorMessage());
            }
            const UniValue options{request.params[2].isNull() ? UniValue::VOBJ : request.params[2]};
            RPCTypeCheckObj(options,
                            {
                                {"fee_rate_estimator", UniValueType(UniValue::VSTR)},
                                {"verbosity", UniValueType(UniValue::VNUM)},
                            }, /*fAllowNull=*/true, /*fStrict=*/true);
            const auto fee_rate_estimator{FeeRateEstimatorTypeFromString(
                options["fee_rate_estimator"].isNull() ? "none" : options["fee_rate_estimator"].get_str())};
            bool conservative{fee_mode == FeeEstimateMode::CONSERVATIVE};
            int verbosity{ParseVerbosity(options["verbosity"], /*default_verbosity=*/1, /*allow_bool=*/false)};
            ChainstateManager& chainman{EnsureAnyChainman(request.context)};
            const std::optional<StateSnapshot> snapshot_before{
                verbosity >= 3 ? std::optional{GetStateSnapshot(chainman, mempool)} : std::nullopt};
            const std::optional<FeeRateEstimatorResults> estimator_results{
                verbosity >= 3 ? std::optional{fee_estimator_man.GetFeeRateEstimatorResults(conf_target, conservative)} : std::nullopt};
            const FeeRateEstimateResult estimate{estimator_results
                                                     ? RequestedEstimate(*estimator_results, fee_rate_estimator)
                                                     : fee_estimator_man.GetFeeRateEstimate(fee_rate_estimator, conf_target, conservative)};
            const std::optional<MemPoolFeeRateEstimator::HealthDiagnostics> health_diagnostics{
                verbosity >= 3 ? std::optional{fee_estimator_man.MempoolPolicyEstimatorHealthDiagnostics()} : std::nullopt};
            UniValue result(UniValue::VOBJ);
            UniValue errors(UniValue::VARR);
            const CFeeRate min_mempool_feerate{mempool.GetMinFee()};
            const CFeeRate min_relay_feerate{mempool.m_opts.min_relay_feerate};
            const CFeeRate effective_fee_floor{std::max(min_mempool_feerate, min_relay_feerate)};
            if (estimate) {
                const auto fee_rate{std::max(CFeeRate(estimate->feerate), effective_fee_floor)};
                result.pushKV("feerate", ValueFromAmount(fee_rate.GetFeePerK()));
            } else {
                errors.push_back(estimate.error().reason);
                result.pushKV("errors", std::move(errors));
            }
            if (estimate && fee_rate_estimator == FeeRateEstimatorType::NONE) {
                result.pushKV("estimator", FeeRateEstimatorTypeToString(estimate->feerate_estimator));
            }
            const FeeRateEstimation& estimation{FeeRateEstimationRef(estimate)};
            result.pushKV("blocks", estimation.returned_target);
            if (verbosity >= 2) {
                UniValue mempool_health_stats(UniValue::VARR);
                const auto blocks_data{health_diagnostics ? health_diagnostics->blocks : fee_estimator_man.MempoolPolicyEstimatorBlocksStats()};
                for (auto it = blocks_data.rbegin(); it != blocks_data.rend(); ++it) {
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("block_height", it->m_height);
                    entry.pushKV("block_weight", it->m_block_weight);
                    entry.pushKV("mempool_txs_weight", it->m_removed_block_txs_weight);
                    mempool_health_stats.push_back(std::move(entry));
                }
                result.pushKV("mempool_health_statistics", std::move(mempool_health_stats));
            }
            if (verbosity >= 3) {
                Assume(snapshot_before.has_value());
                Assume(estimator_results.has_value());
                Assume(health_diagnostics.has_value());
                const FeeRateEstimateResult& block_policy_estimate{estimator_results->block_policy};
                const FeeRateEstimateResult& mempool_policy_estimate{estimator_results->mempool_policy};

                UniValue diagnostics{UniValue::VOBJ};
                diagnostics.pushKV("requested_target", conf_target);
                diagnostics.pushKV("estimate_mode", std::string{self.Arg<std::string_view>("estimate_mode")});
                diagnostics.pushKV("requested_estimator", FeeRateEstimatorTypeToString(fee_rate_estimator));
                diagnostics.pushKV("block_policy", FeeRateEstimateDiagnostics(block_policy_estimate));
                diagnostics.pushKV("mempool_policy", FeeRateEstimateDiagnostics(mempool_policy_estimate));

                UniValue selection{UniValue::VOBJ};
                if (!block_policy_estimate && !mempool_policy_estimate) {
                    selection.pushKV("success", false);
                    selection.pushKV("reason", "both_estimators_error");
                } else if (!block_policy_estimate) {
                    selection.pushKV("success", false);
                    selection.pushKV("reason", "block_policy_error");
                } else if (!mempool_policy_estimate) {
                    selection.pushKV("success", false);
                    selection.pushKV("reason", "mempool_policy_error");
                } else {
                    const auto comparison{*block_policy_estimate <=> *mempool_policy_estimate};
                    const FeeRateEstimation& selected_estimate{*estimator_results->combined};
                    const CFeeRate selected_feerate{selected_estimate.feerate};
                    const CFeeRate returned_feerate{std::max(selected_feerate, effective_fee_floor)};
                    selection.pushKV("success", true);
                    selection.pushKV("reason", comparison < 0 ? "block_policy_lower" :
                                                  comparison > 0 ? "mempool_policy_lower" :
                                                                   "block_policy_tie");
                    selection.pushKV("estimator", FeeRateEstimatorTypeToString(selected_estimate.feerate_estimator));
                    selection.pushKV("blocks", selected_estimate.returned_target);
                    selection.pushKV("feerate_before_rpc_floor", ValueFromAmount(selected_feerate.GetFeePerK()));
                    selection.pushKV("feerate_fee_sats", selected_estimate.feerate.fee);
                    selection.pushKV("feerate_vsize", selected_estimate.feerate.size);
                    selection.pushKV("feerate_after_rpc_floor", ValueFromAmount(returned_feerate.GetFeePerK()));
                    selection.pushKV("fee_floor_applied", returned_feerate > selected_feerate);
                }
                diagnostics.pushKV("selection", std::move(selection));

                UniValue fee_floor{UniValue::VOBJ};
                fee_floor.pushKV("mempool_min", ValueFromAmount(min_mempool_feerate.GetFeePerK()));
                fee_floor.pushKV("min_relay", ValueFromAmount(min_relay_feerate.GetFeePerK()));
                fee_floor.pushKV("effective", ValueFromAmount(effective_fee_floor.GetFeePerK()));
                diagnostics.pushKV("fee_floor", std::move(fee_floor));

                if (estimator_results->mempool_cache) {
                    const auto& cache{*estimator_results->mempool_cache};
                    UniValue mempool_template{UniValue::VOBJ};
                    mempool_template.pushKV("p50", ValueFromAmount(CFeeRate(cache.estimate.m_conservative).GetFeePerK()));
                    mempool_template.pushKV("p75", ValueFromAmount(CFeeRate(cache.estimate.m_economical).GetFeePerK()));
                    mempool_template.pushKV("p50_fee_sats", cache.estimate.m_conservative.fee);
                    mempool_template.pushKV("p50_vsize", cache.estimate.m_conservative.size);
                    mempool_template.pushKV("p75_fee_sats", cache.estimate.m_economical.fee);
                    mempool_template.pushKV("p75_vsize", cache.estimate.m_economical.size);
                    mempool_template.pushKV("p50_used_fee_floor", cache.estimate.m_conservative_used_floor);
                    mempool_template.pushKV("p75_used_fee_floor", cache.estimate.m_economical_used_floor);
                    mempool_template.pushKV("cache_hit", estimator_results->mempool_cache_hit);
                    mempool_template.pushKV("tip_hash", cache.tip_hash.GetHex());
                    mempool_template.pushKV("cache_age_ms", cache.age.count());
                    mempool_template.pushKV("cache_lifetime_ms", std::chrono::duration_cast<std::chrono::milliseconds>(CACHE_LIFE).count());
                    diagnostics.pushKV("mempool_template", std::move(mempool_template));
                }

                const auto& health{*health_diagnostics};
                UniValue mempool_health{UniValue::VOBJ};
                mempool_health.pushKV("status", MempoolHealthToString(health.health));
                mempool_health.pushKV("tracked_blocks", health.tracked_blocks);
                mempool_health.pushKV("required_blocks", MEMPOOL_HEALTH_WINDOW_BLOCKS);
                if (!health.window_tip_hash.IsNull()) {
                    mempool_health.pushKV("window_tip_hash", health.window_tip_hash.GetHex());
                }
                mempool_health.pushKV("total_block_weight", health.total_block_weight);
                mempool_health.pushKV("mempool_txs_weight", health.total_removed_weight);
                if (health.coverage_ratio) {
                    mempool_health.pushKV("coverage_ratio", *health.coverage_ratio);
                }
                mempool_health.pushKV("required_coverage_ratio", MEMPOOL_REPRESENTATION_THRESHOLD);
                mempool_health.pushKV("minimum_representative_window_weight", health.minimum_representative_window_weight);
                mempool_health.pushKV("low_activity_bypass", health.low_activity_bypass);
                diagnostics.pushKV("mempool_health", std::move(mempool_health));

                // Capture final consistency markers only after all diagnostic snapshots have been read.
                const StateSnapshot snapshot_after{GetStateSnapshot(chainman, mempool)};
                const bool tip_consistent{snapshot_before->tip_hash == snapshot_after.tip_hash};
                const bool mempool_consistent{snapshot_before->mempool_sequence == snapshot_after.mempool_sequence};
                diagnostics.pushKV("tip_height_before", snapshot_before->tip_height);
                diagnostics.pushKV("tip_hash_before", snapshot_before->tip_hash.GetHex());
                diagnostics.pushKV("tip_height_after", snapshot_after.tip_height);
                diagnostics.pushKV("tip_hash_after", snapshot_after.tip_hash.GetHex());
                diagnostics.pushKV("tip_consistent", tip_consistent);
                diagnostics.pushKV("mempool_sequence_before", snapshot_before->mempool_sequence);
                diagnostics.pushKV("mempool_sequence_after", snapshot_after.mempool_sequence);
                diagnostics.pushKV("mempool_consistent", mempool_consistent);
                diagnostics.pushKV("snapshot_consistent", tip_consistent && mempool_consistent);

                result.pushKV("diagnostics", std::move(diagnostics));
            }
            return result;
        },
    };
}

static std::vector<RPCResult> FeeRateBucketDoc(bool elide = false)
{
    auto fields = std::vector<RPCResult>{
        {RPCResult::Type::NUM, "startrange", "start of feerate range"},
        {RPCResult::Type::NUM, "endrange", "end of feerate range"},
        {RPCResult::Type::NUM, "withintarget", "number of txs over history horizon in the feerate range that were confirmed within target"},
        {RPCResult::Type::NUM, "totalconfirmed", "number of txs over history horizon in the feerate range that were confirmed at any point"},
        {RPCResult::Type::NUM, "inmempool", "current number of txs in mempool in the feerate range unconfirmed for at least target blocks"},
        {RPCResult::Type::NUM, "leftmempool", "number of txs over history horizon in the feerate range that left mempool unconfirmed after target"},
    };
    return elide ? ElideGroup(std::move(fields)) : fields;
}

static std::vector<RPCResult> FeeEstimateHorizonDoc(bool elide = false)
{
    auto fields = std::vector<RPCResult>{
        {RPCResult::Type::NUM, "feerate", /*optional=*/true, "estimate fee rate in " + CURRENCY_UNIT + "/kvB"},
        {RPCResult::Type::NUM, "decay", "exponential decay (per block) for historical moving average of confirmation data"},
        {RPCResult::Type::NUM, "scale", "The resolution of confirmation targets at this time horizon"},
        {RPCResult::Type::OBJ, "pass", /*optional=*/true, "information about the lowest range of feerates to succeed in meeting the threshold", FeeRateBucketDoc()},
        {RPCResult::Type::OBJ, "fail", /*optional=*/true, "information about the highest range of feerates to fail to meet the threshold", FeeRateBucketDoc(/*elide=*/true)},
        {RPCResult::Type::ARR, "errors", /*optional=*/true, "Errors encountered during processing (if there are any)",
        {
            {RPCResult::Type::STR, "error", ""},
        }},
    };
    return elide ? ElideGroup(std::move(fields)) : fields;
}

static RPCMethod estimaterawfee()
{
    return RPCMethod{
        "estimaterawfee",
        "WARNING: This interface is unstable and may disappear or change!\n"
        "\nWARNING: This is an advanced API call that is tightly coupled to the specific\n"
        "implementation of fee estimation. The parameters it can be called with\n"
        "and the results it returns will change if the internal implementation changes.\n"
        "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
        "confirmation within conf_target blocks if possible. Uses virtual transaction size as\n"
        "defined in BIP 141 (witness data is discounted).\n",
        {
            {"conf_target", RPCArg::Type::NUM, RPCArg::Optional::NO, "Confirmation target in blocks (1 - 1008)"},
            {"threshold", RPCArg::Type::NUM, RPCArg::Default{0.95}, "The proportion of transactions in a given feerate range that must have been\n"
            "confirmed within conf_target in order to consider those feerates as high enough and proceed to check\n"
            "lower buckets."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Results are returned for any horizon which tracks blocks up to the confirmation target",
            {
                {RPCResult::Type::OBJ, "short", /*optional=*/true, "estimate for short time horizon",
                    FeeEstimateHorizonDoc()},
                {RPCResult::Type::OBJ, "medium", /*optional=*/true, "estimate for medium time horizon",
                    FeeEstimateHorizonDoc(/*elide=*/true)},
                {RPCResult::Type::OBJ, "long", /*optional=*/true, "estimate for long time horizon",
                    FeeEstimateHorizonDoc(/*elide=*/true)},
            }},
        RPCExamples{
            HelpExampleCli("estimaterawfee", "6 0.9")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            FeeRateEstimatorManager& fee_estimator_man = EnsureAnyFeeEstimatorMan(request.context);
            const NodeContext& node = EnsureAnyNodeContext(request.context);

            CHECK_NONFATAL(node.validation_signals)->SyncWithValidationInterfaceQueue();
            unsigned int max_target = fee_estimator_man.MaximumTarget();
            unsigned int conf_target = ParseConfirmTarget(request.params[0], max_target);
            double threshold = 0.95;
            if (!request.params[1].isNull()) {
                threshold = request.params[1].get_real();
            }
            if (threshold < 0 || threshold > 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid threshold");
            }

            UniValue result(UniValue::VOBJ);

            for (const FeeEstimateHorizon horizon : ALL_FEE_ESTIMATE_HORIZONS) {
                CFeeRate feeRate;
                EstimationResult buckets;

                // Only output results for horizons which track the target
                if (conf_target > fee_estimator_man.BlockPolicyHighestTargetTracked(horizon)) continue;

                feeRate = fee_estimator_man.BlockPolicyEstimateRawFee(conf_target, threshold, horizon, &buckets);
                UniValue horizon_result(UniValue::VOBJ);
                UniValue errors(UniValue::VARR);
                UniValue passbucket(UniValue::VOBJ);
                passbucket.pushKV("startrange", round(buckets.pass.start));
                passbucket.pushKV("endrange", round(buckets.pass.end));
                passbucket.pushKV("withintarget", round(buckets.pass.withinTarget * 100.0) / 100.0);
                passbucket.pushKV("totalconfirmed", round(buckets.pass.totalConfirmed * 100.0) / 100.0);
                passbucket.pushKV("inmempool", round(buckets.pass.inMempool * 100.0) / 100.0);
                passbucket.pushKV("leftmempool", round(buckets.pass.leftMempool * 100.0) / 100.0);
                UniValue failbucket(UniValue::VOBJ);
                failbucket.pushKV("startrange", round(buckets.fail.start));
                failbucket.pushKV("endrange", round(buckets.fail.end));
                failbucket.pushKV("withintarget", round(buckets.fail.withinTarget * 100.0) / 100.0);
                failbucket.pushKV("totalconfirmed", round(buckets.fail.totalConfirmed * 100.0) / 100.0);
                failbucket.pushKV("inmempool", round(buckets.fail.inMempool * 100.0) / 100.0);
                failbucket.pushKV("leftmempool", round(buckets.fail.leftMempool * 100.0) / 100.0);

                // CFeeRate(0) is used to indicate error as a return value from estimateRawFee
                if (feeRate != CFeeRate(0)) {
                    horizon_result.pushKV("feerate", ValueFromAmount(feeRate.GetFeePerK()));
                    horizon_result.pushKV("decay", buckets.decay);
                    horizon_result.pushKV("scale", buckets.scale);
                    horizon_result.pushKV("pass", std::move(passbucket));
                    // buckets.fail.start == -1 indicates that all buckets passed, there is no fail bucket to output
                    if (buckets.fail.start != -1) horizon_result.pushKV("fail", std::move(failbucket));
                } else {
                    // Output only information that is still meaningful in the event of error
                    horizon_result.pushKV("decay", buckets.decay);
                    horizon_result.pushKV("scale", buckets.scale);
                    horizon_result.pushKV("fail", std::move(failbucket));
                    errors.push_back("Insufficient data or no feerate found which meets threshold");
                    horizon_result.pushKV("errors", std::move(errors));
                }
                result.pushKV(StringForFeeEstimateHorizon(horizon), std::move(horizon_result));
            }
            return result;
        },
    };
}

void RegisterFeeRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"util", &estimatesmartfee},
        {"hidden", &estimaterawfee},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
