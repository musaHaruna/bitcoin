// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/fees.h>

#include <common/messages.h>
#include <core_io.h>
#include <node/context.h>
#include <policy/feerate.h>
#include <policy/fees/block_policy_estimator.h>
#include <policy/fees/estimator_man.h>
#include <policy/fees/mempool_estimator.h>
#include <rpc/protocol.h>
#include <rpc/register.h> // IWYU pragma: associated
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/check.h>
#include <util/expected.h>
#include <validationinterface.h>

#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using common::FeeModeFromString;
using common::FeeModesDetail;
using common::InvalidEstimateModeErrorMessage;
using node::NodeContext;

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
                    {"fee_rate_estimator", RPCArg::Type::STR, RPCArg::Default{"auto"},
                     "Selects which fee rate estimator to use.\n"
                     "\"auto\" (the default) combines both estimators, returning the lower of the block policy and\n"
                     "mempool fee rate estimates. If the mempool fee rate estimator cannot produce an estimate, the\n"
                     "block policy fee rate estimate is returned instead. An error is returned only if the block\n"
                     "policy fee rate estimate is unavailable.\n"
                     "\"block_policy\" uses only the block policy fee rate estimator.\n"
                     "\"mempool_policy\" uses only the mempool fee rate estimator."},
                    {"verbosity", RPCArg::Type::NUM, RPCArg::Default{1},
                     "1 returns feerate or errors. 2 also returns \"mempool_health_statistics\"."},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "feerate", /*optional=*/true, "estimate fee rate in " + CURRENCY_UNIT + "/kvB (only present if no errors were encountered)"},
                {RPCResult::Type::STR, "estimator", /*optional=*/true, "the fee estimator used to produce the result (only present for successful estimates when fee_rate_estimator is \"auto\")"},
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
            const auto parsed_fee_rate_estimator{FeeRateEstimatorTypeFromString(
                options["fee_rate_estimator"].isNull() ? "auto" : options["fee_rate_estimator"].get_str())};
            if (!parsed_fee_rate_estimator) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid fee_rate_estimator parameter, must be one of: \"auto\", \"block_policy\", \"mempool_policy\"");
            }
            const FeeRateEstimatorType fee_rate_estimator{*parsed_fee_rate_estimator};
            bool conservative{fee_mode == FeeEstimateMode::CONSERVATIVE};
            int verbosity{ParseVerbosity(options["verbosity"], /*default_verbosity=*/1, /*allow_bool=*/false)};
            UniValue result(UniValue::VOBJ);
            UniValue errors(UniValue::VARR);
            const auto estimate{fee_estimator_man.GetFeeRateEstimate(fee_rate_estimator, conf_target, conservative)};
            if (estimate) {
                const CFeeRate min_mempool_feerate{mempool.GetMinFee()};
                const CFeeRate min_relay_feerate{mempool.m_opts.min_relay_feerate};
                const auto fee_rate{std::max({CFeeRate(estimate->feerate), min_mempool_feerate, min_relay_feerate})};
                result.pushKV("feerate", ValueFromAmount(fee_rate.GetFeePerK()));
            } else {
                errors.push_back(estimate.error().reason);
                result.pushKV("errors", std::move(errors));
            }
            if (estimate && fee_rate_estimator == FeeRateEstimatorType::AUTO) {
                result.pushKV("estimator", FeeRateEstimatorTypeToString(estimate->feerate_estimator));
            }
            const FeeRateEstimation& estimation{FeeRateEstimationRef(estimate)};
            result.pushKV("blocks", estimation.returned_target);
            if (verbosity >= 2) {
                UniValue mempool_health_stats(UniValue::VARR);
                const auto blocks_data = fee_estimator_man.MempoolPolicyEstimatorBlocksStats();
                for (auto it = blocks_data.rbegin(); it != blocks_data.rend(); ++it) {
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("block_height", it->m_height);
                    entry.pushKV("block_weight", it->m_block_weight);
                    entry.pushKV("mempool_txs_weight", it->m_removed_block_txs_weight);
                    mempool_health_stats.push_back(std::move(entry));
                }
                result.pushKV("mempool_health_statistics", std::move(mempool_health_stats));
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
        {RPCResult::Type::NUM, "success", "decayed chunk observations confirmed by their target deadline"},
        {RPCResult::Type::NUM, "failure", "decayed chunk observations known unconfirmed through their target deadline"},
        {RPCResult::Type::NUM, "unknown", "decayed chunk observations whose target outcome is unknown; excluded from fee estimation"},
        {RPCResult::Type::NUM, "total", "success + failure + unknown; confirmations enter immediately, other outcomes at their target deadline"},
        {RPCResult::Type::NUM, "known_outcomes", "success + failure; the decayed observations used for estimation support"},
        {RPCResult::Type::NUM, "known_success_ratio", "success / known_outcomes (0 if empty); the ratio compared with the threshold"},
        {RPCResult::Type::NUM, "lower", "success / total (0 if empty); descriptive bound, not a confidence interval; not used for the threshold"},
        {RPCResult::Type::NUM, "upper", "(success + unknown) / total (1 if empty); descriptive bound, not a confidence interval; not used for the threshold"},
        {RPCResult::Type::OBJ_DYN, "unknown_reasons", "unknown weights by ending reason", {
            {RPCResult::Type::NUM, "reason", "decayed unknown weight"},
        }},
    };
    return elide ? ElideGroup(std::move(fields)) : fields;
}

static UniValue FeeRateBucketJSON(const EstimatorBucket& bucket)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("startrange", bucket.start);
    result.pushKV("endrange", bucket.end);
    result.pushKV("success", bucket.success);
    result.pushKV("failure", bucket.failure);
    result.pushKV("unknown", bucket.Unknown());
    result.pushKV("total", bucket.Total());
    result.pushKV("known_outcomes", bucket.Known());
    result.pushKV("known_success_ratio", bucket.SuccessRatio());
    result.pushKV("lower", bucket.Lower());
    result.pushKV("upper", bucket.Upper());
    UniValue reasons{UniValue::VOBJ};
    for (size_t i{1}; i < NUM_CHUNK_END_REASONS; ++i) reasons.pushKV(StringForChunkEndReason(static_cast<MemPoolChunkEndReason>(i)), bucket.unknown[i]);
    result.pushKV("unknown_reasons", std::move(reasons));
    return result;
}

static std::vector<RPCResult> FeeEstimateHorizonDoc(bool elide = false)
{
    auto fields = std::vector<RPCResult>{
        {RPCResult::Type::NUM, "feerate", /*optional=*/true, "estimate fee rate in " + CURRENCY_UNIT + "/kvB"},
        {RPCResult::Type::NUM, "decay", "exponential decay (per block) for historical moving average of confirmation data"},
        {RPCResult::Type::NUM, "scale", "The resolution of confirmation targets at this time horizon"},
        {RPCResult::Type::NUM, "target", "Effective target, rounded up to this horizon's resolution"},
        {RPCResult::Type::NUM, "active_observations", "Currently tracked chunk observations, including immature ones"},
        {RPCResult::Type::NUM, "cohort_heights", "Birth heights retained for unresolved future targets"},
        {RPCResult::Type::OBJ_DYN, "endings", "Unweighted observation endings since process start, by reason", {
            {RPCResult::Type::NUM, "reason", "number of endings"},
        }},
        {RPCResult::Type::OBJ, "population", "Recorded outcomes across all fee buckets", FeeRateBucketDoc()},
        {RPCResult::Type::OBJ, "pass", /*optional=*/true, "information about the lowest range of feerates to succeed in meeting the threshold", FeeRateBucketDoc()},
        {RPCResult::Type::OBJ, "fail", /*optional=*/true, "information about the highest range of feerates to fail to meet the threshold", FeeRateBucketDoc(/*elide=*/true)},
        {RPCResult::Type::ARR, "errors", /*optional=*/true, "Errors encountered during processing (if there are any)",
        {
            {RPCResult::Type::STR, "", "error"},
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
            {"threshold", RPCArg::Type::NUM, RPCArg::Default{0.95}, "The minimum success / (success + failure) ratio required to consider those feerates\n"
            "high enough and proceed to check lower buckets. Success means confirmation within conf_target.\n"
            "Unknown outcomes are excluded from this ratio, the minimum sample support, and the estimated feerate."},
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
            const double threshold{self.Arg<double>("threshold")};
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
                UniValue passbucket = FeeRateBucketJSON(buckets.pass);
                UniValue failbucket = FeeRateBucketJSON(buckets.fail);
                horizon_result.pushKV("target", buckets.target);
                horizon_result.pushKV("active_observations", uint64_t(buckets.active_observations));
                horizon_result.pushKV("cohort_heights", uint64_t(buckets.cohort_heights));
                horizon_result.pushKV("population", FeeRateBucketJSON(buckets.all));
                UniValue endings{UniValue::VOBJ};
                for (size_t i{0}; i < NUM_CHUNK_END_REASONS; ++i) endings.pushKV(StringForChunkEndReason(static_cast<MemPoolChunkEndReason>(i)), buckets.endings[i]);
                horizon_result.pushKV("endings", std::move(endings));

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
