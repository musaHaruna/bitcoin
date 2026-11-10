// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/fees/block_policy_estimator.h>
#include <policy/fees/estimator_args.h>
#include <policy/fees/mempool_estimator.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/reachability.h>
#include <test/util/setup_common.h>

#include <cstdio>
#include <memory>

namespace {
const TestingSetup* g_setup;
constexpr ReachabilityGoal BLOCK_POLICY_ESTIMATOR_READ_SUCCEEDS{"block policy estimator reading succeeds"};
} // namespace

void initialize_policy_estimator_io()
{
    RegisterReachabilityGoal(BLOCK_POLICY_ESTIMATOR_READ_SUCCEEDS);
    static const auto testing_setup{
        MakeNoLogFileContext<const TestingSetup>(ChainType::REGTEST, TestOpts{.setup_net = false})};
    g_setup = testing_setup.get();
}

FUZZ_TARGET(policy_estimator_io, .init = initialize_policy_estimator_io)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    FuzzedFileProvider fuzzed_file_provider{fuzzed_data_provider};
    // Reuse estimators across runs to avoid costly object creation.
    static CBlockPolicyEstimator block_policy_estimator{
        BlockPolicyFeeEstPath(*g_setup->m_node.args), DEFAULT_ACCEPT_STALE_FEE_ESTIMATES};
    bool block_policy_read_success{false};
    // FuzzedFileProvider is unavailable on some platforms (including macOS).
    // Also exercise a real file: either arbitrary bytes or a valid snapshot
    // with optional byte mutations, so successful reads remain reachable.
    {
        AutoFile real_file{std::tmpfile()};
        assert(!real_file.IsNull());
        if (fuzzed_data_provider.ConsumeBool()) {
            assert(block_policy_estimator.Write(real_file));
            const auto size{real_file.tell()};
            for (int mutations{fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 8)}; mutations > 0; --mutations) {
                real_file.seek(fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, size - 1), SEEK_SET);
                real_file << fuzzed_data_provider.ConsumeIntegral<uint8_t>();
            }
        } else {
            real_file.write(std::as_bytes(buffer));
        }
        real_file.seek(0, SEEK_SET);
        block_policy_read_success = block_policy_estimator.Read(real_file);
        (void)real_file.fclose();
    }
    {
        AutoFile fuzzed_auto_file_block_policy{fuzzed_file_provider.open()};
        const bool read_success{block_policy_estimator.Read(fuzzed_auto_file_block_policy)};
        block_policy_read_success |= read_success;
        if (read_success) {
            block_policy_estimator.Write(fuzzed_auto_file_block_policy);
        }
        (void)fuzzed_auto_file_block_policy.fclose();
    }
    static MemPoolFeeRateEstimator mempool_feerate_estimator{
        MempoolPolicyEstimatorPath(*g_setup->m_node.args),
        *g_setup->m_node.mempool,
        *g_setup->m_node.chainman};
    {
        AutoFile fuzzed_auto_file_mempool_policy{fuzzed_file_provider.open()};
        if (mempool_feerate_estimator.Read(fuzzed_auto_file_mempool_policy)) {
            mempool_feerate_estimator.Write(fuzzed_auto_file_mempool_policy);
        }
        // Write() does not take ownership; close explicitly because it may
        // have written to the fuzzed file.
        (void)fuzzed_auto_file_mempool_policy.fclose();
    }
    ObserveReachabilityGoal(block_policy_read_success, BLOCK_POLICY_ESTIMATOR_READ_SUCCEEDS);
}
