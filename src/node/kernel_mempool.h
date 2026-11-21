// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_KERNEL_MEMPOOL_H
#define BITCOIN_NODE_KERNEL_MEMPOOL_H

#include <kernel/mempool_interface.h>
#include <txmempool.h>

namespace node {
/** Wrap an existing pool without owning it. Keep the pool alive until this adapter is destroyed. */
class KernelMempool final : public kernel::Mempool
{
    CTxMemPool& m_mempool;

public:
    explicit KernelMempool(CTxMemPool& pool) : m_mempool{pool} {}
    void RemoveRecursiveForReorg(const CTransaction& tx) override EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_mempool.cs);
    std::vector<RemovedMempoolTransactionInfo> removeForBlock(const std::vector<CTransactionRef>& txs) override
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_mempool.cs);
    size_t DynamicMemoryUsage() const override;
    void AddTransactionsUpdated(unsigned int n) override;
    void check(const CCoinsViewCache& coins, int64_t spend_height) const override EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool Empty() const override;
    size_t MaxSizeBytes() const override;
    void UpdateForReorg(Chainstate& chainstate, DisconnectedBlockTransactions& disconnected,
                       bool add_to_mempool) override EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_mempool.cs);
};
} // namespace node

#endif // BITCOIN_NODE_KERNEL_MEMPOOL_H
