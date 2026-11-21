// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/kernel_mempool.h>

#include <node/mempool_accept.h>

namespace node {
void KernelMempool::RemoveRecursiveForReorg(const CTransaction& tx)
{
    AssertLockHeld(m_mempool.cs);
    m_mempool.removeRecursive(tx, MemPoolRemovalReason::REORG);
}

std::vector<RemovedMempoolTransactionInfo> KernelMempool::removeForBlock(const std::vector<CTransactionRef>& txs)
{
    AssertLockHeld(m_mempool.cs);
    return m_mempool.removeForBlock(txs);
}

size_t KernelMempool::DynamicMemoryUsage() const { return m_mempool.DynamicMemoryUsage(); }
void KernelMempool::AddTransactionsUpdated(unsigned int n) { m_mempool.AddTransactionsUpdated(n); }
void KernelMempool::check(const CCoinsViewCache& coins, int64_t spend_height) const { m_mempool.check(coins, spend_height); }
bool KernelMempool::Empty() const { return m_mempool.size() == 0; }
size_t KernelMempool::MaxSizeBytes() const { return m_mempool.m_opts.max_size_bytes; }

void KernelMempool::UpdateForReorg(Chainstate& chainstate, DisconnectedBlockTransactions& disconnected, bool add_to_mempool)
{
    AssertLockHeld(m_mempool.cs);
    UpdateMempoolForReorg(chainstate, m_mempool, disconnected, add_to_mempool);
}
} // namespace node
