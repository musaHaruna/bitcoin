// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/kernel_mempool.h>

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
} // namespace node
