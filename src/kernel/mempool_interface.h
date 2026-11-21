// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_MEMPOOL_INTERFACE_H
#define BITCOIN_KERNEL_MEMPOOL_INTERFACE_H

#include <kernel/cs_main.h>
#include <kernel/mempool_events.h>
#include <primitives/transaction.h>
#include <sync.h>

#include <vector>

class CTransaction;

namespace kernel {
/** Internal, synchronous integration with a node's transaction pool.
 *
 * A null attachment means no mempool. The node owns this interface and its pool
 * and must keep both alive until all chainstates have been destroyed. Only the
 * active chainstate is attached; snapshot transitions transfer that attachment.
 */
class Mempool
{
public:
    virtual ~Mempool() = default;
    /** Remove this transaction and its descendants after disconnect-queue eviction. */
    virtual void RemoveRecursiveForReorg(const CTransaction& tx)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) = 0;
    /** Return owned metadata for confirmed pool transactions in block order. */
    virtual std::vector<RemovedMempoolTransactionInfo> removeForBlock(const std::vector<CTransactionRef>& txs)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) = 0;
};
} // namespace kernel

#endif // BITCOIN_KERNEL_MEMPOOL_INTERFACE_H
