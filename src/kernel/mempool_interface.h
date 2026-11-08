// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_MEMPOOL_INTERFACE_H
#define BITCOIN_KERNEL_MEMPOOL_INTERFACE_H

#include <kernel/cs_main.h>
#include <kernel/mempool_events.h>
#include <primitives/transaction.h>
#include <sync.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class Chainstate;
class CCoinsViewCache;
class CTransaction;
class DisconnectedBlockTransactions;

namespace kernel {
/** Internal interface for chainstate to call the node's mempool functions.
 * Calls finish their mempool work before returning.
 *
 * The node owns this object and the pool. Keep both alive until all chainstates
 * are destroyed. A null pointer in Chainstate means no mempool is attached.
 * Only the active chainstate can have a pool attached. Move that attachment
 * when snapshot processing changes which chainstate is active.
 *
 * Chain activation locks cs_main first, then the mutex returned by GetMutex().
 * Keep both locked while disconnecting blocks, connecting blocks, and updating
 * the mempool after a reorg. GetMutex() must return the same mutex object
 * for the lifetime of this mempool implementation.
 *
 * While these locks are held, member functions must not call ActivateBestChain(),
 * directly or indirectly. They must not wait for queued validation notifications
 * to finish, since notification handlers may need the same locks.
 *
 * Member functions that do not require the caller to hold the pool lock must
 * handle any synchronization they need, such as locking internally or using
 * atomic operations.
 */
class Mempool
{
public:
    virtual ~Mempool() = default;
    /** Return the mutex that protects the pool. */
    virtual RecursiveMutex& GetMutex() const = 0;
    /** Remove this transaction and its descendants after disconnect-queue eviction. */
    virtual void RemoveRecursiveForReorg(const CTransaction& tx)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, GetMutex()) = 0;
    /**
     * Remove transactions confirmed by the block and transactions conflicting with it.
     * Return metadata only for transactions previously in the pool and confirmed by
     * the block, in their order in txs; conflicting removals are not included.
     * The returned transaction references and values must remain valid after removal.
     */
    virtual std::vector<RemovedMempoolTransactionInfo> removeForBlock(const std::vector<CTransactionRef>& txs)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, GetMutex()) = 0;
    /** Return current dynamic memory usage; synchronize internally if needed. */
    virtual size_t DynamicMemoryUsage() const = 0;
    /** Advance the update counter; synchronize internally if needed. */
    virtual void AddTransactionsUpdated(unsigned int n) = 0;
    /** Check pool consistency against coins; acquire the pool mutex if needed. */
    virtual void check(const CCoinsViewCache& coins, int64_t spend_height) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) = 0;
    /** Return whether the pool is empty; synchronize internally if needed. */
    virtual bool Empty() const = 0;
    /** Return the configured pool capacity; synchronize internally if needed. */
    virtual size_t MaxSizeBytes() const = 0;
    /**
     * Reconcile the pool with chainstate after disconnection and drain disconnected.
     * When add_to_mempool is false, perform removal/cleanup without readmission;
     * the entire queue must still be consumed.
     */
    virtual void UpdateForReorg(Chainstate& chainstate, DisconnectedBlockTransactions& disconnected,
                               bool add_to_mempool)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, GetMutex()) = 0;
};
} // namespace kernel

#endif // BITCOIN_KERNEL_MEMPOOL_INTERFACE_H
