// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_KERNEL_MEMPOOL_REMOVAL_REASON_H
#define BITCOIN_KERNEL_MEMPOOL_REMOVAL_REASON_H

#include <cstdint>
#include <string>

/** Reason why a transaction was removed from the mempool,
 * this is passed to the notification signal.
 */
enum class MemPoolRemovalReason {
    EXPIRY,      //!< Expired from mempool
    SIZELIMIT,   //!< Removed in size limiting
    REORG,       //!< Removed for reorganization
    BLOCK,       //!< Removed for block
    CONFLICT,    //!< Removed for conflict with in-block transaction
    REPLACED,    //!< Removed for replacement
};

/** Why a continuously observed chunk stopped being the same mining offer.
 * These values also index persisted estimator diagnostics; changing them requires
 * a fee-estimates format version change. Confirmation is not an unknown outcome.
 */
enum class MemPoolChunkEndReason : uint8_t {
    CONFIRMED,
    REPLACED,
    PACKAGE_CHANGED,
    EXPIRY,
    EVICTION,
    PARTIAL_CONFIRMATION,
    UNSEEN_SPONSOR,
    BLOCK_CONFLICT,
    LOCAL_POLICY,
    REORDERING,
    OBSERVATION_LOST,
    COUNT,
};

std::string RemovalReasonToString(const MemPoolRemovalReason& r) noexcept;

#endif // BITCOIN_KERNEL_MEMPOOL_REMOVAL_REASON_H
