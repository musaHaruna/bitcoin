// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_TYPES_H
#define BITCOIN_INTERFACES_TYPES_H

#include <uint256.h>

#include <cstdint>

namespace interfaces {

//! Hash/height pair to help track and identify blocks.
struct BlockRef {
    uint256 hash;
    int height = -1;
};

//! Block and header tip information.
struct BlockTip {
    int block_height;
    int64_t block_time;
    uint256 block_hash;
};

} // namespace interfaces

#endif // BITCOIN_INTERFACES_TYPES_H
