#pragma once
// include/blockstorage/IBlockStorage.h
//
// Minimal block storage interface used by ChainstateManager and tests.
// Small, safe API suitable for initial migration & unit testing.

#include <optional>
#include <string>
#include <vector>
#include <cstdint>

#include "uint256.h"

namespace blockstorage {

// Represents a disk position (for on-disk backends). Implementations may
// interpret fields differently; in-memory backend uses file=0 and offset=index.
struct DiskBlockPos {
    int file = -1;
    uint32_t offset = 0;
    uint32_t size = 0;
};

// BlockData returned by ReadBlock* methods.
struct BlockData {
    std::vector<uint8_t> raw;
    DiskBlockPos pos;
    size_t on_disk_bytes = 0;
};

// Abstract interface for block storage backends.
// This is intentionally small for the initial migration step.
class IBlockStorage {
public:
    virtual ~IBlockStorage() = default;

    // Open / initialize the storage. Directory parameter is advisory (may be ignored by some impls).
    virtual bool Open(const std::string& datadir) = 0;

    // Write a raw block associated with a given hash. Returns DiskBlockPos on success.
    // Optionally pass height (default -1) for backends/tests that track heights.
    virtual std::optional<DiskBlockPos> WriteBlock(const uint256& hash, const std::vector<uint8_t>& raw_block, int32_t height = -1) = 0;

    // Read block data by its disk position or by block hash.
    virtual std::optional<BlockData> ReadBlockByHash(const uint256& hash) = 0;

    // Existence check.
    virtual bool HasBlock(const uint256& hash) = 0;

    // Return current bytes accounted as block storage by this backend.
    virtual size_t CurrentOnDiskSizeBytes() = 0;

    // Prune until total bytes <= target_bytes. Returns true on success.
    virtual bool PruneToTargetBytes(size_t target_bytes) = 0;

    // Remove a single block by hash. Returns true if removed.
    virtual bool RemoveBlockByHash(const uint256& hash) = 0;
};

} // namespace blockstorage
