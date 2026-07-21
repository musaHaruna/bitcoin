#pragma once
// src/blockstorage/BlockStorageInMemory.h
//
// Simple in-memory BlockStorage implementation used for unit tests.
// Not intended for production use.

#include "include/blockstorage/IBlockStorage.h"

#include <map>
#include <deque>
#include <mutex>

namespace blockstorage {

class InMemoryBlockStorage final : public IBlockStorage {
public:
    InMemoryBlockStorage();
    ~InMemoryBlockStorage() override = default;

    bool Open(const std::string& datadir) override;

    std::optional<DiskBlockPos> WriteBlock(const uint256& hash, const std::vector<uint8_t>& raw_block, int32_t height = -1) override;
    std::optional<BlockData> ReadBlockByHash(const uint256& hash) override;
    bool HasBlock(const uint256& hash) override;

    size_t CurrentOnDiskSizeBytes() override;
    bool PruneToTargetBytes(size_t target_bytes) override;
    bool RemoveBlockByHash(const uint256& hash) override;

private:
    struct Stored {
        std::vector<uint8_t> raw;
        int32_t height;
        DiskBlockPos pos;
        size_t on_disk_bytes;
    };

    // ordered insertion queue of hashes (oldest front)
    std::deque<uint256> m_order;
    std::map<uint256, Stored> m_store;
    size_t m_total_bytes;
    std::mutex m_mutex;
    int m_next_offset; // used to assign DiskBlockPos::offset values
};

} // namespace blockstorage
