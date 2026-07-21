// src/blockstorage/BlockStorageInMemory.cpp
#include "BlockStorageInMemory.h"

#include <cstring>

namespace blockstorage {

InMemoryBlockStorage::InMemoryBlockStorage()
    : m_total_bytes(0), m_next_offset(0)
{
}

bool InMemoryBlockStorage::Open(const std::string& datadir)
{
    // In-memory backend doesn't need datadir; just succeed.
    (void)datadir;
    return true;
}

std::optional<DiskBlockPos> InMemoryBlockStorage::WriteBlock(const uint256& hash, const std::vector<uint8_t>& raw_block, int32_t height)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_store.count(hash)) {
        // already stored: return existing pos
        return m_store[hash].pos;
    }

    Stored s;
    s.raw = raw_block;
    s.height = height;
    s.on_disk_bytes = raw_block.size();
    s.pos.file = 0;
    s.pos.offset = static_cast<uint32_t>(m_next_offset++);
    s.pos.size = static_cast<uint32_t>(raw_block.size());

    m_order.push_back(hash);
    m_store.emplace(hash, std::move(s));
    m_total_bytes += raw_block.size();

    return m_store[hash].pos;
}

std::optional<BlockData> InMemoryBlockStorage::ReadBlockByHash(const uint256& hash)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_store.find(hash);
    if (it == m_store.end()) return std::nullopt;
    BlockData d;
    d.raw = it->second.raw;
    d.pos = it->second.pos;
    d.on_disk_bytes = it->second.on_disk_bytes;
    return d;
}

bool InMemoryBlockStorage::HasBlock(const uint256& hash)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_store.find(hash) != m_store.end();
}

size_t InMemoryBlockStorage::CurrentOnDiskSizeBytes()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_total_bytes;
}

bool InMemoryBlockStorage::PruneToTargetBytes(size_t target_bytes)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (target_bytes >= m_total_bytes) return true;

    while (!m_order.empty() && m_total_bytes > target_bytes) {
        uint256 oldest = m_order.front();
        auto it = m_store.find(oldest);
        if (it == m_store.end()) {
            m_order.pop_front();
            continue;
        }
        m_total_bytes -= it->second.on_disk_bytes;
        m_store.erase(it);
        m_order.pop_front();
    }

    return m_total_bytes <= target_bytes;
}

bool InMemoryBlockStorage::RemoveBlockByHash(const uint256& hash)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_store.find(hash);
    if (it == m_store.end()) return false;
    m_total_bytes -= it->second.on_disk_bytes;
    // Remove one occurrence from m_order
    for (auto oit = m_order.begin(); oit != m_order.end(); ++oit) {
        if (*oit == hash) {
            m_order.erase(oit);
            break;
        }
    }
    m_store.erase(it);
    return true;
}

} // namespace blockstorage
