// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_POLICY_FEES_CHUNK_CONFIRM_STATS_H
#define BITCOIN_POLICY_FEES_CHUNK_CONFIRM_STATS_H

#include <kernel/mempool_removal_reason.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

class AutoFile;

inline constexpr size_t NUM_CHUNK_END_REASONS{static_cast<size_t>(MemPoolChunkEndReason::COUNT)};

/** Fixed target rows plus bounded cohorts grouped by birth height and fee bucket.
 * Confirmations immediately enter every target they met and leave their cohort.
 * Remaining observations enter each target row at birth+target, after block
 * evidence is applied. Successes decay from confirmation; failures and unknowns
 * decay from their target deadline. There is no separate, undecayed pending term.
 */
class ChunkConfirmStats
{
public:
    struct Bucket
    {
        double start = -1;
        double end = -1;
        double success{0};
        double failure{0};
        std::array<double, NUM_CHUNK_END_REASONS> unknown{};
        double Unknown() const;
        double Total() const { return success + failure + Unknown(); }
        double Lower() const { return Total() ? success / Total() : 0; }
        double Upper() const { return Total() ? (success + Unknown()) / Total() : 1; }
    };

    struct Result
    {
        Bucket pass;
        Bucket fail;
        Bucket all;
        double decay = 0;
        unsigned int scale = 0;
        unsigned int target{0};
        size_t active_observations{0};
        size_t cohort_heights{0};
        std::array<uint64_t, NUM_CHUNK_END_REASONS> endings{};
    };

private:
    struct Cohort {
        uint64_t count{0};
        std::array<uint64_t, NUM_CHUNK_END_REASONS> unknown{};
        double fee_sum{0};
        uint64_t Unknown() const;
        uint64_t Active() const;
    };
    struct Cell {
        Bucket outcomes;
        double fee_sum{0};
    };
    const std::vector<double>& buckets;
    const std::map<double, unsigned int>& bucketMap;
    const double decay;
    const unsigned int scale;
    std::vector<std::vector<Cell>> m_rows;
    std::map<unsigned int, std::map<unsigned int, Cohort>> m_cohorts;

    static void Add(Bucket& dest, const Bucket& source, double weight = 1);
    static void ReadDouble(AutoFile& file, double& value);

public:
    /** Bucket bounds and their index map must outlive this object. */
    ChunkConfirmStats(const std::vector<double>& default_buckets,
                      const std::map<double, unsigned int>& bucket_map,
                      unsigned int periods, double decay_in, unsigned int scale_in);

    unsigned int GetMaxConfirms() const { return scale * m_rows.size(); }
    size_t CohortHeights() const { return m_cohorts.size(); }
    void Reset();
    unsigned int NewChunk(unsigned int height, double rate);
    /** Close an observation; return whether a confirmation added immediate statistics. */
    bool EndChunk(unsigned int birth, unsigned int height, unsigned int bucket,
                  double rate, MemPoolChunkEndReason reason);
    void UpdateMovingAverages(unsigned int blocks);
    /** Record newly reached deadlines after applying block confirmation and ending evidence. */
    bool Mature(unsigned int previous, unsigned int height);
    void CheckPending(const std::map<unsigned int, std::map<unsigned int, uint64_t>>& expected, unsigned int height) const;
    double EstimateMedianVal(int target, double sufficient, double threshold, Result* result) const;
    void Write(AutoFile& file, unsigned int height) const;
    void Read(AutoFile& file, size_t num_buckets, unsigned int best_height);
};

#endif // BITCOIN_POLICY_FEES_CHUNK_CONFIRM_STATS_H
