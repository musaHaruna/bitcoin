// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <policy/fees/chunk_confirm_stats.h>

#include <serialize.h>
#include <streams.h>
#include <util/serfloat.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <numeric>
#include <stdexcept>

namespace {

struct EncodedDoubleFormatter
{
    template<typename Stream> void Ser(Stream &s, double v)
    {
        s << EncodeDouble(v);
    }

    template<typename Stream> void Unser(Stream& s, double& v)
    {
        uint64_t encoded;
        s >> encoded;
        v = DecodeDouble(encoded);
    }
};

} // namespace

double ChunkConfirmStats::Bucket::Unknown() const
{
    return std::accumulate(unknown.begin(), unknown.end(), 0.0);
}

uint64_t ChunkConfirmStats::Cohort::Unknown() const
{
    return std::accumulate(unknown.begin(), unknown.end(), uint64_t{0});
}

uint64_t ChunkConfirmStats::Cohort::Active() const
{
    assert(Unknown() <= count);
    return count - Unknown();
}

ChunkConfirmStats::ChunkConfirmStats(const std::vector<double>& default_buckets,
                                   const std::map<double, unsigned int>& bucket_map,
                                   unsigned int periods, double decay_in, unsigned int scale_in)
    : buckets{default_buckets}, bucketMap{bucket_map}, decay{decay_in}, scale{scale_in},
      m_rows(periods, std::vector<Cell>(default_buckets.size())) {}

void ChunkConfirmStats::Add(Bucket& dest, const Bucket& source, double weight)
{
    dest.success += source.success * weight;
    dest.failure += source.failure * weight;
    for (size_t i{0}; i < NUM_CHUNK_END_REASONS; ++i) dest.unknown[i] += source.unknown[i] * weight;
}

void ChunkConfirmStats::ReadDouble(AutoFile& file, double& value)
{
    file >> Using<EncodedDoubleFormatter>(value);
    if (!std::isfinite(value) || value < 0) throw std::runtime_error("Invalid cohort statistic");
}

void ChunkConfirmStats::Reset()
{
    m_cohorts.clear();
    for (auto& row : m_rows) std::ranges::fill(row, Cell{});
}

unsigned int ChunkConfirmStats::NewChunk(unsigned int height, double rate)
{
    const auto bucket = bucketMap.lower_bound(rate)->second;
    auto& cohort = m_cohorts[height][bucket];
    ++cohort.count;
    cohort.fee_sum += rate;
    return bucket;
}

bool ChunkConfirmStats::EndChunk(unsigned int birth, unsigned int height, unsigned int bucket,
                                 double rate, MemPoolChunkEndReason reason)
{
    const auto start = m_cohorts.find(birth);
    if (start == m_cohorts.end()) return false; // All targets already resolved.
    auto& cohort = start->second.at(bucket);
    assert(height >= birth);
    assert(cohort.Active() > 0);
    bool recorded{false};
    if (height > birth && reason == MemPoolChunkEndReason::CONFIRMED) {
        // A known confirmation already meets every target at least this long.
        // Shorter targets retain the misses recorded at their deadlines.
        const size_t first_period = (height - birth - 1) / scale;
        for (size_t period = first_period; period < m_rows.size(); ++period) {
            auto& cell = m_rows[period][bucket];
            ++cell.outcomes.success;
            cell.fee_sum += rate;
            recorded = true;
        }
    }
    if (height == birth || reason == MemPoolChunkEndReason::CONFIRMED) {
        // Same-height endings had no block opportunity. Confirmed observations
        // were recorded above and must not enter later deadlines a second time.
        --cohort.count;
        cohort.fee_sum = std::max(0.0, cohort.fee_sum - rate);
        if (!cohort.count) {
            start->second.erase(bucket);
            if (start->second.empty()) m_cohorts.erase(start);
        }
    } else {
        ++cohort.unknown.at(static_cast<size_t>(reason));
    }
    return recorded;
}

void ChunkConfirmStats::UpdateMovingAverages(unsigned int blocks)
{
    const auto factor = std::pow(decay, blocks);
    for (auto& row : m_rows) for (auto& cell : row) {
        cell.outcomes.success *= factor;
        cell.outcomes.failure *= factor;
        for (auto& count : cell.outcomes.unknown) count *= factor;
        cell.fee_sum *= factor;
        if (cell.outcomes.Total() == 0) cell.fee_sum = 0;
    }
}

bool ChunkConfirmStats::Mature(unsigned int previous, unsigned int height)
{
    bool recorded{false};
    if (height == previous) return false;
    for (size_t period{0}; period < m_rows.size(); ++period) {
        const unsigned int target = (period + 1) * scale;
        if (height < target) continue;
        // Also resolves deadlines passed during an observation gap. Active
        // episodes must have been closed as unknown before advancing the clock.
        auto it = m_cohorts.lower_bound(previous >= target ? previous - target + 1 : 0);
        for (; it != m_cohorts.end() && it->first <= height - target; ++it) {
            const auto weight = std::pow(decay, height - it->first - target);
            for (const auto& [bucket, cohort] : it->second) {
                auto& cell = m_rows[period][bucket];
                cell.outcomes.failure += weight * cohort.Active();
                for (size_t i{0}; i < NUM_CHUNK_END_REASONS; ++i) cell.outcomes.unknown[i] += weight * cohort.unknown[i];
                cell.fee_sum += weight * cohort.fee_sum;
                recorded |= cohort.count != 0;
            }
        }
    }
    // All targets of these birth cohorts have now been recorded.
    if (height >= GetMaxConfirms()) m_cohorts.erase(m_cohorts.begin(), m_cohorts.upper_bound(height - GetMaxConfirms()));
    return recorded;
}

void ChunkConfirmStats::CheckPending(const std::map<unsigned int, std::map<unsigned int, uint64_t>>& expected, unsigned int height) const
{
    assert(m_cohorts.size() <= GetMaxConfirms());
    for (const auto& [birth, by_bucket] : expected) {
        if (height - birth >= GetMaxConfirms()) continue;
        assert(m_cohorts.contains(birth));
        for (const auto& [bucket, count] : by_bucket) assert(m_cohorts.at(birth).at(bucket).Active() == count);
    }
    for (const auto& [birth, by_bucket] : m_cohorts) for (const auto& [bucket, cohort] : by_bucket) {
        assert(birth <= height && height - birth < GetMaxConfirms());
        uint64_t active{0};
        if (const auto it = expected.find(birth); it != expected.end()) {
            if (const auto b = it->second.find(bucket); b != it->second.end()) active = b->second;
        }
        assert(cohort.Active() == active);
    }
}

double ChunkConfirmStats::EstimateMedianVal(int target, double sufficient, double threshold, Result* result) const
{
    const size_t period = (target + scale - 1) / scale - 1;
    const auto& row = m_rows.at(period);
    Bucket range, pass, fail, all;
    double support{0};
    bool passing{true}, found{false};
    size_t best_low{0}, best_high{0}, high{row.size() - 1};
    bool new_range{true};
    for (size_t b = row.size(); b-- > 0;) {
        Add(all, row[b].outcomes);
        if (new_range) { high = b; new_range = false; }
        range.start = b ? buckets[b - 1] : 0;
        range.end = buckets[high];
        Add(range, row[b].outcomes);
        support += row[b].outcomes.Total();
        if (support < sufficient / (1 - decay)) continue;
        support = 0;
        // Unknown outcomes remain in the denominator: this is a descriptive
        // lower bound, not a confidence interval or a guarantee of calibration.
        if (range.Lower() < threshold) {
            if (passing) fail = range;
            passing = false;
        } else {
            pass = range;
            fail = Bucket{};
            found = passing = true;
            best_low = b;
            best_high = high;
            range = Bucket{};
            new_range = true;
        }
    }
    if (passing && !new_range) fail = range;
    double median{-1};
    if (found) {
        double remaining = pass.Total() / 2;
        for (size_t b = best_low; b <= best_high; ++b) {
            const double count = row[b].outcomes.Total();
            if (count < remaining) remaining -= count;
            else if (count > 0) { median = row[b].fee_sum / count; break; }
        }
    }
    if (result) {
        result->pass = pass;
        result->fail = fail;
        all.start = 0;
        all.end = buckets.back();
        result->all = all;
        result->decay = decay;
        result->scale = scale;
        result->target = (period + 1) * scale;
        result->cohort_heights = m_cohorts.size();
    }
    return median;
}

void ChunkConfirmStats::Write(AutoFile& file, unsigned int height) const
{
    file << Using<EncodedDoubleFormatter>(decay) << scale << uint32_t(m_rows.size());
    for (const auto& row : m_rows) for (const auto& cell : row) {
        file << Using<EncodedDoubleFormatter>(cell.outcomes.success)
             << Using<EncodedDoubleFormatter>(cell.outcomes.failure)
             << Using<EncodedDoubleFormatter>(cell.fee_sum);
        for (const auto value : cell.outcomes.unknown) file << Using<EncodedDoubleFormatter>(value);
    }
    // Match EndChunk's zero-opportunity exclusion in the saved view too.
    // A periodic save must not change the running cohort or active identities.
    file << uint32_t(m_cohorts.size() - m_cohorts.contains(height));
    for (const auto& [birth, by_bucket] : m_cohorts) {
        if (birth == height) continue;
        file << birth << uint32_t(by_bucket.size());
        for (const auto& [bucket, original] : by_bucket) {
            auto cohort = original;
            // Active observations cannot be resumed across downtime. Keep
            // unresolved deadlines as unknown instead of silently dropping them.
            cohort.unknown[static_cast<size_t>(MemPoolChunkEndReason::OBSERVATION_LOST)] += cohort.Active();
            file << bucket << cohort.count;
            for (const auto count : cohort.unknown) file << count;
            file << Using<EncodedDoubleFormatter>(cohort.fee_sum);
        }
    }
}

void ChunkConfirmStats::Read(AutoFile& file, size_t num_buckets, unsigned int best_height)
{
    double file_decay;
    unsigned int file_scale;
    uint32_t periods;
    ReadDouble(file, file_decay);
    file >> file_scale >> periods;
    if (file_decay != decay || file_scale != scale || periods != m_rows.size()) throw std::runtime_error("Invalid cohort horizon");
    m_rows.assign(periods, std::vector<Cell>(num_buckets));
    for (auto& row : m_rows) for (auto& cell : row) {
        ReadDouble(file, cell.outcomes.success);
        ReadDouble(file, cell.outcomes.failure);
        ReadDouble(file, cell.fee_sum);
        for (auto& value : cell.outcomes.unknown) ReadDouble(file, value);
        if (cell.outcomes.unknown[0] != 0 || !std::isfinite(cell.outcomes.Total()) ||
            (cell.outcomes.Total() == 0 && cell.fee_sum != 0)) throw std::runtime_error("Invalid cohort outcomes");
    }
    uint32_t cohorts;
    file >> cohorts;
    if (cohorts > GetMaxConfirms()) throw std::runtime_error("Too many pending cohorts");
    for (uint32_t i{0}; i < cohorts; ++i) {
        unsigned int birth;
        uint32_t entries;
        file >> birth >> entries;
        if (birth > best_height || best_height - birth >= GetMaxConfirms() || entries == 0 || entries > num_buckets || m_cohorts.contains(birth)) throw std::runtime_error("Invalid pending cohort");
        auto& by_bucket = m_cohorts[birth];
        for (uint32_t j{0}; j < entries; ++j) {
            unsigned int bucket;
            Cohort cohort;
            file >> bucket >> cohort.count;
            for (auto& count : cohort.unknown) file >> count;
            ReadDouble(file, cohort.fee_sum);
            if (bucket >= num_buckets || by_bucket.contains(bucket) || cohort.count == 0 || cohort.unknown[0] != 0) throw std::runtime_error("Invalid pending cohort bucket");
            uint64_t remaining = cohort.count;
            for (const auto value : cohort.unknown) {
                if (value > remaining) throw std::runtime_error("Invalid pending outcome count");
                remaining -= value;
            }
            if (remaining != 0) throw std::runtime_error("Persisted active observation");
            by_bucket.emplace(bucket, cohort);
        }
    }
}
