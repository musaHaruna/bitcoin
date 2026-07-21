#define BOOST_TEST_MODULE blockstorage_inmemory_tests
#include <boost/test/unit_test.hpp>

#include "include/blockstorage/IBlockStorage.h"
#include "src/blockstorage/BlockStorageInMemory.h"
#include "uint256.h"
#include "utilstrencodings.h"

using namespace blockstorage;

static std::vector<uint8_t> make_fake_block(size_t sz)
{
    std::vector<uint8_t> v;
    v.resize(sz);
    for (size_t i = 0; i < sz; ++i) v[i] = static_cast<uint8_t>(i & 0xff);
    return v;
}

BOOST_AUTO_TEST_SUITE(blockstorage_tests)

BOOST_AUTO_TEST_CASE(inmemory_write_read_prune)
{
    InMemoryBlockStorage storage;
    BOOST_CHECK(storage.Open(""));

    uint256 h1 = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    uint256 h2 = uint256S("0000000000000000000000000000000000000000000000000000000000000002");
    uint256 h3 = uint256S("0000000000000000000000000000000000000000000000000000000000000003");

    auto b1 = make_fake_block(100);
    auto b2 = make_fake_block(200);
    auto b3 = make_fake_block(300);

    auto p1 = storage.WriteBlock(h1, b1, 1);
    BOOST_CHECK(p1.has_value());
    auto p2 = storage.WriteBlock(h2, b2, 2);
    BOOST_CHECK(p2.has_value());
    auto p3 = storage.WriteBlock(h3, b3, 3);
    BOOST_CHECK(p3.has_value());

    BOOST_CHECK_EQUAL(storage.CurrentOnDiskSizeBytes(), size_t(600));

    // Read back and validate
    auto r2 = storage.ReadBlockByHash(h2);
    BOOST_CHECK(r2.has_value());
    BOOST_CHECK_EQUAL(r2->raw.size(), b2.size());

    // Prune to target 350 -> must remove oldest blocks (h1 + maybe h2) to go <=350
    bool ok = storage.PruneToTargetBytes(350);
    BOOST_CHECK(ok);
    BOOST_CHECK(storage.CurrentOnDiskSizeBytes() <= 350);

    // Ensure h3 still present (newest)
    BOOST_CHECK(storage.HasBlock(h3));
    // Oldest h1 likely removed
    // h1 may be removed; ensure RemoveBlockByHash works idempotently.
    storage.RemoveBlockByHash(h1);
}

BOOST_AUTO_TEST_SUITE_END()
