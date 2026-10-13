// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <script/solver.h>
#include <primitives/block.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

using kernel::CBlockFileInfo;
using node::STORAGE_HEADER_BYTES;
using node::BlockManager;
using node::KernelNotifications;
using node::MAX_BLOCKFILE_SIZE;

// use BasicTestingSetup here for the data directory configuration, setup, and cleanup
BOOST_FIXTURE_TEST_SUITE(blockmanager_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(blockmanager_find_block_pos)
{
    const auto params {CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};
    // simulate adding a genesis block normally
    LOCK(::cs_main);
    BOOST_CHECK_EQUAL(blockman.WriteBlock(params->GenesisBlock(), 0).nPos, STORAGE_HEADER_BYTES);
    // simulate what happens during reindex
    // simulate a well-formed genesis block being found at offset 8 in the blk00000.dat file
    // the block is found at offset 8 because there is an 8 byte serialization header
    // consisting of 4 magic bytes + 4 length bytes before each block in a well-formed blk file.
    const FlatFilePos pos{0, STORAGE_HEADER_BYTES};
    blockman.UpdateBlockInfo(params->GenesisBlock(), 0, pos);
    // now simulate what happens after reindex for the first new block processed
    // the actual block contents don't matter, just that it's a block.
    // verify that the write position is at offset 0x12d.
    // this is a check to make sure that https://github.com/bitcoin/bitcoin/issues/21379 does not recur
    // 8 bytes (for serialization header) + 285 (for serialized genesis block) = 293
    // add another 8 bytes for the second block's serialization header and we get 293 + 8 = 301
    FlatFilePos actual{blockman.WriteBlock(params->GenesisBlock(), 1)};
    BOOST_CHECK_EQUAL(actual.nPos, STORAGE_HEADER_BYTES + ::GetSerializeSize(TX_WITH_WITNESS(params->GenesisBlock())) + STORAGE_HEADER_BYTES);
}

BOOST_FIXTURE_TEST_CASE(blockmanager_scan_unlink_already_pruned_files, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    auto& chainman{*Assert(m_node.chainman)};
    auto& blockman{chainman.m_blockman};
    const CBlockIndex* old_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    WITH_LOCK(chainman.GetMutex(), blockman.GetBlockFileInfo(old_tip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    // Prune the older block file, but don't unlink it
    int file_number;
    {
        LOCK(chainman.GetMutex());
        file_number = old_tip->GetBlockPos().nFile;
        blockman.PruneOneBlockFile(file_number);
    }

    const FlatFilePos pos(file_number, 0);

    // Check that the file is not unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // if m_have_pruned is not yet set
    WITH_LOCK(chainman.GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(!blockman.OpenBlockFile(pos, true).IsNull());

    // Check that the file is unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // once m_have_pruned is set
    blockman.m_have_pruned = true;
    WITH_LOCK(chainman.GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(blockman.OpenBlockFile(pos, true).IsNull());

    // Check that calling with already pruned files doesn't cause an error
    WITH_LOCK(chainman.GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());

    // Check that the new tip file has not been removed
    const CBlockIndex* new_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    BOOST_CHECK_NE(old_tip, new_tip);
    const int new_file_number{WITH_LOCK(chainman.GetMutex(), return new_tip->GetBlockPos().nFile)};
    const FlatFilePos new_pos(new_file_number, 0);
    BOOST_CHECK(!blockman.OpenBlockFile(new_pos, true).IsNull());
}

BOOST_FIXTURE_TEST_CASE(blockmanager_block_data_availability, TestChain100Setup)
{
    // The goal of the function is to return the first not pruned block in the range [upper_block, lower_block].
    LOCK(::cs_main);
    auto& chainman = m_node.chainman;
    auto& blockman = chainman->m_blockman;
    const CBlockIndex& tip = *chainman->ActiveTip();

    // Function to prune all blocks from 'last_pruned_block' down to the genesis block
    const auto& func_prune_blocks = [&](CBlockIndex* last_pruned_block)
    {
        LOCK(::cs_main);
        CBlockIndex* it = last_pruned_block;
        while (it != nullptr && it->nStatus & BLOCK_HAVE_DATA) {
            it->nStatus &= ~BLOCK_HAVE_DATA;
            it = it->pprev;
        }
    };

    // 1) Return genesis block when all blocks are available
    BOOST_CHECK_EQUAL(&blockman.GetFirstBlock(tip, BLOCK_HAVE_DATA), chainman->ActiveChain()[0]);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *chainman->ActiveChain()[0]));

    // 2) Check lower_block when all blocks are available
    CBlockIndex* lower_block = chainman->ActiveChain()[tip.nHeight / 2];
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *lower_block));

    // Ensure we don't fail due to the expected absence of undo data in the genesis block
    CBlockIndex* upper_block = chainman->ActiveChain()[2];
    CBlockIndex* genesis = chainman->ActiveChain()[0];
    BOOST_CHECK(blockman.CheckBlockDataAvailability(*upper_block, *genesis, BlockStatus{BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO}));
    // Ensure we detect absence of undo data in the first block
    chainman->ActiveChain()[1]->nStatus &= ~BLOCK_HAVE_UNDO;
    BOOST_CHECK(!blockman.CheckBlockDataAvailability(tip, *genesis, BlockStatus{BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO}));

    // Prune half of the blocks
    int height_to_prune = tip.nHeight / 2;
    CBlockIndex* first_available_block = chainman->ActiveChain()[height_to_prune + 1];
    CBlockIndex* last_pruned_block = first_available_block->pprev;
    func_prune_blocks(last_pruned_block);

    // 3) The last block not pruned is in-between upper-block and the genesis block
    BOOST_CHECK_EQUAL(&blockman.GetFirstBlock(tip, BLOCK_HAVE_DATA), first_available_block);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *first_available_block));
    BOOST_CHECK(!blockman.CheckBlockDataAvailability(tip, *last_pruned_block));

    // Simulate that the first available block is missing undo data and
    // detect this by using a status mask.
    first_available_block->nStatus &= ~BLOCK_HAVE_UNDO;
    BOOST_CHECK(!blockman.CheckBlockDataAvailability(tip, *first_available_block, BlockStatus{BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO}));
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *first_available_block, BlockStatus{BLOCK_HAVE_DATA}));
}

BOOST_FIXTURE_TEST_CASE(blockmanager_block_data_part, TestChain100Setup)
{
    LOCK(::cs_main);
    auto& chainman{m_node.chainman};
    auto& blockman{chainman->m_blockman};
    const CBlockIndex& tip{*chainman->ActiveTip()};
    const FlatFilePos tip_block_pos{tip.GetBlockPos()};

    auto block{blockman.ReadRawBlock(tip_block_pos)};
    BOOST_REQUIRE(block);
    BOOST_REQUIRE_GE(block->size(), 200);

    const auto expect_part{[&](size_t offset, size_t size) {
        auto res{blockman.ReadRawBlock(tip_block_pos, std::pair{offset, size})};
        BOOST_CHECK(res);
        const auto& part{res.value()};
        BOOST_CHECK_EQUAL_COLLECTIONS(part.begin(), part.end(), block->begin() + offset, block->begin() + offset + size);
    }};

    expect_part(0, 20);
    expect_part(0, block->size() - 1);
    expect_part(0, block->size() - 10);
    expect_part(0, block->size());
    expect_part(1, block->size() - 1);
    expect_part(10, 20);
    expect_part(block->size() - 1, 1);
}

BOOST_FIXTURE_TEST_CASE(blockmanager_block_data_part_error, TestChain100Setup)
{
    LOCK(::cs_main);
    auto& chainman{m_node.chainman};
    auto& blockman{chainman->m_blockman};
    const CBlockIndex& tip{*chainman->ActiveTip()};
    const FlatFilePos tip_block_pos{tip.GetBlockPos()};

    auto block{blockman.ReadRawBlock(tip_block_pos)};
    BOOST_REQUIRE(block);
    BOOST_REQUIRE_GE(block->size(), 200);

    const auto expect_part_error{[&](size_t offset, size_t size) {
        auto res{blockman.ReadRawBlock(tip_block_pos, std::pair{offset, size})};
        BOOST_CHECK(!res);
        BOOST_CHECK_EQUAL(res.error(), node::ReadRawError::BadPartRange);
    }};

    expect_part_error(0, 0);
    expect_part_error(0, block->size() + 1);
    expect_part_error(0, std::numeric_limits<size_t>::max());
    expect_part_error(1, block->size());
    expect_part_error(2, block->size() - 1);
    expect_part_error(block->size() - 1, 2);
    expect_part_error(block->size() - 2, 3);
    expect_part_error(block->size() + 1, 0);
    expect_part_error(block->size() + 1, 1);
    expect_part_error(block->size() + 2, 2);
    expect_part_error(block->size(), 0);
    expect_part_error(block->size(), 1);
    expect_part_error(std::numeric_limits<size_t>::max(), 1);
    expect_part_error(std::numeric_limits<size_t>::max(), std::numeric_limits<size_t>::max());
}

BOOST_FIXTURE_TEST_CASE(blockmanager_readblock_hash_mismatch, TestingSetup)
{
    CBlockIndex index;
    {
        LOCK(cs_main);
        const auto tip{m_node.chainman->ActiveTip()};
        index.nStatus = tip->nStatus;
        index.nDataPos = tip->nDataPos;
        index.phashBlock = &uint256::ONE; // mismatched block hash
    }

    ASSERT_DEBUG_LOG("GetHash() doesn't match index");
    CBlock block;
    BOOST_CHECK(!m_node.chainman->m_blockman.ReadBlock(block, index));
}

BOOST_AUTO_TEST_CASE(blockmanager_flush_block_file)
{
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    node::BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    // Test blocks with no transactions, not even a coinbase
    CBlock block1;
    block1.nVersion = 1;
    CBlock block2;
    block2.nVersion = 2;
    CBlock block3;
    block3.nVersion = 3;

    // They are 80 bytes header + 1 byte 0x00 for vtx length
    constexpr int TEST_BLOCK_SIZE{81};

    // Blockstore is empty
    LOCK(::cs_main);
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), 0);

    // Write the first block to a new location.
    FlatFilePos pos1{blockman.WriteBlock(block1, /*nHeight=*/1)};

    // Write second block
    FlatFilePos pos2{blockman.WriteBlock(block2, /*nHeight=*/2)};

    // Two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (TEST_BLOCK_SIZE + STORAGE_HEADER_BYTES) * 2);

    // First two blocks are written as expected
    // Errors are expected because block data is junk, thrown AFTER successful read
    CBlock read_block;
    BOOST_CHECK_EQUAL(read_block.nVersion, 0);
    {
        ASSERT_DEBUG_LOG("Errors in block header");
        BOOST_CHECK(!blockman.ReadBlock(read_block, pos1, {}));
        BOOST_CHECK_EQUAL(read_block.nVersion, 1);
    }
    {
        ASSERT_DEBUG_LOG("Errors in block header");
        BOOST_CHECK(!blockman.ReadBlock(read_block, pos2, {}));
        BOOST_CHECK_EQUAL(read_block.nVersion, 2);
    }

    // During reindex, the flat file block storage will not be written to.
    // UpdateBlockInfo will, however, update the blockfile metadata.
    // Verify this behavior by attempting (and failing) to write block 3 data
    // to block 2 location.
    CBlockFileInfo* block_data = blockman.GetBlockFileInfo(0);
    BOOST_CHECK_EQUAL(block_data->nBlocks, 2);
    blockman.UpdateBlockInfo(block3, /*nHeight=*/3, /*pos=*/pos2);
    // Metadata is updated...
    BOOST_CHECK_EQUAL(block_data->nBlocks, 3);
    // ...but there are still only two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (TEST_BLOCK_SIZE + STORAGE_HEADER_BYTES) * 2);

    // Block 2 was not overwritten:
    BOOST_CHECK(!blockman.ReadBlock(read_block, pos2, {}));
    BOOST_CHECK_EQUAL(read_block.nVersion, 2);
}

BOOST_AUTO_TEST_CASE(blockmanager_manual_prune_storage_flush)
{
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .prune_target = BlockManager::PRUNE_TARGET_MANUAL,
        .fast_prune = true,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
            .memory_only = true,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    CBlock old_block;
    old_block.nVersion = 1;
    CBlock current_block;
    current_block.nVersion = 2;

    LOCK(::cs_main);
    const FlatFilePos old_pos{blockman.WriteBlock(old_block, /*nHeight=*/10)};
    CBlockIndex* old_index{blockman.InsertBlockIndex(old_block.GetHash())};
    old_index->nHeight = 10;
    old_index->nFile = old_pos.nFile;
    old_index->nDataPos = old_pos.nPos;
    old_index->nUndoPos = 1;
    old_index->nStatus |= BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;

    // Finalize the old file and force subsequent data into a new file.
    blockman.GetBlockFileInfo(old_pos.nFile)->nSize = 0x10000;
    const uint64_t old_file_bytes{
        blockman.GetBlockFileInfo(old_pos.nFile)->nSize +
        blockman.GetBlockFileInfo(old_pos.nFile)->nUndoSize};
    const FlatFilePos current_pos{blockman.WriteBlock(current_block, /*nHeight=*/20)};
    BOOST_REQUIRE_NE(old_pos.nFile, current_pos.nFile);

    auto result{blockman.FlushBlockStorage({
        .prune = node::BlockPruneOptions{
            .chain_tip_height = 400,
            .first_prunable_height = 0,
            .last_prunable_height = 10,
        },
        .manual_prune_height = 10,
    })};
    BOOST_REQUIRE(result);
    BOOST_CHECK(result->wrote_block_index);
    BOOST_CHECK(result->Pruned());
    BOOST_CHECK_EQUAL(result->pruned_files.size(), 1U);
    BOOST_CHECK(result->pruned_files.contains(old_pos.nFile));
    BOOST_CHECK_EQUAL(result->pruned_bytes, old_file_bytes);

    // The storage operation persisted unavailable metadata before unlinking.
    BOOST_CHECK(!(old_index->nStatus & BLOCK_HAVE_DATA));
    BOOST_CHECK(!(old_index->nStatus & BLOCK_HAVE_UNDO));
    BOOST_CHECK_EQUAL(old_index->nFile, 0);
    BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(old_pos.nFile)->nSize, 0U);
    bool pruned_flag{false};
    BOOST_CHECK(blockman.m_block_tree_db->ReadFlag("prunedblockfiles", pruned_flag));
    BOOST_CHECK(pruned_flag);
    BOOST_CHECK(blockman.m_have_pruned);
    BOOST_CHECK(blockman.OpenBlockFile(FlatFilePos{old_pos.nFile, 0}, true).IsNull());
    BOOST_CHECK(!blockman.OpenBlockFile(FlatFilePos{current_pos.nFile, 0}, true).IsNull());
}

BOOST_AUTO_TEST_CASE(blockmanager_prune_flush_failure)
{
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options options{
        .chainparams = Params(),
        .prune_target = BlockManager::PRUNE_TARGET_MANUAL,
        .fast_prune = true,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
            .memory_only = true,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), options};
    LOCK(::cs_main);
    CBlock block;
    block.nVersion = 1;
    const auto old_pos{blockman.WriteBlock(block, 10)};
    blockman.GetBlockFileInfo(old_pos.nFile)->nSize = 0x10000;
    block.nVersion = 2;
    const auto current_pos{blockman.WriteBlock(block, 20)};
    BOOST_REQUIRE_NE(old_pos.nFile, current_pos.nFile);
    const node::BlockPruneOptions prune{
        .chain_tip_height = 400,
        .first_prunable_height = 0,
        .last_prunable_height = 10,
    };
    BOOST_REQUIRE(blockman.FlushBlockStorage({.prune = prune, .write_block_index = true}));
    CBlockFileInfo persisted_before;
    BOOST_REQUIRE(blockman.m_block_tree_db->ReadBlockFileInfo(old_pos.nFile, persisted_before));
    BOOST_REQUIRE_GT(persisted_before.nSize, 0U);

    // Opening the current file fails after the old file has been selected.
    const auto current_path{blockman.GetBlockPosFilename(current_pos)};
    BOOST_REQUIRE(fs::remove(current_path));
    BOOST_REQUIRE(fs::create_directory(current_path));
    ASSERT_DEBUG_LOG("Flushing block file to disk failed");
    auto result{blockman.FlushBlockStorage({.prune = prune, .manual_prune_height = 10})};
    BOOST_REQUIRE(!result);
    BOOST_CHECK(result.error() == node::BlockStorageFlushError::FLUSH_FAILED);
    // Earlier in-memory mutations are not rolled back, but the block-index
    // batch and physical unlink must not run after the failed file flush.
    BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(old_pos.nFile)->nSize, 0U);
    CBlockFileInfo persisted_after;
    BOOST_REQUIRE(blockman.m_block_tree_db->ReadBlockFileInfo(old_pos.nFile, persisted_after));
    BOOST_CHECK_EQUAL(persisted_after.nSize, persisted_before.nSize);
    BOOST_CHECK(!blockman.OpenBlockFile(FlatFilePos{old_pos.nFile, 0}, true).IsNull());
}

BOOST_AUTO_TEST_CASE(blockmanager_manual_prune_invalid_range_noop)
{
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .prune_target = BlockManager::PRUNE_TARGET_MANUAL,
        .fast_prune = true,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
            .memory_only = true,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    CBlock old_block;
    old_block.nVersion = 1;
    CBlock current_block;
    current_block.nVersion = 2;

    LOCK(::cs_main);
    const FlatFilePos old_pos{blockman.WriteBlock(old_block, /*nHeight=*/10)};
    CBlockIndex* old_index{blockman.InsertBlockIndex(old_block.GetHash())};
    old_index->nHeight = 10;
    old_index->nFile = old_pos.nFile;
    old_index->nDataPos = old_pos.nPos;
    old_index->nStatus |= BLOCK_HAVE_DATA;
    blockman.GetBlockFileInfo(old_pos.nFile)->nSize = 0x10000;
    const FlatFilePos current_pos{blockman.WriteBlock(current_block, /*nHeight=*/20)};
    BOOST_REQUIRE_NE(old_pos.nFile, current_pos.nFile);

    for (const node::BlockPruneOptions& invalid_prune : {
             node::BlockPruneOptions{
                 .chain_tip_height = -1,
                 .first_prunable_height = 0,
                 .last_prunable_height = 10,
             },
             node::BlockPruneOptions{
                 .chain_tip_height = 400,
                 .first_prunable_height = -1,
                 .last_prunable_height = 10,
             },
             node::BlockPruneOptions{
                 .chain_tip_height = 400,
                 .first_prunable_height = 11,
                 .last_prunable_height = 10,
             },
         }) {
        auto result{blockman.FlushBlockStorage({
            .prune = invalid_prune,
            .manual_prune_height = 10,
        })};
        BOOST_REQUIRE(result);
        BOOST_CHECK(!result->wrote_block_index);
        BOOST_CHECK(!result->Pruned());
        BOOST_CHECK_EQUAL(result->pruned_bytes, 0U);
    }

    BOOST_CHECK(old_index->nStatus & BLOCK_HAVE_DATA);
    BOOST_CHECK_EQUAL(old_index->nFile, old_pos.nFile);
    BOOST_CHECK(!blockman.m_have_pruned);
    BOOST_CHECK(!blockman.OpenBlockFile(FlatFilePos{old_pos.nFile, 0}, true).IsNull());
    BOOST_CHECK(!blockman.OpenBlockFile(FlatFilePos{current_pos.nFile, 0}, true).IsNull());
}

BOOST_AUTO_TEST_CASE(blockmanager_request_prune)
{
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .prune_target = MIN_DISK_SPACE_FOR_BLOCK_FILES,
        .fast_prune = true,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
            .memory_only = true,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    CBlock old_block;
    old_block.nVersion = 1;
    CBlock current_block;
    current_block.nVersion = 2;

    LOCK(::cs_main);
    const FlatFilePos old_pos{blockman.WriteBlock(old_block, /*nHeight=*/10)};
    CBlockIndex* old_index{blockman.InsertBlockIndex(old_block.GetHash())};
    old_index->nHeight = 10;
    old_index->nFile = old_pos.nFile;
    old_index->nDataPos = old_pos.nPos;
    old_index->nStatus |= BLOCK_HAVE_DATA;
    blockman.GetBlockFileInfo(old_pos.nFile)->nSize = 0x10000;
    const FlatFilePos current_pos{blockman.WriteBlock(current_block, /*nHeight=*/20)};
    BOOST_REQUIRE_NE(old_pos.nFile, current_pos.nFile);

    const node::BlockStorageFlushRequest request{
        .prune = node::BlockPruneOptions{
            .chain_tip_height = 200000,
            .first_prunable_height = 0,
            .last_prunable_height = 10,
            .target_bytes = MIN_DISK_SPACE_FOR_BLOCK_FILES,
        },
    };

    // File allocation requested a pruning check. Consume it while usage is low.
    auto allocation_result{blockman.FlushBlockStorage(request)};
    BOOST_REQUIRE(allocation_result);
    BOOST_CHECK(!allocation_result->wrote_block_index);
    BOOST_CHECK(!allocation_result->Pruned());

    // Inflate only the file catalog entry, avoiding a large test file on disk.
    blockman.GetBlockFileInfo(old_pos.nFile)->nSize = MIN_DISK_SPACE_FOR_BLOCK_FILES;

    // Target pruning is demand-driven, so the same request is initially a no-op.
    auto idle_result{blockman.FlushBlockStorage(request)};
    BOOST_REQUIRE(idle_result);
    BOOST_CHECK(!idle_result->wrote_block_index);
    BOOST_CHECK(!idle_result->Pruned());
    BOOST_CHECK(old_index->nStatus & BLOCK_HAVE_DATA);

    blockman.RequestPrune();
    auto requested_result{blockman.FlushBlockStorage(request)};
    BOOST_REQUIRE(requested_result);
    BOOST_CHECK(requested_result->wrote_block_index);
    BOOST_CHECK(requested_result->Pruned());
    BOOST_CHECK(requested_result->pruned_files.contains(old_pos.nFile));
    BOOST_CHECK(!(old_index->nStatus & BLOCK_HAVE_DATA));
    BOOST_CHECK(blockman.OpenBlockFile(FlatFilePos{old_pos.nFile, 0}, true).IsNull());
    BOOST_CHECK(!blockman.OpenBlockFile(FlatFilePos{current_pos.nFile, 0}, true).IsNull());
}

BOOST_AUTO_TEST_CASE(blockmanager_precomputed_prune_limits)
{
    struct TestCase {
        const char* name;
        int first;
        int last;
        bool enabled;
        bool below_trigger;
        uint64_t extra_space;
        std::set<int> expected;
    };
    for (const auto& test : {
             TestCase{"disabled", 0, 30, false, false, 0, {}},
             TestCase{"headroom_does_not_trigger", 0, 30, true, true, 500_MiB, {}},
             TestCase{"exact_trigger", 0, 30, true, false, 0, {0}},
             TestCase{"headroom_selects_more", 0, 30, true, false, 150_MiB, {0, 1}},
             TestCase{"lower_bound", 20, 30, true, false, 0, {1}},
             TestCase{"inverted_range", 31, 30, true, false, 500_MiB, {}},
             TestCase{"negative_upper_bound", 0, -1, true, false, 500_MiB, {}},
         }) {
        BOOST_TEST_CONTEXT(test.name) {
            KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
            const BlockManager::Options options{
                .chainparams = Params(),
                .prune_target = MIN_DISK_SPACE_FOR_BLOCK_FILES,
                .fast_prune = true,
                .blocks_dir = m_args.GetBlocksDirPath() / test.name,
                .notifications = notifications,
                .block_tree_db_params = DBParams{
                    .path = m_args.GetDataDirNet() / test.name / "index",
                    .cache_bytes = 0,
                    .memory_only = true,
                },
            };
            fs::create_directories(options.blocks_dir);
            BlockManager blockman{*Assert(m_node.shutdown_signal), options};
            LOCK(::cs_main);
            CBlock block;
            for (int i = 0; i < 4; ++i) {
                block.nVersion = i + 1;
                const auto pos{blockman.WriteBlock(block, (i + 1) * 10)};
                BOOST_REQUIRE_EQUAL(pos.nFile, i);
                if (i < 3) blockman.GetBlockFileInfo(i)->nSize = 0x10000;
            }
            // Inflate metadata only, after forcing three completed small files.
            for (int i = 0; i < 3; ++i) blockman.GetBlockFileInfo(i)->nSize = 100_MiB;
            const uint64_t trigger{blockman.CalculateCurrentUsage() +
                                   node::BLOCKFILE_CHUNK_SIZE + node::UNDOFILE_CHUNK_SIZE};
            auto result{blockman.FlushBlockStorage({
                .prune = node::BlockPruneOptions{
                    // Storage must honor supplied policy even below mainnet's
                    // PruneAfterHeight and below its configured target.
                    .chain_tip_height = 400,
                    .first_prunable_height = test.first,
                    .last_prunable_height = test.last,
                    .target_bytes = test.enabled ? trigger + test.below_trigger : 0,
                    .extra_space = test.extra_space,
                },
            })};
            BOOST_REQUIRE(result);
            BOOST_CHECK(result->pruned_files == test.expected);
            BOOST_CHECK_EQUAL(result->wrote_block_index, !test.expected.empty());
            BOOST_CHECK_EQUAL(result->pruned_bytes, test.expected.size() * 100_MiB);
            for (int i = 0; i < 4; ++i) {
                BOOST_CHECK_EQUAL(blockman.OpenBlockFile(FlatFilePos{i, 0}, true).IsNull(), test.expected.contains(i));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(blockmanager_prune_lock_rewind)
{
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .prune_target = BlockManager::PRUNE_TARGET_MANUAL,
        .fast_prune = true,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
            .memory_only = true,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    CBlock block;
    LOCK(::cs_main);
    block.nVersion = 1;
    const FlatFilePos first_pos{blockman.WriteBlock(block, /*nHeight=*/10)};
    blockman.GetBlockFileInfo(first_pos.nFile)->nSize = 0x10000;
    block.nVersion = 2;
    const FlatFilePos second_pos{blockman.WriteBlock(block, /*nHeight=*/20)};
    blockman.GetBlockFileInfo(second_pos.nFile)->nSize = 0x10000;
    block.nVersion = 3;
    const FlatFilePos current_pos{blockman.WriteBlock(block, /*nHeight=*/30)};
    BOOST_REQUIRE_NE(first_pos.nFile, second_pos.nFile);
    BOOST_REQUIRE_NE(second_pos.nFile, current_pos.nFile);

    const node::BlockPruneOptions prune{
        .chain_tip_height = 400,
        .first_prunable_height = 0,
        .last_prunable_height = 20,
    };

    // A reorg rewinds the lock from 100 to 20. Its internal buffer then keeps
    // both completed files, whose first heights are 10 and 20.
    blockman.UpdatePruneLock("test_lock", node::PruneLockInfo{.height_first = 100});
    blockman.RewindPruneLocks(/*max_height_first=*/20);
    auto locked_result{blockman.FlushBlockStorage({
        .prune = prune,
        .manual_prune_height = 20,
    })};
    BOOST_REQUIRE(locked_result);
    BOOST_CHECK(!locked_result->wrote_block_index);
    BOOST_CHECK(!locked_result->Pruned());
    BOOST_CHECK(!blockman.OpenBlockFile(FlatFilePos{first_pos.nFile, 0}, true).IsNull());
    BOOST_CHECK(!blockman.OpenBlockFile(FlatFilePos{second_pos.nFile, 0}, true).IsNull());

    BOOST_REQUIRE(blockman.DeletePruneLock("test_lock"));
    auto unlocked_result{blockman.FlushBlockStorage({
        .prune = prune,
        .manual_prune_height = 20,
    })};
    BOOST_REQUIRE(unlocked_result);
    BOOST_CHECK(unlocked_result->wrote_block_index);
    BOOST_CHECK(unlocked_result->Pruned());
    BOOST_CHECK_EQUAL(unlocked_result->pruned_files.size(), 2U);
    BOOST_CHECK(unlocked_result->pruned_files.contains(first_pos.nFile));
    BOOST_CHECK(unlocked_result->pruned_files.contains(second_pos.nFile));
    BOOST_CHECK(blockman.OpenBlockFile(FlatFilePos{first_pos.nFile, 0}, true).IsNull());
    BOOST_CHECK(blockman.OpenBlockFile(FlatFilePos{second_pos.nFile, 0}, true).IsNull());
    BOOST_CHECK(!blockman.OpenBlockFile(FlatFilePos{current_pos.nFile, 0}, true).IsNull());
}

BOOST_FIXTURE_TEST_CASE(prune_lock_update_and_delete, TestingSetup)
{
    LOCK(::cs_main);
    auto& chainman{*Assert(m_node.chainman)};
    auto& blockman{chainman.m_blockman};

    // Create a prune lock
    blockman.UpdatePruneLock("test_lock", node::PruneLockInfo{.height_first = 100});

    // Update it to a new height
    blockman.UpdatePruneLock("test_lock", node::PruneLockInfo{.height_first = 200});

    // Delete existing prune lock
    BOOST_CHECK(blockman.DeletePruneLock("test_lock"));

    // Verify deletion worked by trying to delete the same lock again
    BOOST_CHECK(!blockman.DeletePruneLock("test_lock"));

    // Deleting a non-existent lock returns false
    BOOST_CHECK(!blockman.DeletePruneLock("nonexistent"));
}

BOOST_AUTO_TEST_SUITE_END()
