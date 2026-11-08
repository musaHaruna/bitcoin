#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Require txindex iterator corruption to be reported as a database error.

This optional extended test uses plyvel and POSIX process signals. It always
expects the corrected behavior, so it fails before the FindTx status check.
"""

import os
import signal

try:
    import plyvel  # type: ignore[import]
except ImportError:
    plyvel = None

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error


def tables(path):
    return set(path.glob("*.ldb")) | set(path.glob("*.sst"))


def read_varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise AssertionError("Invalid LevelDB block-handle varint")


def isolate_transaction_table(path):
    # Called with the node stopped. Keep the original DB and preserve every
    # key/value in the replacement, separating metadata from the sole 'x' row.
    with plyvel.DB(str(path), create_if_missing=False) as db:
        with db.iterator(verify_checksums=True) as iterator:
            records = list(iterator)
    transactions = [(key, value) for key, value in records if key.startswith(b"x")]
    assert_equal(len(transactions), 1)
    assert all(key < b"x" for key, _ in records if not key.startswith(b"x"))
    path.rename(path.with_name("txindex-original"))

    with plyvel.DB(str(path), create_if_missing=True, error_if_exists=True,
                   compression=None) as db:
        with db.write_batch(sync=True) as batch:
            for key, value in records:
                if not key.startswith(b"x"):
                    batch.put(key, value)
        db.compact_range()
        metadata_tables = tables(path)
        assert metadata_tables
        with db.write_batch(sync=True) as batch:
            for key, value in transactions:
                batch.put(key, value)
        db.compact_range(start=b"x", stop=b"y")
        transaction_tables = tables(path) - metadata_tables
        assert metadata_tables <= tables(path)
        assert_equal(len(transaction_tables), 1)
        with db.iterator(verify_checksums=True) as iterator:
            assert_equal(list(iterator), records)

    table = transaction_tables.pop()
    data = table.read_bytes()
    assert len(data) >= 48
    assert_equal(data[-8:], bytes.fromhex("57fb808b247547db"))
    # The 48-byte SST footer starts with the metaindex's block handle. With
    # one entry, no compression and no filter, the preceding byte is the last
    # byte of the sole data block's CRC. Leave its payload/index/footer intact.
    meta_offset, _ = read_varint(data, len(data) - 48)
    assert 5 < meta_offset < len(data) - 48
    assert_equal(data[meta_offset - 5], 0)  # Uncompressed data block.
    assert transactions[0][0] in data[:meta_offset - 5]
    return table, meta_offset - 1, data[meta_offset - 1:meta_offset]


def write_byte(node, path, offset, value):
    # Only pause this test's process, and always resume it. Keep the mapped
    # file's length unchanged. This intentionally injects a storage fault.
    node.process.send_signal(signal.SIGSTOP)
    try:
        with path.open("r+b") as file:
            file.seek(offset)
            file.write(value)
            file.flush()
            os.fsync(file.fileno())
    finally:
        node.process.send_signal(signal.SIGCONT)


class TxIndexIteratorErrorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.bind_to_localhost_only = False
        self.extra_args = [["-txindex=1", "-networkactive=0", "-listen=0"]]

    def skip_test_if_missing_module(self):
        if os.name != "posix":
            raise SkipTest("This reproduction requires POSIX process signals")
        if plyvel is None:
            raise SkipTest("plyvel not available (pip install plyvel)")

    def run_test(self):
        node = self.nodes[0]
        descriptor = node.getdescriptorinfo("raw(51)")["descriptor"]
        blockhash = self.generatetodescriptor(node, 1, descriptor)[0]
        txid = node.getblock(blockhash)["tx"][0]
        self.wait_for_index_sync()
        original_tx = node.getrawtransaction(txid)
        missing = "No such mempool or blockchain transaction"
        assert_raises_rpc_error(-5, missing, node.getrawtransaction, "00" * 32)
        self.log.info("Healthy database: transaction found; unknown transaction gives RPC -5")

        self.stop_node(0)
        table, offset, original = isolate_transaction_table(node.chain_path / "indexes" / "txindex")
        self.start_node(0)
        self.wait_for_index_sync()
        assert_equal(node.getrawtransaction(txid), original_tx)
        self.log.info("Repacked database: same contents; healthy lookup still succeeds")

        try:
            write_byte(node, table, offset, bytes([original[0] ^ 1]))
            self.log.info("Flipped one data-block checksum byte in %s", table.name)
            assert_raises_rpc_error(-1, "Corruption: block checksum mismatch", node.getrawtransaction, txid)
            self.log.info("Damaged database: verified RPC -1 (Corruption: block checksum mismatch)")
            assert_equal(node.getblockcount(), 1)
        finally:
            write_byte(node, table, offset, original)

        assert_equal(node.getrawtransaction(txid), original_tx)
        assert_raises_rpc_error(-5, missing, node.getrawtransaction, "00" * 32)
        self.log.info("Restored database: transaction found again; unknown transaction still gives RPC -5")
        self.log.info("Iterator error reported; node remained responsive")


if __name__ == "__main__":
    TxIndexIteratorErrorTest(__file__).main()
