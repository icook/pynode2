#
# chain_db.py - Bitcoin blockchain database
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import struct
import string
import cStringIO
import leveldb
import io
import os
import logging
import bitcoin.core.serialize as serialize
import bitcoin.core as core

from bitcoin.messages import msg_block
from bitcoin.core.scripteval import VerifySignature


def tx_blk_cmp(a, b):
    if a.dFeePerKB != b.dFeePerKB:
        return int(a.dFeePerKB - b.dFeePerKB)
    return int(a.dPriority - b.dPriority)


def block_value(height, fees):
    subsidy = 50 * core.COIN
    subsidy >>= (height / 210000)
    return subsidy + fees


class Cache(object):

    def __init__(self, max=1000):
        self.d = {}
        self.l = []
        self.max = max

    def put(self, k, v):
        self.d[k] = v
        self.l.append(k)

        while (len(self.l) > self.max):
            kdel = self.l[0]
            del self.l[0]
            del self.d[kdel]

    def get(self, k):
        try:
            return self.d[k]
        except:
            return None

    def exists(self, k):
        return k in self.d


class TxIdx(object):

    def __init__(self, blkhash="\0" * 32, spentmask=0L):
        self.blkhash = blkhash
        self.spentmask = spentmask


class BlkMeta(object):

    def __init__(self):
        self.height = -1
        self.work = 0L

    def deserialize(self, s):
        l = s.split()
        if len(l) < 2:
            raise RuntimeError
        self.height = int(l[0])
        self.work = long(l[1], 16)

    def serialize(self):
        r = str(self.height) + ' ' + hex(self.work)
        return r

    def __repr__(self):
        return "BlkMeta(height %d, work %x)" % (self.height, self.work)


class HeightIdx(object):

    def __init__(self):
        self.blocks = []

    def deserialize(self, s):
        self.blocks = []
        l = s.split()
        for hashstr in l:
            hash = long(hashstr, 16)
            self.blocks.append(hash)

    def serialize(self):
        l = []
        for blkhash in self.blocks:
            l.append(blkhash.encode('hex'))
        return ' '.join(l)

    def __repr__(self):
        return "HeightIdx(blocks=%s)" % (self.serialize(),)


class ChainDb(object):
    """ Manages a blockchain database. This implementation uses leveldb to
    store index information and a raw blocks.dat like file to store complete
    network blocks as recieved from network. """

    def __init__(self, manager):
        self.log = logging.getLogger(self.__class__.__name__)
        self.settings = manager.settings
        self.mempool = manager.mempool
        self.params = manager.params

        self.blk_cache = Cache(500)
        self.orphans = {}
        self.orphan_deps = {}

        # LevelDB to hold:
        #    tx:*      transaction outputs
        #    misc:*    state
        #    height:*  list of blocks at height h
        #    blkmeta:* block metadata
        #    blocks:*  block seek point in stream
        dat = self.settings['datadir'] + '/blocks.dat'
        self.blk_write = io.BufferedWriter(io.FileIO(dat, 'ab'))
        self.blk_read = io.BufferedReader(io.FileIO(dat, 'rb'))
        self.db = leveldb.LevelDB(self.settings['datadir'] + '/leveldb')

        try:
            self.db.Get('misc:height')
        except KeyError:
            self.log.info("Initializing empty blockchain database")
            batch = leveldb.WriteBatch()
            batch.Put('misc:height', str(-1))
            batch.Put('misc:msg_start', self.params.MESSAGE_START)
            batch.Put('misc:tophash', hex(0L))
            batch.Put('misc:total_work', hex(0L))
            self.db.Write(batch)

        try:
            start = self.db.Get('misc:msg_start')
            if start != self.params.MESSAGE_START:
                raise KeyError
        except KeyError:
            self.log.info(
                "Database magic number mismatch. Data corruption or incorrect network?")
            raise RuntimeError

    def puttxidx(self, txhash, txidx, batch=None):
        """ Puts a serialized TxIdx object into the datastore. """
        try:
            self.db.Get('tx:' + txhash)
            old_txidx = self.gettxidx(txhash)
            self.log.warn("overwriting duplicate TX {}, height {}, oldblk {}, oldspent {}, newblk {}".format(
                txhash.encode('hex'), self.getheight(), old_txidx.blkhash.encode('hex'), old_txidx.spentmask, txidx.blkhash.encode('hex')))
        except KeyError:
            pass
        batch = self.db if batch is not None else batch
        batch.Put('tx:' + txhash,
                  txidx.blkhash.encode('hex') + ' ' + hex(txidx.spentmask))

        return True

    def gettxidx(self, txhash):
        """ Retrieves a serialized TxIdx object from the datastore. Returns a
        TxIdx object."""
        try:
            ser_value = self.db.Get('tx:' + txhash)
        except KeyError:
            return None

        pos = string.find(ser_value, ' ')

        txidx = TxIdx()
        txidx.blkhash = core.x(ser_value[:pos])
        txidx.spentmask = long(ser_value[pos + 1:], 16)

        return txidx

    def gettx(self, txhash):
        """ Looks up a raw transaction from a given transaction hash. Uses the
        stored TxIdx objects (key "tx:*") to find the associated blockhash.
        Block is then retrieved and deserialized in order to retrieve
        transaction. """
        txidx = self.gettxidx(txhash)
        if txidx is None:
            return None

        block = self.getblock(txidx.blkhash)
        for tx in block.vtx:
            if tx.GetHash() == txhash:
                return tx

        self.log.info("ERROR: Missing TX %064x in block %064x" %
                      (txhash, txidx.blkhash))
        return None

    def haveblock(self, blkhash, checkorphans=True):
        """ Determines if we know of a block. Checks cache, then datastore. """
        if self.blk_cache.exists(blkhash):
            return True
        if checkorphans and blkhash in self.orphans:
            return True
        try:
            self.db.Get('blocks:' + blkhash)
            return True
        except KeyError:
            return False

    def have_prevblock(self, block):
        """ Checks if we know of the block before the given block. """
        if (self.getheight() < 0 and
                block.GetHash() == self.params.GENESIS_BLOCK.GetHash()):
            return True
        if self.haveblock(block.hashPrevBlock, checkorphans=False):
            return True
        return False

    def getblock(self, blkhash):
        """ Loads a given block from the raw blocks.dat file. Uses the file
        position number that is stored in the datastore to seek to the right
        spot in the file. """
        block = self.blk_cache.get(blkhash)
        if block is not None:
            return block

        try:
            # Lookup the block index, seek in the file
            fpos = long(self.db.Get('blocks:' + blkhash))
            self.blk_read.seek(fpos)

            # read and decode "block" msg
            msg = msg_block.msg_deser(self.blk_read)
            if msg is None:
                return None
            block = msg.block
        except KeyError:
            return None

        self.blk_cache.put(blkhash, block)

        return block

    def spend_txout(self, txhash, n_idx, batch=None):
        """ Mark a transaction as "spent" in the datastore. """
        txidx = self.gettxidx(txhash)
        if txidx is None:
            return False

        txidx.spentmask |= (1L << n_idx)
        self.puttxidx(txhash, txidx, batch)

        return True

    def clear_txout(self, txhash, n_idx, batch=None):
        """ Mark a transaction as "unspent" in the datastore. """
        txidx = self.gettxidx(txhash)
        if txidx is None:
            return False

        txidx.spentmask &= ~(1L << n_idx)
        self.puttxidx(txhash, txidx, batch)

        return True

    def unique_outpts(self, block):
        outpts = {}
        txmap = {}
        for tx in block.vtx:
            if tx.is_coinbase:
                continue
            txmap[tx.GetHash()] = tx
            for txin in tx.vin:
                v = (txin.prevout.hash, txin.prevout.n)
                if v in outpts:
                    return None

                outpts[v] = False

        return (outpts, txmap)

    def txout_spent(self, txout):
        """ Return whether a transaction is marked as spent in the datastore.
        """
        txidx = self.gettxidx(txout.hash)
        if txidx is None:
            return None

        if txout.n > 100000:  # outpoint index sanity check
            return None

        if txidx.spentmask & (1L << txout.n):
            return True

        return False

    def spent_outpts(self, block):
        # list of outpoints this block wants to spend
        l = self.unique_outpts(block)
        if l is None:
            return None
        outpts = l[0]
        txmap = l[1]

        # pass 1: if outpoint in db, make sure it is unspent
        for k in outpts.iterkeys():
            outpt = core.COutPoint()
            outpt.hash = k[0]
            outpt.n = k[1]
            rc = self.txout_spent(outpt)
            if rc is None:
                continue
            if rc:
                return None

            outpts[k] = True  # skip in pass 2

        # pass 2: remaining outpoints must exist in this block
        for k, v in outpts.iteritems():
            if v:
                continue

            if k[0] not in txmap:  # validate txout hash
                return None

            tx = txmap[k[0]]  # validate txout index (n)
            if k[1] >= len(tx.vout):
                return None

            # outpts[k] = True  # not strictly necessary

        return outpts.keys()

    def tx_signed(self, tx, block, check_mempool):
        for i in xrange(len(tx.vin)):
            txin = tx.vin[i]

            # search database for dependent TX
            txfrom = self.gettx(txin.prevout.hash)

            # search block for dependent TX
            if txfrom is None and block is not None:
                for blktx in block.vtx:
                    if blktx.GetHash() == txin.prevout.hash:
                        txfrom = blktx
                        break

            # search mempool for dependent TX
            if txfrom is None and check_mempool:
                try:
                    txfrom = self.mempool.pool[txin.prevout.hash]
                except:
                    self.log.info("TX {}/{} no-dep {}".format(
                        tx.GetHash().encode('hex'), i,
                        txin.prevout.hash.encode('hex')))
                    return False
            if txfrom is None:
                self.log.info("TX {}/{} no-dep {}"
                              .format(tx.GetHash().encode('hex'), i,
                                      txin.prevout.hash.encode('hex')))
                return False

            if not VerifySignature(txfrom, tx, i):
                self.log.info("TX {}/{} sigfail".format(
                    tx.GetHash().encode('hex'), i))
                return False

        return True

    def tx_is_orphan(self, tx):
        try:
            core.CheckTransaction(tx)
        except core.CheckTransactionError:
            return None

        for txin in tx.vin:
            rc = self.txout_spent(txin.prevout)
            if rc is None:      # not found: orphan
                try:
                    txfrom = self.mempool.pool[txin.prevout.hash]
                except:
                    return True
                if txin.prevout.n >= len(txfrom.vout):
                    return None
            if rc is True:      # spent? strange
                return None

        return False

    def connect_block(self, ser_hash, block, blkmeta):
        # verify against checkpoint list
        try:
            chk_hash = self.params.CHECKPOINTS[blkmeta.height]
            if chk_hash != serialize.uint256_from_str(block.GetHash()):
                self.log.info(
                    "Block {} does not match checkpoint hash {}, height {}"
                    .format(block.GetHash().encode('hex'), chk_hash, blkmeta.height))
                return False
        except KeyError:
            pass

        # check TX connectivity
        outpts = self.spent_outpts(block)
        if outpts is None:
            self.log.info("Unconnectable block {}"
                          .format(block.GetHash().encode('hex')))
            return False

        # verify script signatures
        if ('nosig' not in self.settings and
            ('forcesig' in self.settings or
             blkmeta.height > max(self.params.CHECKPOINTS.keys()))):
            for tx in block.vtx:
                if tx.is_coinbase():
                    continue

                if not self.tx_signed(tx, block, False):
                    self.log.info(
                        "Invalid signature in block {}".format(block.GetHash().encode('hex')))
                    return False

        # update database pointers for best chain
        batch = leveldb.WriteBatch()
        batch.Put('misc:total_work', hex(blkmeta.work))
        batch.Put('misc:height', str(blkmeta.height))
        batch.Put('misc:tophash', ser_hash)

        self.log.info("height {}, block {}".format(
            blkmeta.height, block.GetHash().encode('hex')))

        # all TX's in block are connectable; index
        neverseen = 0
        for tx in block.vtx:
            if not self.mempool.remove(tx.GetHash()):
                neverseen += 1

            txidx = TxIdx(block.GetHash())
            if not self.puttxidx(tx.GetHash(), txidx, batch):
                self.log.info("TxIndex failed {}"
                              .format(tx.GetHash().encode('hex')))
                return False

        self.log.info("MemPool: blk.vtx.sz %d, neverseen %d, poolsz %d" % (
            len(block.vtx), neverseen, self.mempool.size()))

        # mark deps as spent
        for outpt in outpts:
            self.spend_txout(outpt[0], outpt[1], batch)

        self.db.Write(batch)
        return True

    def disconnect_block(self, block):
        prevmeta = BlkMeta()
        prevmeta.deserialize(self.db.Get('blkmeta:' + block.hashPrevBlock))

        tup = self.unique_outpts(block)
        if tup is None:
            return False

        outpts = tup[0]

        # mark deps as unspent
        batch = leveldb.WriteBatch()
        for outpt in outpts:
            self.clear_txout(outpt[0], outpt[1], batch)

        # update tx index and memory pool
        for tx in block.vtx:
            try:
                batch.Delete('tx:' + tx.GetHash())
            except KeyError:
                pass

            if not tx.is_coinbase():
                self.mempool.add(tx)

        # update database pointers for best chain
        batch.Put('misc:total_work', hex(prevmeta.work))
        batch.Put('misc:height', str(prevmeta.height))
        batch.Put('misc:tophash', block.hashPrevBlock)
        self.db.Write(batch)

        self.log.info("disconnect: height {}, block {}".format(
            prevmeta.height, block.hashPrevBlock))

        return True

    def getblockmeta(self, blkhash):
        try:
            meta = BlkMeta()
            meta.deserialize(self.db.Get('blkmeta:' + blkhash))
        except KeyError:
            return None

        return meta

    def getblockheight(self, blkhash):
        meta = self.getblockmeta(blkhash)
        if meta is None:
            return -1

        return meta.height

    def reorganize(self, new_best_blkhash):
        self.log.info("Reorganize start ========")

        conn = []
        disconn = []

        old_best_blkhash = self.gettophash()
        fork = old_best_blkhash
        longer = new_best_blkhash
        while fork != longer:
            while (self.getblockheight(longer) >
                   self.getblockheight(fork)):
                block = self.getblock(longer)
                conn.append(block)

                longer = block.hashPrevBlock
                if longer == 0:
                    return False

            if fork == longer:
                break

            block = self.getblock(fork)
            disconn.append(block)

            fork = block.hashPrevBlock
            if fork == 0:
                return False

        self.log.info("REORG disconnecting top hash {}"
                      .format(old_best_blkhash.encode('hex')))

        for block in disconn:
            if not self.disconnect_block(block):
                return False

        self.log.info("REORG connecting new top hash {}"
                      .format(new_best_blkhash.encode('hex')))
        self.log.info("REORG chain union point {}".format(fork.encode('hex')))

        for block in conn:
            if not self.connect_block(block.GetHash(),
                                      block,
                                      self.getblockmeta(block.GetHash())):
                return False

        self.log.info("REORG disconnected %d blocks, connected %d blocks" % (
            len(disconn), len(conn)))

        self.log.info("Reorganize end =========")
        return True

    def set_best_chain(self, ser_prevhash, ser_hash, block, blkmeta):
        # the easy case, extending current best chain
        if (blkmeta.height == 0 or
                self.db.Get('misc:tophash') == ser_prevhash):
            return self.connect_block(ser_hash, block, blkmeta)

        # switching from current chain to another, stronger chain
        return self.reorganize(block.GetHash())

    def putoneblock(self, block):
        try:
            core.CheckBlock(block)
        except core.CheckBlockError:
            self.log.info(
                "Invalid block {}".format(block.GetHash().encode('hex')))
            return False

        if not self.have_prevblock(block):
            self.orphans[block.GetHash()] = True
            self.orphan_deps[block.hashPrevBlock] = block
            self.log.info("Orphan block {} ({} orphans)"
                          .format(block.GetHash().encode('hex'),
                                  len(self.orphan_deps)))
            return False

        top_height = self.getheight()
        top_work = long(self.db.Get('misc:total_work'), 16)

        # read metadata for previous block
        prevmeta = BlkMeta()
        if top_height >= 0:
            prevmeta.deserialize(self.db.Get('blkmeta:' + block.hashPrevBlock))

        batch = leveldb.WriteBatch()

        # build network "block" msg, as canonical disk storage form
        msg = msg_block()
        msg.block = block
        f = cStringIO.StringIO()
        msg.msg_ser(f)
        msg_data = f.getvalue()

        # write "block" msg to storage
        fpos = self.blk_write.tell()
        self.blk_write.write(msg_data)
        self.blk_write.flush()

        # add index entry
        batch.Put('blocks:' + block.GetHash(), str(fpos))

        # store metadata related to this block
        blkmeta = BlkMeta()
        blkmeta.height = prevmeta.height + 1
        blkmeta.work = (prevmeta.work +
                        serialize.uint256_from_compact(block.nBits))
        batch.Put('blkmeta:' + block.GetHash(), blkmeta.serialize())

        # store list of blocks at this height
        heightidx = HeightIdx()
        heightstr = str(blkmeta.height)
        try:
            heightidx.deserialize(self.db.Get('height:' + heightstr))
        except KeyError:
            pass
        heightidx.blocks.append(block.GetHash())

        batch.Put('height:' + heightstr, heightidx.serialize())
        self.db.Write(batch)

        # if chain is not best chain, proceed no further
        if blkmeta.work <= top_work:
            self.log.info(
                "height {} (weak), block {}"
                .format(blkmeta.height, block.GetHash().encode('hex')))
            return True

        # update global chain pointers
        if not self.set_best_chain(block.hashPrevBlock, block.GetHash(),
                                   block, blkmeta):
            return False

        return True

    def putblock(self, block):
        if self.haveblock(block.GetHash(), True):
            self.log.info("Duplicate block {} submitted"
                          .format(block.GetHash().encode('hex')))
            return False

        if not self.putoneblock(block):
            return False

        blkhash = block.GetHash()
        while blkhash in self.orphan_deps:
            block = self.orphan_deps[blkhash]
            if not self.putoneblock(block):
                return True

            del self.orphan_deps[blkhash]
            del self.orphans[block.GetHash()]

            blkhash = block.GetHash()

        return True

    def locate(self, locator):
        for hash in locator.vHave:
            if hash in self.blkmeta:
                blkmeta = BlkMeta()
                blkmeta.deserialize(self.db.Get('blkmeta:' + hash))
                return blkmeta
        return 0

    def getheight(self):
        return int(self.db.Get('misc:height'))

    def gettophash(self):
        return self.db.Get('misc:tophash')

    def loadfile(self, filename):
        fd = os.open(filename, os.O_RDONLY)
        self.log.info("Importing data from " + filename)
        buf = ''
        wanted = 4096
        while True:
            if wanted > 0:
                if wanted < 4096:
                    wanted = 4096
                s = os.read(fd, wanted)
                if len(s) == 0:
                    break

                buf += s
                wanted = 0

            buflen = len(buf)
            startpos = string.find(buf, self.params.MESSAGE_START)
            if startpos < 0:
                wanted = 8
                continue

            sizepos = startpos + 4
            blkpos = startpos + 8
            if blkpos > buflen:
                wanted = 8
                continue

            blksize = struct.unpack("<i", buf[sizepos:blkpos])[0]
            if (blkpos + blksize) > buflen:
                wanted = 8 + blksize
                continue

            ser_blk = buf[blkpos:blkpos + blksize]
            buf = buf[blkpos + blksize:]

            f = cStringIO.StringIO(ser_blk)
            block = core.CBlock()
            block.deserialize(f)

            self.putblock(block)
