#
# node.py - Bitcoin P2P network half-a-node
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import gevent
import gevent.pywsgi
from gevent import Greenlet

import toml
import struct
import socket
import time
import sys
import random
import cStringIO
import copy
import hashlib
import logging
import argparse
import signal

import bitcoin.messages as messages
import bitcoin.net as net

from .mem_pool import MemPool
from .chain_db import ChainDb
from .networks import networks

MY_SUBVERSION = "/pynode2:0.1.0/"


class NodeConn(Greenlet):

    def __init__(self, dstaddr, dstport, manager):
        Greenlet.__init__(self)
        self.log = logging.getLogger(self.__class__.__name__)
        self.peermgr = manager.peermgr
        self.mempool = manager.mempool
        self.chaindb = manager.chaindb
        self.params = manager.params

        self.dstaddr = dstaddr
        self.dstport = dstport
        self.sock = gevent.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.recvbuf = ""
        self.ver_send = self.params.MIN_PROTO_VERSION
        self.ver_recv = self.params.PROTO_VERSION
        self.last_sent = 0
        self.getblocks_ok = True
        self.last_block_rx = time.time()
        self.last_getblocks = 0
        self.remote_height = -1
        self.hash_continue = None

    def _run(self):
        self.log.info("Connecting to {}:{}"
                      .format(self.dstaddr, self.dstport))
        try:
            self.sock.connect((self.dstaddr, self.dstport))
        except:
            self.handle_close()

        # stuff version msg into sendbuf
        vt = messages.msg_version()
        vt.addrTo.ip = self.dstaddr
        vt.addrTo.port = self.dstport
        vt.addrFrom.ip = "0.0.0.0"
        vt.addrFrom.port = 0
        if self.settings['spv']:
            vt.nServices = 0
        else:
            vt.nServices = 1
        vt.nStartingHeight = self.chaindb.getheight()
        vt.strSubVer = MY_SUBVERSION
        self.send_message(vt)

        self.log.info("Connected to {}:{}"
                      .format(self.dstaddr, self.dstport))
        try:
            while True:
                try:
                    t = self.sock.recv(8192)
                    if len(t) <= 0:
                        raise ValueError
                except (IOError, ValueError):
                    self.handle_close()
                    return
                self.recvbuf += t
                self.got_data()
        except Exception:
            self.log.error(
                "Connection to peer crashed! {}:{}, ver {}"
                .format(self.dstaddr, self.dstport, self.ver_send), exc_info=True)
            self.handle_close()

    def handle_close(self):
        self.log.info("Closed connection to {}:{}"
                      .format(self.dstaddr, self.dstport))
        self.recvbuf = ""
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.close()
        except:
            pass

    def got_data(self):
        while True:
            if len(self.recvbuf) < 4:
                return
            if self.recvbuf[:4] != self.params.MESSAGE_START:
                raise ValueError("got garbage %s" % repr(self.recvbuf))
            # check checksum
            if len(self.recvbuf) < 4 + 12 + 4 + 4:
                return
            command = self.recvbuf[4:4 + 12].split("\x00", 1)[0]
            msglen = struct.unpack("<i", self.recvbuf[4 + 12:4 + 12 + 4])[0]
            checksum = self.recvbuf[4 + 12 + 4:4 + 12 + 4 + 4]
            if len(self.recvbuf) < 4 + 12 + 4 + 4 + msglen:
                return
            msg = self.recvbuf[4 + 12 + 4 + 4:4 + 12 + 4 + 4 + msglen]
            th = hashlib.sha256(msg).digest()
            h = hashlib.sha256(th).digest()
            if checksum != h[:4]:
                raise ValueError("got bad checksum %s" % repr(self.recvbuf))
            self.recvbuf = self.recvbuf[4 + 12 + 4 + 4 + msglen:]

            if command in messages.messagemap:
                f = cStringIO.StringIO(msg)
                cls = messages.messagemap[command]
                t = cls.msg_deser(f, protover=self.ver_send)
                self.got_message(t)
            else:
                self.log.warn("UNKNOWN COMMAND %s %s" % (command, repr(msg)))

    def send_message(self, message):
        self.log.debug("send %s" % repr(message))

        tmsg = message.to_bytes(params=self.params)

        try:
            self.sock.sendall(tmsg)
            self.last_sent = time.time()
        except:
            self.handle_close()

    def send_getheaders(self):
        our_height = self.chaindb.getheight()
        if our_height < 0:
            tophash = self.params.GENESIS_BLOCK.GetHash()
        elif our_height < self.remote_height:
            tophash = self.chaindb.gettophash()
        else:
            return

        gb = messages.msg_getheaders(protover=self.ver_send)
        if our_height >= 0:
            gb.locator.vHave.append(tophash)
        self.send_message(gb)

    def send_getblocks(self):
        our_height = self.chaindb.getheight()
        if our_height < 0:
            gd = messages.msg_getdata(protover=self.ver_send)
            inv = net.CInv()
            inv.type = 2
            inv.hash = self.params.GENESIS_BLOCK.GetHash()
            gd.inv.append(inv)
            self.send_message(gd)
        elif our_height < self.remote_height:
            gb = messages.msg_getblocks(protover=self.ver_send)
            if our_height >= 0:
                gb.locator.vHave.append(self.chaindb.gettophash())
            self.send_message(gb)

    def request_latest(self, timecheck=True):
        if not self.getblocks_ok:
            return
        now = time.time()
        if timecheck and (now - self.last_getblocks) < 5:
            return
        self.last_getblocks = now

        if self.settings['spv']:
            self.send_getheaders()
        else:
            self.send_getblocks()

    def got_message(self, message):
        gevent.sleep()

        if self.last_sent + 30 * 60 < time.time():
            self.send_message(messages.msg_ping(self.ver_send))

        self.log.debug("recv %s" % repr(message))

        if message.command == "version":
            self.ver_send = min(self.params.PROTO_VERSION, message.nVersion)
            if self.ver_send < self.params.MIN_PROTO_VERSION:
                self.log.info("Obsolete version %d, closing" %
                              (self.ver_send,))
                self.handle_close()
                return

            if (self.ver_send >= self.params.NOBLKS_VERSION_START and
                    self.ver_send <= self.params.NOBLKS_VERSION_END):
                self.getblocks_ok = False

            self.remote_height = message.nStartingHeight
            self.send_message(messages.msg_verack(self.ver_send))
            if self.ver_send >= self.params.CADDR_TIME_VERSION:
                self.send_message(messages.msg_getaddr(self.ver_send))
            self.request_latest()

        elif message.command == "verack":
            self.ver_recv = self.ver_send

            if self.ver_send >= self.params.MEMPOOL_GD_VERSION:
                self.send_message(messages.msg_mempool())

        elif message.command == "ping":
            if self.ver_send > self.params.BIP0031_VERSION:
                self.send_message(messages.msg_pong(self.ver_send))

        elif message.command == "addr":
            self.peermgr.new_addrs(message.addrs)

        elif message.command == "inv":

            # special message sent to kick getblocks
            if (len(message.inv) == 1 and
                    message.inv[0].type == messages.MSG_BLOCK and
                    self.chaindb.haveblock(message.inv[0].hash, True)):
                self.request_latest(False)
                return

            want = messages.msg_getdata(self.ver_send)
            for i in message.inv:
                if i.type == 1:
                    want.inv.append(i)
                elif i.type == 2:
                    want.inv.append(i)
            if len(want.inv):
                self.send_message(want)

        elif message.command == "tx":
            if self.chaindb.tx_is_orphan(message.tx):
                self.log.info(
                    "MemPool: Ignoring orphan TX {}"
                    .format(message.tx.GetHash().encode('hex')))
            elif not self.chaindb.tx_signed(message.tx, None, True):
                self.log.info(
                    "MemPool: Ignoring failed-sig TX {}"
                    .format(message.tx.GetHash().encode('hex')))
            else:
                self.mempool.add(message.tx)

        elif message.command == "block":
            self.chaindb.putblock(message.block)
            self.last_block_rx = time.time()

        elif message.command == "headers":
            self.chaindb.putblock(message.block)
            self.last_block_rx = time.time()

        elif message.command == "getdata":
            self.getdata(message)

        elif message.command == "getblocks":
            self.getblocks(message)

        elif message.command == "getheaders":
            self.getheaders(message)

        elif message.command == "getaddr":
            msg = messages.msg_addr()
            msg.addrs = self.peermgr.random_addrs()

            self.send_message(msg)

        elif message.command == "mempool":
            msg = messages.msg_inv()
            for k in self.mempool.pool.iterkeys():
                inv = net.CInv()
                inv.type = messages.MSG_TX
                inv.hash = k
                msg.inv.append(inv)

                if len(msg.inv) == 50000:
                    break

            self.send_message(msg)

        # if we haven't seen a 'block' message in a little while,
        # and we're still not caught up, send another getblocks
        last_blkmsg = time.time() - self.last_block_rx
        if last_blkmsg > 5:
            self.request_latest()

    def getdata_tx(self, txhash):
        if txhash in self.mempool.pool:
            tx = self.mempool.pool[txhash]
        else:
            tx = self.chaindb.gettx(txhash)
            if tx is None:
                return

        msg = messages.msg_tx()
        msg.tx = tx

        self.send_message(msg)

    def getdata_block(self, blkhash):
        block = self.chaindb.getblock(blkhash)
        if block is None:
            return

        msg = messages.msg_block()
        msg.block = block

        self.send_message(msg)

        if blkhash == self.hash_continue:
            self.hash_continue = None

            inv = net.CInv()
            inv.type = messages.MSG_BLOCK
            inv.hash = self.chaindb.gettophash()

            msg = messages.msg_inv()
            msg.inv.append(inv)

            self.send_message(msg)

    def getdata(self, message):
        if len(message.inv) > 50000:
            self.handle_close()
            return
        for inv in message.inv:
            if inv.type == messages.MSG_TX:
                self.getdata_tx(inv.hash)
            elif inv.type == messages.MSG_BLOCK:
                self.getdata_block(inv.hash)

    def getblocks(self, message):
        blkmeta = self.chaindb.locate(message.locator)
        height = blkmeta.height
        top_height = self.getheight()
        end_height = height + 500
        if end_height > top_height:
            end_height = top_height

        msg = messages.msg_inv()
        while height <= end_height:
            hash = long(self.chaindb.height[str(height)])
            if hash == message.hashstop:
                break

            inv = net.CInv()
            inv.type = messages.MSG_BLOCK
            inv.hash = hash
            msg.inv.append(inv)

            height += 1

        if len(msg.inv) > 0:
            self.send_message(msg)
            if height <= top_height:
                self.hash_continue = msg.inv[-1].hash

    def getheaders(self, message):
        blkmeta = self.chaindb.locate(message.locator)
        height = blkmeta.height
        top_height = self.getheight()
        end_height = height + 2000
        if end_height > top_height:
            end_height = top_height

        msg = messages.msg_headers()
        while height <= end_height:
            blkhash = long(self.chaindb.height[str(height)])
            if blkhash == message.hashstop:
                break

            db_block = self.chaindb.getblock(blkhash)
            block = copy.copy(db_block)
            block.vtx = []

            msg.headers.append(block)

            height += 1

        self.send_message(msg)


class PeerManager(object):

    def __init__(self, manager):
        self.log = logging.getLogger(self.__class__.__name__)
        self.mempool = manager.mempool
        self.chaindb = manager.chaindb
        self.params = manager.params
        self.manager = manager

        self.peers = []
        self.addrs = {}
        self.tried = {}

    def add(self, host, port):
        self.log.info("PeerManager: connecting to %s:%d" % (host, port))
        self.tried[host] = True
        c = NodeConn(host, port, self.manager)
        self.peers.append(c)
        return c

    def new_addrs(self, addrs):
        for addr in addrs:
            if addr.ip in self.addrs:
                continue
            self.addrs[addr.ip] = addr

        self.log.info("PeerManager: Received %d new addresses (%d addrs, %d tried)" %
                      (len(addrs), len(self.addrs), len(self.tried)))

    def random_addrs(self):
        ips = self.addrs.keys()
        random.shuffle(ips)
        if len(ips) > 1000:
            del ips[1000:]

        vaddr = []
        for ip in ips:
            vaddr.append(self.addrs[ip])

        return vaddr

    def closeall(self):
        for peer in self.peers:
            peer.handle_close()
        self.peers = []


class Manager(object):
    defaults = dict(host="127.0.0.1",
                    rpcpass=None,
                    rpcuser=None,
                    port=8333,
                    rpcport=9332,
                    db="/tmp/chaindb",
                    spv=False,
                    datadir="/tmp/pynode_datadir",
                    chain="bitcoin_mainnet")

    def __init__(self, settings):
        self.settings = self.defaults.copy()
        self.settings.update(settings)

        if not self.settings['rpcuser'] or not self.settings['rpcpass']:
            self.log.error(
                "You must set the following in config: rpcuser, rpcpass")
            sys.exit(1)

        self.settings['port'] = int(self.settings['port'])
        self.settings['rpcport'] = int(self.settings['rpcport'])

        self.log = logging.getLogger("startup")
        root = logging.getLogger()
        root.setLevel(logging.INFO)

        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s [%(name)s] %(levelname)s: %(message)s')
        ch.setFormatter(formatter)
        root.addHandler(ch)
        self.log.info("=" * 100)
        self.log.info("PyNode starting up....")

        self.params = networks[self.settings['chain']]

        self.mempool = MemPool()
        self.chaindb = ChainDb(self)
        self.peermgr = PeerManager(self)

        # connect to all seed nodes
        for name, dns in self.params.DNS_SEEDS:
            hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(dns)
            for ip in ipaddrlist:
                self.log.info("Got {} from DNS seed {}".format(ip, dns))
                c = self.peermgr.add(ip, self.params.DEFAULT_PORT)
                c.start()

        gevent.signal(signal.SIGHUP, exit, "SIGHUP")
        gevent.signal(signal.SIGINT, exit, "SIGINT")
        gevent.signal(signal.SIGTERM, exit, "SIGTERM")

        #gevent.wait()
        while True:
            gevent.sleep(3)
            self.log.info("Connected to {} peers"
                          .format(len(self.peermgr.peers)))

        self.log.info("PyNode EXIT")
        self.log.info("=" * 100)

    def exit(self, signal=None):
        """ Handle an exit request """
        self.logger.info("{} {}".format(signal, "*" * 80))
        # Kill the top level greenlet
        gevent.kill(gevent.hub.get_hub().parent)


def main():
    parser = argparse.ArgumentParser(description='Run powerpool!')
    parser.add_argument('config', type=argparse.FileType('r'),
                        help='yaml configuration file to run with')
    parser.add_argument('-d', '--dump-config', action="store_true",
                        help='print the result of the YAML configuration file and exit')
    parser.add_argument('-s', '--server-number', type=int, default=0,
                        help='increase the configued server_number by this much')
    args = parser.parse_args()

    # override those defaults with a loaded yaml config
    raw_config = toml.load(args.config) or {}
    if args.dump_config:
        import pprint
        pprint.pprint(raw_config)
        exit(0)
    Manager(raw_config)


if __name__ == '__main__':
    main()
