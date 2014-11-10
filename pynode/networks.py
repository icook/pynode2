from bitcoin.core import x, CBlock


class BitcoinMainNet(object):
    # Replace global defs from bitcoin.core
    COIN = 100000000
    MAX_MONEY = 21000000 * COIN
    MAX_BLOCK_SIZE = 1000000
    MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50

    BIP0031_VERSION = 60000
    PROTO_VERSION = 60002
    MIN_PROTO_VERSION = 209

    CADDR_TIME_VERSION = 31402

    # Mimick bitcoinlib "params" global
    MESSAGE_START = b'\xf9\xbe\xb4\xd9'
    DEFAULT_PORT = 8333
    RPC_PORT = 8332
    DNS_SEEDS = (('bitcoin.sipa.be', 'seed.bitcoin.sipa.be'),
                 ('bluematt.me', 'dnsseed.bluematt.me'),
                 ('dashjr.org', 'dnsseed.bitcoin.dashjr.org'),
                 ('bitcoinstats.com', 'seed.bitcoinstats.com'),
                 ('xf2.org', 'bitseed.xf2.org'))
    BASE58_PREFIXES = {'PUBKEY_ADDR': 0,
                       'SCRIPT_ADDR': 5,
                       'SECRET_KEY': 128}

    # Mimick bitcoinlib "core_params" global
    NAME = 'bitcoin_mainnet'
    GENESIS_BLOCK = CBlock.deserialize(
        x('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'))
    SUBSIDY_HALVING_INTERVAL = 210000
    PROOF_OF_WORK_LIMIT = 2 ** 256 - 1 >> 32


class BitcoinTestNet(BitcoinMainNet):
    # Mimick bitcoinlib "core_params" global
    NAME = 'bitcoin_testnet'
    GENESIS_BLOCK = CBlock.deserialize(
        x('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'))

    # Mimick bitcoinlib "params" global
    MESSAGE_START = b'\x0b\x11\x09\x07'
    DEFAULT_PORT = 18333
    RPC_PORT = 18332
    DNS_SEEDS = (('bitcoin.petertodd.org', 'testnet-seed.bitcoin.petertodd.org'),
                 ('bluematt.me', 'testnet-seed.bluematt.me'))
    BASE58_PREFIXES = {'PUBKEY_ADDR': 111,
                       'SCRIPT_ADDR': 196,
                       'SECRET_KEY': 239}


class BitcoinRegTest(BitcoinMainNet):
    # Mimick bitcoinlib "core_params" global
    NAME = 'bitcoin_regtest'
    GENESIS_BLOCK = CBlock.deserialize(
        x('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'))
    SUBSIDY_HALVING_INTERVAL = 150
    PROOF_OF_WORK_LIMIT = 2 ** 256 - 1 >> 1

    # Mimick bitcoinlib "params" global
    MESSAGE_START = b'\xfa\xbf\xb5\xda'
    DEFAULT_PORT = 18444
    RPC_PORT = 18332
    DNS_SEEDS = ()
    BASE58_PREFIXES = {'PUBKEY_ADDR': 111,
                       'SCRIPT_ADDR': 196,
                       'SECRET_KEY': 239}


networks = {'bitcoin_regtest': BitcoinRegTest,
            'bitcoin_testnet': BitcoinTestNet,
            'bitcoin_mainnet': BitcoinMainNet}
