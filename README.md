PyNode2
===========

This is a rewrite of the pynode written by Jeff Garzik. The goal is to make an
easy to work with Bitcoin (or altcoin) node implementation for network
analysis. Working with Python tends to be much quicker/easier than C++ or
similar systems languages.

Note that this node implementation isn't designed to be used for real
sending/recieving, but more as a malleable tool for education and analysis of
the network.

Only Python 2.7 is currently supported due to reliance on Gevent.

Running PyNode
================

For development, setup a virtual enviroment like so:

```bash
mkvirtualenv pynode
git clone https://github.com/icook/pynode2
cd pynode2
pip install -r requirements.txt
pip install -e .
pynode example.toml
```

Currently there are no more automated ways to install. This may change if
there's interest.

Current Featureset
===================

* Download and synchronize a blockchain (somewhat slower than reference wallet)
* Connect to peers using DNS seed nodes
* Multiple network configurations (testnet, litecoin, etc)
