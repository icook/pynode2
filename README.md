PyNode2
===========

**Still very green, although contributions are more than welcome**

This is a cleanup/rewrite of the pynode written by Jeff Garzik. The goal is to
make an easy to work with Bitcoin (or altcoin) node implementation for network
analysis in the spirit of [Bitnode's getaddr](https://getaddr.bitnodes.io/).
Working with Python tends to be much quicker/easier than C++ or similar systems
languages.

Note that this node implementation isn't designed to be used for real
sending/recieving, but more as a malleable tool for education and analysis of
the network.

Only Python 2.7 is currently supported due to reliance on Gevent.

Contributing
================

Contributions are always welcome, my only request at the moment is that you try
and code pretty closely to [PEP8](https://www.python.org/dev/peps/pep-0008/)
standards.

Most tasks on this project will need a pretty good understanding of both Python
and Bitcoin internals until there is more documentation.

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

* Download and synchronize a blockchain (slower than reference wallet)
* Connect to peers using DNS seed nodes
* Multiple network configurations possible (testnet, litecoin, etc)
