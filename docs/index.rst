.. tBB documentation master file, created by
   sphinx-quickstart on Fri Apr 14 15:36:45 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

tBB
===
tBB is an open-source Intrusion Detection System written in Python.
It is able of keeping track of connections, disconnections and other changes
in the network it monitors.


Contents:
---------
.. toctree::
   :maxdepth: 2

   networking
   network_security
   ids
   tBB
   AWS
   future


Installation
------------

To install tBB, fetch the latest version from GitHub::

    $ git clone https://github.com/dpdani/tBB.git
    $ cd tBB

Install the required dependencies::

    $ sudo python3 -m pip install -r requirements.txt
    $ sudo apt install nmap iputils-arping