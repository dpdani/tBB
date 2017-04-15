Getting Started
===============

Go through these !!! number here !!! simple steps to install and configure tBB.

Up to this moment the only tested OS for tBB is Ubuntu, nevertheless you should
be able to run tBB in many other POSIX environments.


0. Are you allowed to do this?
------------------------------

Before starting at all you should consider that tBB installation *and execution*
require root privileges. If you're not able to supply such privileges for your
environment, please contact your system administrator.


1. Check Python is installed
----------------------------

tBB requires Python 3 to run. Check that it is installed before proceeding::

    sudo apt install python3
    python3

If a shell like this ``>>> `` pops up, Python had been correctly installed.
Close the shell and proceed with the installation.


2. Download tBB
---------------

Fetch the latest version of tBB from GitHub::

    git clone https://github.com/dpdani/tBB.git
    cd tBB


3. Download dependencies
------------------------

These dependencies are required to run tBB::

    sudo python3 -m pip install -r requirements.txt
    sudo apt install nmap iputils-arping


4. Set your password
--------------------

Front-ends will ask for this password when you connect to a running tBB server::

    sudo nano tBB_access_password
    *enter your password*
    sudo chmod 600 tBB_access_password

You're done!