Getting Started
===============

Go through these 4 simple steps to install and configure tBB.

Up to this moment the only tested OS for tBB is Ubuntu, nevertheless you should
be able to run tBB in many other POSIX environments.


0. Are you allowed to do this?
------------------------------

Before starting at all you should consider that tBB installation *and execution*
require root privileges.
If you're not able to supply such privileges for your environment, please contact your system administrator.


1. Check Python is installed
----------------------------

tBB requires Python 3 to run. Check that it is installed before proceeding::

    sudo apt install python3 python3-pip git
    python3

If a shell like this ``>>>`` pops up, Python had been correctly installed.
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

First let tBB create the folders it needs to get working::

    sudo ./run 192.168.0.0/24
    
.. note:: The network you specify with this command is not relevant.
          We just need to launch tBB so that it installs its required
          configuration folders.
 
Now tBB should complain that it didn't find a password file, let's go
and create it.
 
Front-ends will ask for this password when you connect to a running tBB server::

    cd ~/.tBB
    sudo nano tBB_access_password
    *enter password & save*
    sudo chmod 600 tBB_access_password

You're done!
------------

Now you can start using tBB. Go back to the installation folder and start tBB::

    sudo ./run …  # whatever network you mean to monitor

You can also configure tBB to fit your specific needs. Please refer to the
configuration section of this manual.

Uh oh!
------
Did something go wrong? You might find the answer to your questions in this section, if not, feel free to open an issue `on GitHub <https://github.com/dpdani/tBB>`_.
