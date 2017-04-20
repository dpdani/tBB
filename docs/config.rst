Configuring tBB
=============

If you wish to configure tBB settings, you can use the configuration files tBB is instructed to
look for. These files are always located in the ``~/.tBB/configs/`` folder. Please check where this folder
is located before continuing reading.

Configuration files are in the standard JSON format. If you're unfamiliar with such format, please refer
to `RFC 7159 <https://tools.ietf.org/html/rfc7159>`_, or other documentation on the Internet.

.. note:: You're free to change settings in these files at any time, but if you want your
          changes to take effect you'll to have to restart tBB.


How configuration works in tBB.
-------------------------------

Configuration in tBB works like the way cascade sheets work. There are 3 levels of configuration::

    BUILTIN configuration
            ^
            |
            |
    DEFAULT configuration
            ^
            |
            |
    SPECIFIC configuration

The first level is the *built-in* configuration that comes with tBB: this cannot be changed and acts
as a fallback for tBB.

The second level is the *default* configuration which is stored in ``~/.tBB/configs/config_default.json``:
you can set this and will be applied to every network your tBB installation will monitor.

The third level is the *network-specific* configuration which is stored in ``~/.tBB/configs/config_{NETWORK}.json``:
this configuration will only be applied if tBB is asked to monitor the ``{NETWORK}`` network.
On network-specific filename syntax please refer to the below section.

Each new level overrides the previous one.


Network-specific configuration files naming conventions.
--------------------------------------------------------

Specific configuration files naming conventions follow the scans naming conventions, and is as follows::

    ~/.tBB/configs/config_{NETWORK IP}\{NETMASK (cidr)}-{NETWORK LENGTH}.json

This rigid naming conventions allow tBB to use the correct configuration file for every network
you may want to monitor.

.. example:: For instance, if you want to create a configuration file for network ``192.168.100.0/24`` you're going to
             need to create a file named ``config_192.168.100.0\24-256.json``. 

.. note:: Please note the backslash ``\`` replacing the forward slash ``/`` (forward slash is invalid for
          the Unix file name conventions). Also note the given network length in the filename after the dash ``-`` sign.
