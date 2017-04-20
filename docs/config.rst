Configuring tBB
=============

If you wish to configure tBB settings, you have to use the configuration files tBB is instructed to
use. These files are always located in the root tBB folder. Please check where this folder is located
before continuing reading.

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

The first level is the built-in configuration that comes with tBB: this cannot be changed and acts
as a fallback for tBB.

The second level is the default configuration which is stored in `~/.tBB/configs/config_default.json`:
you can set this and will be applied to every network your tBB installation will monitor.

The third level is the network-specific configuration which is stored in `~/.tBB/configs/config_{NETWORK}.json`:
this configuration will only be applied if 

There is more than one configuration file for tBB: there's the default configuration file and possibly
many network-specific configuration files. Both of these kinds of files are to be stored in the `~/.tBB/configs/`
folder.
