Configuring tBB
===============

If you wish to configure tBB settings, you can use the configuration files tBB is instructed to
look for. These files are always located in the ``~/.tBB/configs/`` folder. Please check where this folder
is located before continuing reading.

Configuration files are in the standard JSON format. If you're unfamiliar with such format, please refer
to `RFC 7159 <https://tools.ietf.org/html/rfc7159>`_, or other documentation on the Internet.

.. note:: You're free to change settings in these files at any time, but if you want your
          changes to take effect you'll to have to restart tBB.


How configuration works in tBB
------------------------------

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

Each new level overrides the configurations of the previous one.

.. note:: There are many configuration files you may want to add to your 
          tBB installation, but tBB is capable of running without any configuration
          file, falling back to the built-in configuration.


Network-specific configuration files naming conventions
-------------------------------------------------------

Specific configuration files naming conventions follow the scans naming conventions, and is as follows::

    ~/.tBB/configs/config_{NETWORK IP}\{NETMASK (cidr)}-{NETWORK LENGTH}.json

This rigid naming conventions allow tBB to use the correct configuration file for every network
you may want to monitor.

For instance, if you want to create a configuration file for network ``192.168.100.0/24`` you're going to
need to create a file named ``config_192.168.100.0\24-256.json``. 

.. note:: Please note the backslash ``\`` replacing the forward slash ``/`` (forward slash is invalid for
          the Unix file name conventions). Also note the given network length in the filename after the dash ``-`` sign.


Configuration fields
--------------------

The various fields configurable in tBB are divided in logical sections, so that they can be easier
to understand and recognize.

What follows are tables of the available configurable fields.

Default values are the values specified in the built-in configuration.


**Root-level**

=================  =============================================  =======================  =============
Field name         Description                                    Example values           Default value
=================  =============================================  =======================  =============
``monitoring``     Section dedicated to the monitoring machinery  *is section, see below*   ...
``frontends``      Section dedicated to frontends communication   *is section, see below*   ...
``serialization``  Section dedicated to scans storage handling    *is section, see below*   ...
``logging``        Section dedicated to the logging facilities    *is section, see below*   ...
=================  =============================================  =======================  =============


**monitoring**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``discoveries``                     Section dedicated to the discovery methods     *is section, see below*     ...
``least_record_update``             Maximum amount of time for which tBB will not  ``'00:00'``                ``'30:00'``
                                    re-perform a complete scan on startup
                                    (format: ``minutes:seconds``).
``enable_notifiers``                Tell notifiers about detected changes.         ``false``                  ``true``
``time_between_checks``             Amount of time to wait before proceeding       ``'00:00'``                ``'00:02'``
                                    to check the next host [#f1]_
                                    (format: ``minutes:seconds``).
``maximum_seconds_randomly_added``  Maximum amount of time to add randomly [#f2]_  ``10``                     ``2``
                                    to ``time_between_checks`` (in seconds). Must
                                    be a positive integer.
``auto_ignore_broadcasts``          Enable/disable automatic broadcasts ignore.    ``false``                  ``true``
                                    If enabled, when a broadcast is detected
                                    during a scan, it will be ignored in the next
                                    ones.
``hosts``                           Number of hosts sub-networks will be divided   ``64``                     ``16``
                                    into. Must be a valid network length (aka,
                                    power of 2).
``ignore``                          List of IPs to ignore.                         ``['192.168.100.1']``      ``[]``
``ignore_mac``                      List of MACs to ignore.                        ``['00:00:00:00:00:00']``  ``[]``
``ignore_name``                     List of host names to ignore.                  ``['donald.duck']``        ``[]``
==================================  =============================================  =========================  =============

.. [#f1] Determined by `Tracker.highest_priority_host <http://tbb.readthedocs.io/en/latest/tBB.html#tBB.tracker.Tracker.highest_priority_host>`_.
.. [#f2] See `Tracker.keep_network_tracked <http://tbb.readthedocs.io/en/latest/tBB.html#tBB.tracker.Tracker.keep_network_tracked>`_ for further details.
