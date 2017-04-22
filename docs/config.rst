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


**monitoring → discoveries**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``arp``                             Section dedicated to the ARP discovery method  *is section, see below*     ...
``icmp``                            Section dedicated to the ICMP discovery        *is section, see below*     ...
                                    method
``syn``                             Section dedicated to the SYN discovery method  *is section, see below*     ...
==================================  =============================================  =========================  =============


**monitoring → discoveries → arp**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``count``                           Number of ARP broadcasts to emit.              ``1``                      ``3``
``timeout``                         Maximum amount of time in which to wait for    
                                    a response (in seconds). Must be a positive
                                    integer.
                                    A higher value in this field represent a more
                                    reliable check, but also a slower one.
``quit_on_first``                   Stop listening for responses at first          ``false``                  ``true``
                                    response.
==================================  =============================================  =========================  =============


**monitoring → discoveries → icmp**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``count``                           Number of requests to send.                    ``4``                      ``1``
                                    If ``flood`` is enabled, it represents the
                                    number of responses to receive before
                                    returning.
``timeout``                         Maximum amount of time in which to wait for    ``1``                      ``4``
                                    a response (in seconds). Must be a positive
                                    integer.
                                    A higher value in this field represent a more
                                    reliable check, but also a slower one.
``flood``                           Enable/disable flood ping mode.                ``false``                  ``true``
``enable``                          Enable/disable discovery method.               ``false``                  ``true``
==================================  =============================================  =========================  =============


**monitoring → discoveries → syn**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``ports``                           Ports to check. Must be of string type.        ``'80'``                   ``'2'``
``timeout``                         Maximum amount of time in which to wait for    ``1``                      ``4``
                                    a response (in seconds). Must be a positive
                                    integer.
                                    A higher value in this field represent a more
                                    reliable check, but also a slower one.
``enable``                          Enable/disable discovery method.               ``false``                  ``true``
==================================  =============================================  =========================  =============


**frontends**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``host``                            IP address for the frontends socket.           ``192.168.1.10``           ``localhost``
``port``                            Port number for the frontends socket.          ``2000``                   ``1984``
``maximum_port_lookup``             Maximum number of times tBB will look for the  ``1``                      ``20``
                                    next available port if the previous one is
                                    busy.
``ssl``                             Section dedicated to securing communications   *is section, see below*     ...
                                    with SSL/TLS.
==================================  =============================================  =========================  =============


**frontends → ssl**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``enable``                          Enable/disable SSL encryption. tBB will fall   ``false``                  ``true``
                                    back to HTTP communication.
``check_hostname``                  Enable/disable certificate checking, must      ``true``                   ``false``
                                    agree with frontends on this field for
                                    correct SSL handshake.
==================================  =============================================  =========================  =============


**serialization**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``indent``                          Number of spaces with which indent the scan    ``0``                      ``4``
                                    storages (`json.dump(indent) ext. docs`_).
``do_sort``                         Enable/disable sorting of scan storages        ``false``                  ``true``
                                    (`json.dump(sort_keys) ext. docs`_).
==================================  =============================================  =========================  =============


**logging**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``default_time_format``             Default format for datetimes in log files.     ``'%d-%m-%Y %H.%M.%S'``    ``'%Y-%m-%d %H.%M.%S'``
                                    [#f3]_
``level``                           Minimum logging level. One of ``DEBUG``,       ``DEBUG``                  ``INFO``
                                    ``INFO``, ``WARNING``, ``ERROR``,
                                    ``CRITICAL``.
``formatters``                      Section dedicated to loggers formatters.       *is section, see below*     ...
``handlers``                        Section dedicated to loggers handlers.         *is section, see below*     ...
==================================  =============================================  =========================  =============


**logging → formatters**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``complete``                        Section dedicated to the complete formatter.   *is section, see below*     ...
``brief``                           Section dedicated to the brief formatter.      *is section, see below*     ...
``syslog``                          Section dedicated to the syslog formatter.     *is section, see below*     ...
``custom_1``                        Section dedicated to the custom_1 formatter.   *is section, see below*     ...
``custom_2``                        Section dedicated to the custom_2 formatter.   *is section, see below*     ...
``custom_3``                        Section dedicated to the custom_3 formatter.   *is section, see below*     ...
==================================  =============================================  =========================  =============


**logging → formatters → complete/brief/syslog/custom_1/custom_2/custom_3**

*All formatters share the same configuration skeleton.*

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``format``                          String to format logging upon. [#f4]_           ...                        ...
``datefmt``                         String to format datetimes upon. [#f3]_        ``'%d-%m-%Y %H.%M.%S'``    ``{default_time_format}``
                                    Macro ``{default_time_format}`` points to 
                                    ``logging`` → ``default_time_format``.
==================================  =============================================  =========================  =============


**logging → handlers**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``console``                         Section dedicated to the complete handler.     *is section, see below*     ...
``syslog``                          Section dedicated to the syslog handler.       *is section, see below*     ...
``file``                            Section dedicated to the file handler.         *is section, see below*     ...
``enable``                          List of enabled logging handlers: handlers     ``[]``                     ``['console', 'file']``
                                    found in this list will be triggered when
                                    logging.
==================================  =============================================  =========================  =============


**logging → handlers → console**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``level``                           Minimum logging level for this handler. One    ``DEBUG``                  ``INFO``
                                    of ``DEBUG``, ``INFO``, ``WARNING``,
                                    ``ERROR``, ``CRITICAL``.
``formatter``                       Formatter chosen for this handler, as defined  ``custom_1``               ``brief``
                                    in ``logging`` → ``formatters``.
==================================  =============================================  =========================  =============


**logging → handlers → syslog**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``level``                           Minimum logging level for this handler. One    ``DEBUG``                  ``INFO``
                                    of ``DEBUG``, ``INFO``, ``WARNING``,
                                    ``ERROR``, ``CRITICAL``.
``formatter``                       Formatter chosen for this handler, as defined  ``custom_2``               ``syslog``
                                    in ``logging`` → ``formatters``.
``address``                         Section dedicated to the syslog host address.  *is section, see below*     ...
``socktype``                        ISO/OSI level 4 protocol chosen by the syslog  ``STREAM``                 ``DATAGRAM``
                                    server. One of UDP: ``DATAGRAM``, TCP:
                                    ``STREAM``.
==================================  =============================================  =========================  =============


**logging → handlers → syslog → address**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``ip``                              Syslog host IP.                                ``'192.168.100.20'``       ``''``
``port``                            Syslog server port.                            ``514``                    ``''``
==================================  =============================================  =========================  =============


**logging → handlers → file**

==================================  =============================================  =========================  =============
Field name                          Description                                    Example values             Default value
==================================  =============================================  =========================  =============
``level``                           Minimum logging level for this handler. One    ``WARNING``                ``DEBUG``
                                    of ``DEBUG``, ``INFO``, ``WARNING``,
                                    ``ERROR``, ``CRITICAL``.
``formatter``                       Formatter chosen for this handler, as defined  ``syslog``                 ``complete``
                                    in ``logging`` → ``formatters``.
``max_bytes``                       Maximum size for log file (in bytes).          ``1000``                   ``10000000`` (``10 MB``)
``backup_count``                    Maximum number of log files (of at most        ``1``                      ``4``
                                    ``max_bytes`` size) to keep.
``filename``                        Log file name.                                 ``definetelynota           ``tBB.log``
                                                                                   logfile.log``
==================================  =============================================  =========================  =============




.. [#f1] Determined by `Tracker.highest_priority_host <http://tbb.readthedocs.io/en/latest/tBB.html#tBB.tracker.Tracker.highest_priority_host>`_.
.. [#f2] See `Tracker.keep_network_tracked <http://tbb.readthedocs.io/en/latest/tBB.html#tBB.tracker.Tracker.keep_network_tracked>`_ for further details.
.. [#f3] Python logging library date format documentation https://docs.python.org/3/library/logging.html#logging.Formatter.formatTime
.. [#f4] Python logging library log records documentation https://docs.python.org/3/library/logging.html#logrecord-attributes
.. _json.dump(indent) ext. docs: https://docs.python.org/3/library/json.html#json.dump
.. _json.dump(sort_keys) ext. docs: https://docs.python.org/3/library/json.html#json.dump
