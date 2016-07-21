"""

tBB - The Big Brother.
Network analysis tool: keeps track of connections, disconnections
and changes in the specified network.
For further information open tBB/docs/.

"""
import os
import socket
import sys
import datetime
import logging
import logging.config
import logging.handlers
import json
import asyncio
import tracker
from net_elements import *


loop = asyncio.get_event_loop()


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
default_time_format = "%d/%m/%Y-%H.%M.%S"
default_logging_config = {
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'complete': {
            'format': '%(levelname)s|%(name)s@%(asctime)s: %(message)s',
            'datefmt': default_time_format,
        },
        'brief': {
            'format': '%(asctime)s: %(message)s',
            'datefmt': default_time_format,
        },
    },
    'handlers': {
        'console': {
            'level': 'WARNING',
            'class': 'logging.StreamHandler',
            'formatter': 'brief',
        },
        'syslog': {
            'level': 'WARNING',
            'class': 'logging.handlers.SysLogHandler',
            'formatter': 'complete',
            'address': ("192.168.46.23", 1984),
            'socktype': socket.SOCK_DGRAM,
            'facility': logging.handlers.SysLogHandler.LOG_DAEMON,
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'complete',
            'maxBytes': 10000000,  # 10 Mb
            'backupCount': 4,  # occupies at most 50Mb for logs
            'filename': 'tBB.log'
        }
    },
    'loggers': {
        '': {
            'handlers': ['console', 'file', 'syslog'],
            'level': 'INFO',
            'propagate': True
        }
    }
}


def configure_logging(config_file, silent):
    if config_file:
        if 'logging' in config_file:
            try:
                if silent:
                    config_file['logging']['handlers']['console']['level'] = 60
                logging.config.dictConfig(config_file['logging'])
            except Exception:
                logger.warning("Couldn't use config file for logging.", exc_info=True)
            else:
                return
    logging.config.dictConfig(default_logging_config)


def configure_tracker(track, config):
    if config:
        if 'tracker' in config:
            for attr in config['tracker']:
                setattr(track, attr, config['tracker'][attr])


def read_configuration_file(path):
    config = dict()
    if os.path.exists(path):
        with open(path, 'r') as f:
            read = f.read().replace('{default_time_format}', default_time_format)
        try:
            config = json.loads(read)
        except (ValueError, ImportError):
            logger.info("Found configuration file at {}, but is malformed.", path, exc_info=True)
        else:
            logger.info("Found configuration file at {}.", path)
        try:
            config['logging']['handlers']['syslog']['address'] = \
                (config['logging']['handlers']['syslog']['address']['ip'],
                 config['logging']['handlers']['syslog']['address']['port'])
        except KeyError: pass
        try:
            config['tracker']['time_between_checks'] = datetime.timedelta(
                minutes = config['tracker']['time_between_checks']['minutes'],
                seconds = config['tracker']['time_between_checks']['seconds'],
            )
        except KeyError: pass
        try:
            config['tracker']['icmp'] = tracker.discoveries.ICMPDiscovery(
                count = config['tracker']['discoveries']['icmp']['count'],
                timeout = config['tracker']['discoveries']['icmp']['timeout'],
                flood = config['tracker']['discoveries']['icmp']['flood'],
                enabled = config['tracker']['do_icmp']
            )
        except KeyError: pass
        try:
            config['tracker']['arp'] = tracker.discoveries.ARPDiscovery(
                count = config['tracker']['discoveries']['arp']['count'],
                timeout = config['tracker']['discoveries']['arp']['timeout'],
                quit_on_first = config['tracker']['discoveries']['arp']['quit_on_first'],
                enabled = config['tracker']['do_arp']
            )
        except KeyError: pass
        try:
            config['tracker']['syn'] = tracker.discoveries.SYNDiscovery(
                ports = config['tracker']['discoveries']['syn']['ports'],
                timeout = config['tracker']['discoveries']['syn']['timeout'],
                enabled = config['tracker']['do_syn']
            )
        except KeyError: pass
        try:
            del config['tracker']['discoveries']
            cached = dict(config['tracker'])
            for key in cached:
                if key.startswith('do_'):
                    del config['tracker'][key]
        except KeyError: pass
    return config


@asyncio.coroutine
def tiny_cli(globals, locals):
    import async_stdio
    while True:
        inp = yield from async_stdio.async_input('$ ')
        if inp in ('q', 'exit', 'quit'):
            break
        try:
            exec(inp, globals, locals)
        except Exception as exc:
            print("ERROR.")
            print(exc)
    logger.warning("tBB close requested by user input ({}).".format(inp))
    loop.stop()


def main(args):
    silent = False
    if '--silent' in args:
        silent = True
        def write(*args, **kwargs):
            pass
        sys.stdout.write = write
    config = read_configuration_file(
        os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.json"))
    )
    configure_logging(config, silent)
    logger.warning(" === tBB started ===  args: {}".format(args))  # warnings are sent to syslog
    try:
        del args[args.index('--silent')]
    except: pass
    if '--help' in args:
        print((
            "\n"
            "{}\n"
            "\n"
            "Usage:\n"
            "    tBB [OPTIONS] networkIp: opens tBB and monitors network 'networkIp'.\n"
            "    tBB [OPTIONS]: opens tBB and monitors network specified in the configuration\n"
            "                   file. If no configuration file is found or the default\n"
            "                   network is not set, tBB will ask for a network IP in the\n"
            "                   command prompt.\n"
            "\n"
            "Options:\n"
            "    --help: show this message and exit.\n"
            "    --verbose: display information about host connecting/disconnecting and\n"
            "               other information that would not be normally displayed.\n"
            "    --debug: display debug information. Implicitly shows --verbose information.\n"
            "    --silent: display nothing.\n"
            "    --no-arp: don't run ARP discoveries.\n"
            "    --no-icmp: don't run ICMP discoveries.\n"
            "    --no-syn: don't run SYN discoveries.\n").format(__doc__.strip()))
        # TODO: implement --no-*
        return
    if '--verbose' in args:
        logger.setLevel(logging.INFO)
        del args[args.index('--verbose')]
    if '--debug' in args:
        logger.setLevel(logging.DEBUG)
        del args[args.index('--debug')]
    print((" === tBB - The Big Brother ===\n"
           "Started at: {}\n").format(datetime.datetime.strftime(datetime.datetime.now(), default_time_format)))
    # remove all option arguments before reading requested network
    if len(args) > 0:
        netip = args[0]
    else:
        try:
            netip = config['networkIp']
        except KeyError:  # config not found or 'networkIp' not set
            netip = input("Please, specify a network to monitor: ")
    try:
        net = Network(netip)
    except ValueError:  # invalid network input
        print("Cannot start tBB: '{}' is not a valid network address.".format(netip))
        logger.critical("tBB closed due to incorrect network address ({}).", netip)
        return
    # print("Loading notifiers... ", end='')
    # load_notifiers()
    # print("{} notifiers found.".format(len(notifiers)))
    # print("Opening port for frontends... ", end='')
    # open_frontend_port()
    # print("port = {}".format(port))
    # print("Opening database... ", end='')
    # connect_to_database()
    # print("database size = {}.".format(db_size))
    # if not silent:
    #     if db_empty:
    #         print("First network map on record.")
    #     else:
    #         print("Loading network map on record... ", end='')
    #         load_record()
    #         print("last updated: {} ({} ago).".format(db_last_updated, db_last_updated_ago))
    # print("Running initial scan... ", end='')
    # initial_scan()
    # print("{}/{} hosts up.".format(up_hosts, len(net)))
    logger.info("Monitoring network {}.".format(net))
    logger.info("No previous network scans found on record. Running initial check...")  # TODO: requires serialization
    track = tracker.Tracker(net)
    configure_tracker(track, config)
    enable_notifiers = track.enable_notifiers
    track.enable_notifiers = False  # disabling notifiers for initial check
    # tasks = []
    # start = 1
    # hosts = 16
    # while start < len(net):
    #     tasks.append(asyncio.async(track.do_partial_scan(start, hosts)))
    #     start += hosts
    tasks = asyncio.async(track.do_complete_network_scan())
    start = datetime.datetime.now()
    try:
        up = loop.run_until_complete(tasks)
    except KeyboardInterrupt:
        user_quit(tasks)
    else:
        took = datetime.datetime.now() - start
        track.enable_notifiers = enable_notifiers
        logger.info("Initial check done. {}/{} hosts up. Took {}.".format(up, len(net), took))
        print("\nThe Big Brother is watching.\n")
        tasks = [
            track.keep_network_tracked(initial_sleep=0)
        ]
        if not silent:
            tasks.append(tiny_cli(globals(), locals()))
        tasks = asyncio.gather(*tasks)
        try:
            loop.run_until_complete(tasks)
        except KeyboardInterrupt:
            user_quit(tasks)
        except RuntimeError:
            pass  # loop stopped before Futures completed.
        finally:
            loop.close()
    finally:
        loop.close()


def user_quit(tasks):
    print("\n")
    logger.warning("tBB close requested by user input (Ctrl-C).")
    tasks.cancel()
    loop.run_forever()
    tasks.exception()


if __name__ == '__main__':
    main(sys.argv[1:])
    if loop.is_running():
        loop.stop()
    if not loop.is_closed():
        loop.close()
    logger.warning("  --- tBB closing ---")
