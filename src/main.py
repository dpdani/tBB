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
import serialization
import frontends
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


def configure_logging(config_file, silent, socket_port):
    if config_file:
        if 'logging' in config_file:
            try:
                if silent:
                    config_file['logging']['handlers']['console']['level'] = 60
                try:
                    if config_file['logging']['handlers']['syslog']['address'][1] == '{frontends_socket_port}':
                        config_file['logging']['handlers']['syslog']['address'] = \
                            (config_file['logging']['handlers']['syslog']['address'][0], socket_port)
                except KeyError:
                    logger.error("Error while reading syslog configuration. Got:", exc_info=True)
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
                if attr == "ignore":
                    ignore_list = track.ignore
                    for ignore in config['tracker']['ignore']:
                        ignore_list.append(ignore)
                    track.ignore = ignore_list
                elif attr == "ignore_mac":
                    ignore_list = track.ignore_mac
                    for ignore in config['tracker']['ignore_mac']:
                        ignore_list.append(ignore)
                    track.ignore_mac = ignore_list
                else:
                    setattr(track, attr, config['tracker'][attr])


def read_configuration_file(path):
    config = dict()
    if os.path.exists(path):
        with open(path, 'r') as f:
            read = f.read().replace('{default_time_format}', default_time_format)
        try:
            config = json.loads(read)
        except (ValueError, ImportError):
            logger.exception("Found configuration file at {}, but is malformed.".format(path, exc_info=True))
        else:
            logger.info("Found configuration file at {}.".format(path))
        try:
            config['logging']['handlers']['syslog']['address'] = \
                (config['logging']['handlers']['syslog']['address']['ip'],
                 config['logging']['handlers']['syslog']['address']['port'])
        except KeyError:
            logger.exception("Skipping syslog configuration: file malformed.")
        try:
            config['tracker']['time_between_checks'] = datetime.timedelta(
                minutes = config['tracker']['time_between_checks']['minutes'],
                seconds = config['tracker']['time_between_checks']['seconds'],
            )
        except KeyError:
            logger.exception("Skipping tracker.time_between_checks configuration: file malformed.")
        try:
            cached = config['tracker']['discoveries']
            config['tracker']['discoveries'] = []
            i = 0
            for disc in cached:
                if disc['type'] == 'icmp':
                    config['tracker']['discoveries'].append(
                        tracker.discoveries.ICMPDiscovery(
                            count = cached[i]['count'],
                            timeout = cached[i]['timeout'],
                            flood = cached[i]['flood'],
                            enabled = cached[i]['enabled']
                        )
                    )
                elif disc['type'] == 'syn':
                    config['tracker']['discoveries'].append(
                        tracker.discoveries.SYNDiscovery(
                            ports = cached[i]['ports'],
                            timeout = cached[i]['timeout'],
                            enabled = cached[i]['enabled']
                        )
                    )
                i += 1
        except KeyError:
            logger.exception("Skipping tracker.discoveries configuration: file malformed.")
        try:
            config['tracker']['arp'] = tracker.discoveries.ARPDiscovery(
                count = config['tracker']['arp']['count'],
                timeout = config['tracker']['arp']['timeout'],
                quit_on_first = config['tracker']['arp']['quit_on_first'],
                enabled = True
            )
        except KeyError:
            logger.exception("Skipping tracker.arp configuration: file malformed.")
        try:
            ignore_list = []
            for ignore in config['tracker']['ignore']:
                ignore_list.append(IPElement(ignore))
            config['tracker']['ignore'] = ignore_list
        except:
            logger.exception("Skipping tracker.ignore configuration: file malformed.")
        try:
            ignore_list = []
            for ignore in config['tracker']['ignore_mac']:
                ignore_list.append(MACElement(ignore))
            config['tracker']['ignore_mac'] = ignore_list
        except:
            logger.exception("Skipping tracker.ignore_mac configuration: file malformed.")
    return config


@asyncio.coroutine
def tiny_cli(globals, locals):
    import async_stdio
    import traceback
    while True:
        inp = yield from async_stdio.async_input('$ ')
        if inp in ('q', 'exit', 'quit'):
            break
        try:
            exec(inp, globals, locals)
        except Exception as exc:
            print("ERROR.")
            traceback.print_exc()
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
    try:
        port = frontends.FrontendsHandler.determine_port(
            host=config['frontends_socket']['host'],
            starting_port=config['frontends_socket']['port'],
            maximum_port_lookup=config['frontends_socket']['maximum_port_lookup']
        )
    except KeyError:
        logger.error("Couldn't find settings for frontends configuration. Using default configuration "
                     "(host: 'localhost', starting port: '1984', maximum port lookup: '20').", exc_info=True)
        port = frontends.FrontendsHandler.determine_port(
            host='localhost',
            starting_port=1984,
            maximum_port_lookup=20
        )
    except:
        logger.critical("Couldn't find appropriate port with given configuration: host: '{}', starting port: '{}', "
                        "maximum tries: '{}'. Got exception:".format(config['socket_host'], config['port'],
                                                                      config['maximum_port_lookup']),
                        exc_info=True
        )
        return
    configure_logging(config, silent, socket_port=port)
    logger.warning(" === tBB started ===  args: {}".format(args))  # warnings are usually sent to syslog
    if os.geteuid() != 0:
        logger.critical("tBB requires root privileges to be run.")
        return
    password_file_path = os.path.join(os.getcwd(), 'tBB_access_password')
    if not os.path.exists(password_file_path):
        logger.critical("couldn't find password file.")
        return
    password_file_mode = oct(os.stat(password_file_path).st_mode)[-3:]
    if password_file_mode != '600':
        logger.critical("password file has invalid permissions: {}.".format(password_file_mode))
        return
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
        logger.critical("tBB closed due to incorrect network address ({}).".format(netip))
        return
    try:
        least_record_update_seconds = config['least_record_update_seconds']
    except KeyError:
        least_record_update_seconds = 3600
    logger.info("Monitoring network {}.".format(net))
    loaded_from_record = False
    if os.path.exists(serialization.path_for_network(net)):
        logger.info("Found scan on record. Loading...")
        ser = serialization.Serializer(network=net)
        ser.load()
        track = ser.track
        loaded_from_record = True
        logger.info("Last update on record: {}.".format(sorted(ser.sessions)[-1][1].strftime(default_time_format)))
    else:
        logger.info("No previous network scans found on record.")
        hosts = 16
        try:
            hosts = config['tracker']['hosts']
        except KeyError:
            pass
        track = tracker.TrackersHandler(net, hosts)
        ser = serialization.Serializer(network=net, track=track)
        track.serializer = ser
    configure_tracker(track, config)
    with open(password_file_path, 'r') as f:
        password = f.read().strip()
    frontends_handler = frontends.FrontendsHandler(track, password,
                                                   host=config['frontends_socket']['host'],
                                                   port=port, loop=loop,
                                                   use_ssl=config['frontends_socket']['ssl'],
                                                   do_checks=config['frontends_socket']['do_checks'])
    tasks = asyncio.async(frontends_handler.start())
    try:
        loop.run_until_complete(tasks)
    except KeyboardInterrupt:
        frontends_handler.close()
        user_quit(tasks)
        loop.close()
        return
    if not silent:
        track.force_notify = True  # do notify to screen
    do_complete_scan = True
    if loaded_from_record:
        try:
            if (datetime.datetime.now() - sorted(ser.sessions)[-1][1]).total_seconds() < least_record_update_seconds:
                do_complete_scan = False
        except IndexError:
            print("indexerror")
    tasks = None
    if do_complete_scan:
        tasks = asyncio.async(track.do_complete_network_scan())
    start = datetime.datetime.now()
    try:
        if do_complete_scan:
            logger.info("Running complete network check...")
            up = loop.run_until_complete(tasks)
            loop.run_until_complete(ser.save())
    except KeyboardInterrupt:
        user_quit(tasks)
        loop.close()
        return
    took = datetime.datetime.now() - start
    track.force_notify = False
    try:
        logger.info("Initial check done. {}/{} hosts up. Took {}.".format(up, len(net), took))
    except NameError: pass  # complete_scan not run -> 'up' not defined
    print("\nThe Big Brother is watching.\n")
    tasks = [
        track.keep_network_tracked(initial_sleep=True),
        ser.keep_saving(frequency=600)  # every 10 minutes
    ]
    if not silent:
        tasks.append(tiny_cli(globals(), locals()))
    tasks = asyncio.gather(*tasks)
    try:
        loop.run_until_complete(tasks)
    except KeyboardInterrupt:
        user_quit(tasks)
        loop.close()
    except RuntimeError:
        pass  # loop stopped before Futures completed.
    finally:
        loop.close()


def user_quit(tasks):
    print("\n")
    logger.warning("tBB close requested by user input (Ctrl-C).")
    tasks.cancel()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    try:
        tasks.exception()
    except asyncio.CancelledError:
        pass
    except asyncio.InvalidStateError:  # no exceptions
        pass


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        logger.warning("tBB close requested by user input (Ctrl-C).")
    if loop.is_running():
        loop.stop()
    if not loop.is_closed():
        loop.close()
    logger.warning("  --- tBB closing ---")
