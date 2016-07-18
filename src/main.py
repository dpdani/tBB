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
from net_elements import Network, Host


logger = logging.getLogger(__name__)
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
            'address': ("192.168.46.23", 1984),  #
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


def configure_logging(config_file):
    if config_file:
        if 'logging' in config_file:
            try:
                logging.config.dictConfig(config_file['logging'])
            except Exception:
                print(config_file)
                logger.warning("Couldn't use config file for logging.", exc_info=True)
            else:
                return
    logging.config.dictConfig(default_logging_config)


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
    return config


def main(args):
    config = read_configuration_file(
        os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.json"))
    )
    configure_logging(config)
    logger.warning(" === tBB started ===  args: {}".format(args))  # warnings are sent to syslog
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
            "               other stuff that would not be normally displayed.\n"
            "    --debug: display debug information. Implicitly shows --verbose information.\n"
            "    --silent: display nothing.\n"
            "    --no-arp: don't run ARP discoveries.\n"
            "    --no-icmp: don't run ICMP discoveries.\n"
            "    --no-syn: don't run SYN discoveries.\n").format(__doc__.strip()))
        # TODO: implement --no-*
        return
    silent = False
    if '--verbose' in args:
        logger.setLevel(logging.INFO)
        del args[args.index('--verbose')]
    if '--debug' in args:
        logger.setLevel(logging.DEBUG)
        del args[args.index('--debug')]
    if '--silent' in args:
        silent = True
        logger.setLevel(60)  # 60 > logging.CRITICAL
        silent = True
        del args[args.index('--silent')]
    if not silent: print((
        " === tBB - The Big Brother ===\n"
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
    # if not silent: print("Loading notifiers... ", end='')
    # load_notifiers()
    # if not silent: print("{} notifiers found.".format(len(notifiers)))
    # if not silent: print("Opening port for frontends... ", end='')
    # open_frontend_port()
    # if not silent: print("port = {}".format(port))
    # if not silent: print("Opening database... ", end='')
    # connect_to_database()
    # if not silent: print("database size = {}.".format(db_size))
    # if not silent:
    #     if db_empty:
    #         print("First network map on record.")
    #     else:
    #         print("Loading network map on record... ", end='')
    #         load_record()
    #         print("last updated: {} ({} ago).".format(db_last_updated, db_last_updated_ago))
    # if not silent: print("Running initial scan... ", end='')
    # initial_scan()
    # if not silent: print("{}/{} hosts up.".format(up_hosts, len(net)))
    logger.info("Monitoring network {}.".format(net))
    if not silent: print("\nThe Big Brother is watching.\n")


if __name__ == '__main__':
    main(sys.argv[1:])
    logger.warning("  --- tBB closing ---")