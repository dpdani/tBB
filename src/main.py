"""

tBB - The Big Brother.
Network analysis tool: keeps track of connections, disconnections
and changes in the specified network.
For further information open tBB/docs/.

"""
import os
import sys
import datetime
import logging
import logging.config
import logging.handlers
import json
from net_elements import Network, Host


default_time_format = "%d/%m/%Y-%I.%M.%S"

logger = logging.getLogger(__name__)
logging.config.dictConfig({
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
        # 'syslog': {
        #     'level': 'WARNING',
        #     'class': 'logging.handlers.SysLogHandler',
        #     'formatter': 'complete',
        #     'address': '("", logging.handlers.SYSLOG_UDP_PORT)',  # TODO: where is it?
        #     'facility': 'logging.handlers.SysLogHandler.LOG_SYSLOG',
        # },
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'complete',
            'maxBytes': 10000000,  # 10 Mb
            'backupCount': 4,  # occupies at most 50Mb for logs
            'filename': 'tBB.log'
        }
    },
    'loggers': {
        '': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True
        }
    }
})


def main(args):
    logging.info("tBB started with args {}".format(args))
    config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    config = None
    if os.path.exists(config_file_path):
        with open(config_file_path, 'r') as f:
            config = json.load(f)
        if len(config) > 0:
            logging.info("Found configuration file at {}.".format(config_file_path))
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
        "\n"
        " === tBB - The Big Brother ===\n"
        "Started at: {}\n\n").format(datetime.datetime.strftime(datetime.datetime.now(), default_time_format)))
    # remove all option arguments before reading requested network
    if len(args) > 0:
        netip = args[0]
    else:
        try:
            netip = config['networkIp']
        except (TypeError, KeyError):  # config not found or 'networkIp' not set
            netip = input("Please, specify a network to monitor: ")
    try:
        net = Network(netip)
    except ValueError:  # invalid network input
        print("Cannot start tBB: '{}' is not a valid network address.".format(netip))
        logging.info("tBB closed due to incorrect network address ({}).".format(netip))
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
    logging.info("Monitoring network {}.".format(net))
    print("\nThe Big Brother is watching.\n")


if __name__ == '__main__':
    main(sys.argv[1:])