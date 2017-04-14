#!/usr/bin/python3
#
# tBB is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# tBB is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""

|tBB - The Big Brother.
|Network analysis tool: keeps track of connections, disconnections
and changes in the specified network.
|For further information open tBB/docs/.

"""
import argparse
import os
import socket
import sys
import datetime
import logging
import logging.config
import logging.handlers
import json
import asyncio
import collections

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import paths
import tracker
import serialization
import frontends
from net_elements import *
from builtin_configuration import builtin


loop = asyncio.get_event_loop()


original_stdout = sys.stdout.write


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def configure_logging(settings):
    # Fill in default time format
    for formatter in settings.formatters.value.values():
        if formatter.datefmt.value == '{default_time_format}':
            formatter.datefmt.value = settings.default_time_format.value
    # Create configuration dictionary compliant with logging's dictConfig
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'complete': {
                'format': settings.formatters.complete.format.value,
                'datefmt': settings.formatters.complete.datefmt.value,
            },
            'brief': {
                'format': settings.formatters.brief.format.value,
                'datefmt': settings.formatters.brief.datefmt.value,
            },
            'syslog': {
                'format': settings.formatters.syslog.format.value,
                'datefmt': settings.formatters.syslog.datefmt.value,
            },
            'custom_1': {
                'format': settings.formatters.custom_1.format.value,
                'datefmt': settings.formatters.custom_1.datefmt.value,
            },
            'custom_2': {
                'format': settings.formatters.custom_2.format.value,
                'datefmt': settings.formatters.custom_2.datefmt.value,
            },
            'custom_3': {
                'format': settings.formatters.custom_3.format.value,
                'datefmt': settings.formatters.custom_3.datefmt.value,
            },
        },
        'handlers': {
            'console': {
                'level': settings.handlers.console.level.value,
                'class': 'logging.StreamHandler',
                'formatter': settings.handlers.console.formatter.value,
            },
            'syslog': {
                'level': settings.handlers.syslog.level.value,
                'class': 'logging.handlers.SysLogHandler',
                'formatter': settings.handlers.syslog.formatter.value,
                'address': {'ip': settings.handlers.syslog.address.ip.value,
                            'port': settings.handlers.syslog.address.port.value},
                'socktype': 'ext://socket.SOCK_STREAM' if settings.handlers.syslog.socktype.value
                            == 'STREAM' else 'ext://socket.SOCK_DGRAM',
                'facility': 'logging.handlers.SysLogHandler.LOG_DAEMON',
            },
            'file': {
                'level': settings.handlers.file.level.value,
                'class': 'logging.handlers.RotatingFileHandler',
                'formatter': settings.handlers.file.formatter.value,
                'maxBytes': settings.handlers.file.max_bytes.value,
                'backupCount': settings.handlers.file.backup_count.value,
                'filename': settings.handlers.file.filename.value,
            },
        },
        'loggers': {
            '': {
                'handlers': settings.handlers.enable.value,
                'level': settings.level.value,
                'propagate': True
            }
        }
    }
    # Set up logging configuration
    logging.config.dictConfig(logging_config)


@asyncio.coroutine
def developer_cli(globals_, locals_):
    sys.stdout.write = original_stdout  # prevent complete stdout blocking from silent mode
    del logging._handlers['console']
    import async_stdio
    import traceback
    print("  ===  Opening console for developer mode.  ===\n"
          "||WARNING||: do not use this console unless you know "
          "what you're doing and do not use developer mode in "
          "a production environment!\n"
          "!!! Usage of this mode might cause security issues !!!")
    while True:
        inp = yield from async_stdio.async_input('developer$ ')
        if inp in ('q', 'exit', 'quit'):
            break
        try:
            exec(inp, globals_, locals_)
        except:
            print("ERROR.")
            traceback.print_exc()
    logger.warning("tBB close requested by user input ({}).".format(inp))
    loop.stop()


def main(args):
    # Check paths and permissions
    try:
        paths.check_required_paths()
    except Exception as exc:
        logger.exception("Couldn't create required folders for tBB. "
                         "Cannot start tBB. Here's full exception.")
        return
    if os.geteuid() != 0:
        logger.critical("tBB requires root privileges to be run.")
        return
    password_file_path = os.path.join(paths.root, 'tBB_access_password')
    if not os.path.exists(password_file_path):
        logger.critical("Couldn't find password file!!! Aborting.")
        return
    password_file_mode = oct(os.stat(password_file_path).st_mode)[-3:]
    if password_file_mode != '600':
        logger.critical("password file has invalid permissions: {}.".format(password_file_mode))
        return
    # Parse network console argument
    try:
        net = Network(args.network)
    except (TypeError, ValueError):
        print('Invalid network \'{}\'. Aborting.'.format(args.network))
        return
    # Read builtin configuration
    settings = builtin
    # Update to default configuration
    default_config_path = os.path.abspath(os.path.join(
        paths.configs, "config_default.json"))
    if os.path.isfile(default_config_path):
        with open(default_config_path, 'r') as f:
            settings.update(
                settings.parse(json.load(f)))
    # Update to network-specific configuration
    specific_config_path = os.path.abspath(os.path.join(
        paths.configs, "config_{}.json".format(
        serialization.path_for_network(net, saving_path='', suffix='')
    )))
    if os.path.isfile(specific_config_path):
        with open(specific_config_path, 'r') as f:
            settings.update(
                settings.parse(json.load(f)))
    # Set up logging
    configure_logging(settings.logging)

    logger.warning(" === tBB started ===  args: {}".format(args))  # warnings are usually sent to syslog
    if args.debug:
        logging._handlers['console'].setLevel(logging.DEBUG)
    if args.silent:
        silent = True
        def write(*args, **kwargs):
            pass
        sys.stdout.write = write
        logging._handlers['console'].setLevel(60)  # higher than critical -> silent
    print(" === tBB - The Big Brother ===\n"
          "Started at: {}\n".format(datetime.datetime.strftime(datetime.datetime.now(),
                                    settings.logging.default_time_format.value)))
    logger.info("Monitoring network {}.".format(net))
    least_record_update_seconds = settings.monitoring.least_record_update.value\
        .total_seconds()
    loaded_from_record = False
    if os.path.exists(serialization.path_for_network(net)):
        logger.info("Found scan on record. Loading...")
        ser = serialization.Serializer(network=net, config=settings.serialization)
        ser.load()
        track = ser.track
        loaded_from_record = True
        logger.info("Last update on record: {}.".format(sorted(ser.sessions)[-1][1].strftime(
            settings.logging.default_time_format.value)))
    else:
        logger.info("No previous network scans found on record.")
        track = tracker.TrackersHandler(net, settings.monitoring.hosts)
        ser = serialization.Serializer(network=net, track=track, config=settings.serialization)
        track.serializer = ser
    track.configure(config=settings.monitoring)
    track.warn_parsing_exception = args.warn_parsing
    with open(password_file_path, 'r') as f:
        password = f.read().strip()
    frontends_handler = frontends.FrontendsHandler(track,
                                                   password,
                                                   config=settings.frontends,
                                                   loop=loop)
    tasks = asyncio.async(frontends_handler.start())
    try:
        loop.run_until_complete(tasks)
    except KeyboardInterrupt:
        frontends_handler.close()
        user_quit(tasks)
        loop.close()
        return
    if not args.silent:
        track.force_notify = True  # do notify to screen
    do_complete_scan = True
    if loaded_from_record:
        try:
            if (datetime.datetime.now() - sorted(ser.sessions)[-1][1])\
                    .total_seconds() < least_record_update_seconds:
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
    except NameError:
        pass  # complete_scan not run -> 'up' not defined
    print("\nThe Big Brother is watching.\n")
    tasks = [
        track.keep_network_tracked(initial_sleep=True),
        ser.keep_saving(frequency=600)  # every 10 minutes
    ]
    if args.developer:
        tasks.append(developer_cli(globals(), locals()))
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
    args = argparse.ArgumentParser(prog='tBB', description=\
'''
tBB - The Big Brother.
An open-source Intrusion Detection System.
Keeps track of connections, disconnections
and changes in the specified network.
''')
    args.add_argument('-s', '--silent', help='run tBB in silent mode.',
                      action='store_true')
    args.add_argument('-d', '--debug', help='display debug information.',
                      action='store_true')
    args.add_argument('-e', '--developer', help='open a developer console '
                      '(even in silent mode). WARNING: do not allow this option '
                      ' in a production environment.',
                      action='store_true')
    args.add_argument('-w', '--warn-parsing', help='display parsing errors.',
                      action='store_true')
    args.add_argument('network', help='network to monitor.')
    args = args.parse_args()
    try:
        main(args)
    except KeyboardInterrupt:
        logger.warning("tBB close requested by user input (Ctrl-C).")
    if loop.is_running():
        loop.stop()
    if not loop.is_closed():
        loop.close()
    logger.warning("  --- tBB closing ---")
