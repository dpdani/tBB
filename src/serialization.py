"""

Serialization module for tBB.

"""

import asyncio
import os
import json
import datetime
import logging
from concurrent.futures import ProcessPoolExecutor
import tracker
from net_elements import *


start_datetime = datetime.datetime.now()
default_saving_path = os.path.join(os.getcwd(), "scans")


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def path_for_network(network, saving_path=default_saving_path):
    return os.path.join(saving_path, network.as_string().replace('/', '\\') + '.tbbscan')


class Serializer(object):
    def __init__(self, network=None, path=None, track=None, out_indent=4, out_sort_keys=True,
                 sessions=[]):
        if network is not None:
            self.path = path_for_network(network)
        else:
            self.path = path
        self.out_indent = out_indent
        self.out_sort_keys = out_sort_keys
        self.track = track
        self.sessions = sessions
        self.last_save = datetime.datetime.fromtimestamp(0)

    def load(self):
        logger.debug("Loading scan from file {}.".format(self.path))
        net = Network(os.path.splitext(os.path.basename(self.path))[0].replace('\\', '/'))
        with open(self.path, 'r') as f:
            read = json.load(f)
        for session in read['SESSIONS']:
            self.sessions.append(
                (datetime.datetime.fromtimestamp(float(session)),
                 datetime.datetime.fromtimestamp(read['SESSIONS'][session]))
            )
        self.track = tracker.TrackersHandler(net, read['TRACKERS_HANDLER']['hosts'])
        self.track.serializer = self
        ignore_list = self.track.ignore
        for ignore in read['TRACKERS_HANDLER']['ignore']:
            if IPElement(ignore) not in ignore_list:
                ignore_list.append(IPElement(ignore))
        self.track.ignore = ignore_list
        ignore_list = self.track.ignore_mac
        for ignore in read['TRACKERS_HANDLER']['ignore_mac']:
            if MACElement(ignore) not in ignore_list:
                ignore_list.append(MACElement(ignore))
        self.track.ignore_mac = ignore_list
        for ip in read['IP_HOSTS']:
            host = self.track.ip_hosts[IPElement(ip)]
            host.last_check = datetime.datetime.fromtimestamp(read['IP_HOSTS'][ip]['last_check'])
            host.last_seen = datetime.datetime.fromtimestamp(read['IP_HOSTS'][ip]['last_seen'])
            for history_name in ('mac', 'is_up', 'discovery'):
                history_name += "_history"
                history = getattr(host, history_name)
                for entry in read['IP_HOSTS'][ip][history_name]:
                    decoded = datetime.datetime.fromtimestamp(float(entry))
                    history[decoded] = read['IP_HOSTS'][ip][history_name][entry]
        for mac in read['MAC_HOSTS']:
            try:
                host = self.track.mac_hosts[MACElement(mac)]
            except KeyError:
                host = MACHost(MACElement(mac))
            host.last_update = datetime.datetime.fromtimestamp(read['MAC_HOSTS'][mac]['last_update'])
            for entry in read['MAC_HOSTS'][mac]['history']:
                decoded = datetime.datetime.fromtimestamp(float(entry))
                decoded_ips = []
                for ip in read['MAC_HOSTS'][mac]['history'][entry]:
                    decoded_ips.append(IPElement(ip))
                host.history[decoded] = tuple(decoded_ips)
            self.track.trackers[0].mac_hosts[MACElement(mac)] = host  # putting every mac host in the first tracker
                                                                      # causes issues when comparing from last state in single tracker

    @asyncio.coroutine
    def save(self):
        yield from asyncio.get_event_loop().run_in_executor(ProcessPoolExecutor(max_workers=3), self._save)
        # self._save already sets self.last_save, but the executor prevents the change from being storedx
        self.last_save = datetime.datetime.now()

    def _save(self):
        logger.debug("Saving scan to file {}.".format(self.path))
        to_save = {
            "SESSIONS": {},
            "TRACKERS_HANDLER": {},
            "IP_HOSTS": {},
            "MAC_HOSTS": {},
        }
        for session in self.sessions:
            to_save['SESSIONS'][session[0].timestamp()] = session[1].timestamp()
        to_save['SESSIONS'][start_datetime.timestamp()] = datetime.datetime.now().timestamp()
        to_save['TRACKERS_HANDLER']['hosts'] = self.track.hosts
        to_save['TRACKERS_HANDLER']['ignore'] = []
        to_save['TRACKERS_HANDLER']['ignore_mac'] = []
        for ignore in self.track.ignore:
            if ignore not in to_save['TRACKERS_HANDLER']['ignore']:
                to_save['TRACKERS_HANDLER']['ignore'].append(ignore.as_string())
        for ignore in self.track.ignore_mac:
            if ignore not in to_save['TRACKERS_HANDLER']['ignore_mac']:
                to_save['TRACKERS_HANDLER']['ignore_mac'].append(ignore.mac)
        for ip_host in self.track.ip_hosts:
            host = self.track.ip_hosts[ip_host]
            to_save['IP_HOSTS'][ip_host.as_string()] = {
                'mac_history': {},
                'is_up_history': {},
                'discovery_history': {},
                'last_check': host.last_check.timestamp(),
                'last_seen': host.last_seen.timestamp()
            }
            for history_name in ('mac', 'is_up', 'discovery'):
                history_name += "_history"
                history = getattr(host, history_name)
                for entry in history:
                    encoded = entry.timestamp()
                    to_save['IP_HOSTS'][ip_host.as_string()][history_name][encoded] = history[entry]
        for mac_host in self.track.mac_hosts:
            host = self.track.mac_hosts[mac_host]
            to_save['MAC_HOSTS'][mac_host.mac] = {
                'history': {},
                'last_update': host.last_update.timestamp(),
            }
            for entry in host.history:
                encoded = str(entry.timestamp())
                encoded_ips = []
                for ip in host.history[entry]:
                    encoded_ips.append(ip.as_string())
                to_save['MAC_HOSTS'][MACElement(mac_host.mac)]['history'][encoded] = encoded_ips
        with open(self.path, 'w') as f:
            json.dump(to_save, f, indent=self.out_indent, sort_keys=self.out_sort_keys)
        self.last_save = datetime.datetime.now()

    @asyncio.coroutine
    def keep_saving(self, frequency):
        while asyncio.get_event_loop().is_running():
            if (datetime.datetime.now() - self.last_save).total_seconds() >= frequency:
                yield from self.save()
                logger.info("Automatic saving.")
            yield from asyncio.sleep(10)
