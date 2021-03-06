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

Serialization module for tBB.

"""

import asyncio
import os
import json
import datetime
import time
import logging
from concurrent.futures import ProcessPoolExecutor
import paths
import tracker
from net_elements import *


start_datetime = datetime.datetime.now()


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def path_for_network(network, saving_path=paths.scans, suffix='.tbbscan'):
    return os.path.join(saving_path, network.as_string().replace('/', '\\') + suffix)


class Serializer(object):
    def __init__(self, network=None, path=None, track=None, config=None, sessions=[]):
        if network is not None:
            self.path = path_for_network(network)
        else:
            self.path = path
        self.out_indent = config.indent.value
        self.out_sort_keys = config.do_sort.value
        self.track = track
        self.sessions = sessions
        self.last_save = datetime.datetime.fromtimestamp(0)
        self.saving = False  # is this Serializer saving to file?

    def load(self):
        start = time.time()
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
        ignore_list = self.track.ignore_name
        for ignore in read['TRACKERS_HANDLER']['ignore_name']:
            if ignore not in ignore_list:
                ignore_list.append(ignore)
        self.track.ignore_mac = ignore_list
        priorities = self.track.priorities
        for ip in read['TRACKERS_HANDLER']['priorities']:
            if read['TRACKERS_HANDLER']['priorities'][ip] != 0:
                priorities.update({IPElement(ip): read['TRACKERS_HANDLER']['priorities'][ip]})
        self.track.priorities = priorities
        for ip in read['IP_HOSTS']:
            host = self.track.ip_hosts[IPElement(ip)]
            host.last_check = datetime.datetime.fromtimestamp(read['IP_HOSTS'][ip]['last_check'])
            host.last_seen = datetime.datetime.fromtimestamp(read['IP_HOSTS'][ip]['last_seen'])
            for history_name in ('mac', 'is_up', 'discovery', 'name'):
                history_name += "_history"
                history = getattr(host, history_name)
                for entry in read['IP_HOSTS'][ip][history_name]:
                    decoded = datetime.datetime.fromtimestamp(float(entry))
                    history[decoded] = read['IP_HOSTS'][ip][history_name][entry]
                    if history_name == 'name_history':
                        # print("name_history")
                        # print(history[decoded])
                        history[decoded] = tuple(history[decoded])
                        # print(history[decoded])
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
            self.track.trackers[0].mac_hosts[MACElement(mac)] = host
        for name in read['NAME_HOSTS']:
            try:
                host = self.track.name_hosts[name]
            except KeyError:
                host = NameHost(name)
            host.last_update = datetime.datetime.fromtimestamp(read['NAME_HOSTS'][name]['last_update'])
            for entry in read['NAME_HOSTS'][name]['history']:
                decoded = datetime.datetime.fromtimestamp(float(entry))
                decoded_ips = []
                for ip in read['NAME_HOSTS'][name]['history'][entry]:
                    decoded_ips.append(IPElement(ip))
                host.history[decoded] = tuple(decoded_ips)
            self.track.trackers[0].name_hosts[name] = host
        logger.debug("Loading took {:.3f} seconds.".format(time.time() - start))

    @asyncio.coroutine
    def save(self):
        yield from asyncio.get_event_loop().run_in_executor(ProcessPoolExecutor(max_workers=3), self._save)
        # self._save already sets self.last_save, but the executor prevents the change from being stored
        self.last_save = datetime.datetime.now()

    def _save(self):
        if self.saving:
            logger.debug('skipping saving due to pending operation.')
            return
        self.saving = True
        start = time.time()
        logger.debug("Saving scan to file {}.".format(self.path))
        to_save = {
            "SESSIONS": {},
            "TRACKERS_HANDLER": {},
            "IP_HOSTS": {},
            "MAC_HOSTS": {},
            "NAME_HOSTS": {},
        }
        for session in self.sessions:
            to_save['SESSIONS'][session[0].timestamp()] = session[1].timestamp()
        to_save['SESSIONS'][start_datetime.timestamp()] = datetime.datetime.now().timestamp()
        to_save['TRACKERS_HANDLER']['hosts'] = self.track.hosts
        to_save['TRACKERS_HANDLER']['ignore'] = []
        to_save['TRACKERS_HANDLER']['ignore_mac'] = []
        to_save['TRACKERS_HANDLER']['ignore_name'] = []
        to_save['TRACKERS_HANDLER']['priorities'] = {}
        for ignore in self.track.ignore:
            if ignore.as_string() not in to_save['TRACKERS_HANDLER']['ignore']:
                to_save['TRACKERS_HANDLER']['ignore'].append(ignore.as_string())
        for ignore in self.track.ignore_mac:
            if ignore.mac not in to_save['TRACKERS_HANDLER']['ignore_mac']:
                to_save['TRACKERS_HANDLER']['ignore_mac'].append(ignore.mac)
        for ignore in self.track.ignore_name:
            if ignore not in to_save['TRACKERS_HANDLER']['ignore_name']:
                to_save['TRACKERS_HANDLER']['ignore_name'].append(ignore)
        for ip in self.track.priorities:
            if self.track.priorities[ip] != 0:
                to_save['TRACKERS_HANDLER']['priorities'].update({ip.as_string(): self.track.priorities[ip]})
        for ip_host in self.track.ip_hosts:
            host = self.track.ip_hosts[ip_host]
            to_save['IP_HOSTS'][ip_host.as_string()] = {
                'mac_history': {},
                'is_up_history': {},
                'discovery_history': {},
                'name_history': {},
                'last_check': host.last_check.timestamp(),
                'last_seen': host.last_seen.timestamp()
            }
            for history_name in ('mac', 'is_up', 'discovery', 'name'):
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
        for name_host in self.track.name_hosts:
            host = self.track.name_hosts[name_host]
            to_save['NAME_HOSTS'][name_host] = {
                'history': {},
                'last_update': host.last_update.timestamp(),
            }
            if host.name == 'empty-name':
                # this name usually takes up a lot of space for some very useless
                # information, so let's only save the latest status for 'empty-name'.
                ips = []
                for ip in host.history[sorted(host.history)[-1]]:
                    ips.append(ip.as_string())
                to_save['NAME_HOSTS']['empty-name']['history'][str(sorted(host.history)[-1].timestamp())] = ips
                continue
            for entry in host.history:
                encoded = str(entry.timestamp())
                encoded_ips = []
                for ip in host.history[entry]:
                    encoded_ips.append(ip.as_string())
                to_save['NAME_HOSTS'][name_host]['history'][encoded] = encoded_ips
        with open(self.path, 'w') as f:
            json.dump(to_save, f, indent=self.out_indent, sort_keys=self.out_sort_keys)
        self.saving = False
        self.last_save = datetime.datetime.now()
        logger.debug("Saving took {:.3f} seconds.".format(time.time() - start))

    @asyncio.coroutine
    def keep_saving(self, frequency):
        while asyncio.get_event_loop().is_running():
            if (datetime.datetime.now() - self.last_save).total_seconds() >= frequency:
                yield from self.save()
                logger.info("Automatic saving.")
            yield from asyncio.sleep(10)
