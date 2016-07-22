"""

Tracker implementation.

"""

import asyncio
from asyncio import coroutine
import logging
import datetime
import random
from net_elements import Network, IPElement, IPHost, MACElement, MACHost, netmask_from_netlength
import discoveries


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Tracker(object):
    def __init__(self, network):
        if not isinstance(network, Network):
            raise TypeError("expected argument network to be a Network instance.")
        self.network = network
        self.ip_hosts = {}
        for ip in self.network:
            self.ip_hosts[ip] = IPHost(ip)
        self.priorities = {}  # IP: priority
        self.ignore = []  # IP
        self.mac_hosts = {}
        self.discoveries = [
            discoveries.DefaultICMPDiscovery,
            discoveries.DefaultSYNDiscovery
        ]
        self.arp = discoveries.DefaultARPDiscovery
        self.time_between_checks = datetime.timedelta(minutes=0, seconds=0)
        self.maximum_seconds_randomly_added = 0
        self.enable_notifiers = True
        self._outer_status = 'initialized'  # supply information to front-ends
        self._status = 'initialized'        #
        self.ignore_networks_and_broadcasts = True

    @property
    def up_hosts(self):
        up = 0
        for host in self.ip_hosts.values():
            if host.is_up:
                up += 1
        return up

    @property
    def status(self):
        """Used to supply information to front-ends."""
        return self._status

    @status.setter
    def status(self, value):
        self._status = value
        logger.debug(self._status)
        # tell front-ends about update here

    @property
    def outer_status(self):
        """Used to supply information to front-ends."""
        return self._outer_status

    @outer_status.setter
    def outer_status(self, value):
        self._outer_status = value
        logger.debug(self._outer_status)
        # tell front-ends about update here

    @property
    def average_network_iteration_time(self):
        """Average network check iteration time in seconds.
        Calculated based on network's length and set sleeping times
        between checks.
        :return type: float or int
        """
        enabled_discoveries = 0
        for discovery in self.discoveries:
            if discovery.enabled:
                enabled_discoveries += 1
        return len(self.network) * (self.time_between_checks.total_seconds() + self.maximum_seconds_randomly_added / 2) \
               * enabled_discoveries

    @coroutine
    def do_complete_network_scan(self):
        """Runs complete network scan.
        Similarly to Track.do_partial_scan, this does not
        use self.highest_priority_host internally; iterates
        over self.network instead.
        """
        logger.debug("Scanning entire network: {}.".format(self.network))
        self.outer_status = "Scanning entire network: {}.".format(self.network)
        up = 0
        syn_enabled = self.discoveries[1].enabled
        self.discoveries[1].enabled = False
        # tasks = []
        # start = 1
        # hosts = 16
        # while start < len(self.network):
        #     tasks.append(self.do_partial_scan(start, hosts))
        #     start += hosts
        # yield from asyncio.gather(*tasks)
        for ip in self.network:
            if self.ignore_networks_and_broadcasts:
                if ip.is_broadcast() and ip.is_network() and ip in self.ignore:
                    logger.debug("Ignoring: {}".format(ip))
                    continue
            else:
                if ip in self.ignore:
                    logger.debug("Ignoring: {}".format(ip))
                    continue
            if (yield from self.do_single_scan(ip)):
                up += 1
        self.discoveries[1].enabled = syn_enabled
        return up

    @coroutine
    def do_partial_scan(self, start, hosts):
        """Runs partial scan of the network.
        Starting from argument start for so many hosts as
        defined in argument hosts.
        Similarly to Track.do_complete_network_scan, this
        does not use self.highest_priority_host internally;
        iterates over self.network instead.
        :param start: integer to add to self.network to get first ip to scan.
        :type start: int
        :param hosts: number of ips to scan.
        :type hosts: int
        :return:
        """
        if type(start) != int or type(hosts) != int:
            raise TypeError("expected argument start and end to be of type int. Got: {} and {}.".format(
                type(start), type(hosts)
            ))
        ip = self.network + start
        logger.debug("Scanning network from {} for {} hosts.".format(ip, hosts))
        self.outer_status = "Scanning network '{}' from {} for {} hosts.".format(self.network, ip, hosts)
        up = 0
        for _ in range(hosts - start):
            if self.ignore_networks_and_broadcasts:
                if ip.is_broadcast() and ip.is_network() and ip in self.ignore:
                    logger.debug("Ignoring: {}".format(ip))
                    continue
            else:
                if ip in self.ignore:
                    logger.debug("Ignoring: {}".format(ip))
                    continue
            if (yield from self.do_single_scan(ip)):
                up += 1
            ip += 1
        return up

    @coroutine
    def do_single_scan(self, ip):
        """Runs a scan to the specified ip.
        Uses discovery methods self.icmp, self.arp and self.syn.
        You can enable/disable each one of them setting Tracker.do_*.
        This function takes care of detecting whether the host changed
        its status and if so it calls self.fire_notifiers.
        If one discovery method results positive others won't be run.
        Note: in order to provide the mac address of the scanning host,
        ARP will be run even if self.do_arp is set to false, but it
        won't be tracked as the discovery method used when executed
        for this purpose.
        Returns whether or not the host was found to be up.
        :param ip: ip to scan.
        :type ip: IPElement()
        :return: bool
        """
        if not isinstance(ip, IPElement):
            raise TypeError("expected argument ip to be an IPElement instance. Got: {}.".format(ip))
        if ip not in self.ip_hosts.keys():
            logger.error("asked to scan '{}', but couldn't locate it in self.ip_hosts.".format(ip))
            raise RuntimeError("could not internally locate host '{}'.".format(ip))
        logger.debug("scanning ip '{}'. {} since last scan.".format(ip, self.ip_hosts[ip].ago))
        method = None
        is_up = False
        self.status = "scanning ip '{}' - running mac discovery.".format(ip)
        mac = (yield from self.arp.run(ip))[1]
        for discovery in self.discoveries:
            if discovery.enabled:
                self.status = "scanning ip '{}' - running {}.".format(ip, discovery.short_name)
                method = discovery.short_name
                try:
                    is_up = yield from discovery.run(ip)
                except discoveries.PingedBroadcast:
                    return False
                if is_up:
                    break
                else:
                    method = None
        self.status = "scanning ip '{}' - finishing.".format(ip)
        ip_changed = self.ip_hosts[ip].update(mac, method, is_up)
        try:
            if mac is not None:
                mac_changed = self.mac_hosts[MACElement(mac)].update(ip, is_up)
            elif self.ip_hosts[ip].mac is not None and mac is None:  # mac went down
                mac = self.ip_hosts[ip].mac
                mac_changed = self.mac_hosts[MACElement(mac)].update(ip, is_up)
            else:
                mac_changed = False
        except KeyError:
            host = MACHost(MACElement(mac))
            mac_changed = host.update(ip, is_up)
            self.mac_hosts[MACElement(mac)] = host
        if ip_changed or mac_changed:
            self.fire_notifiers(ip, mac, method, is_up)
        return is_up

    @coroutine
    def keep_network_tracked(self, initial_sleep=0):
        """Keeps the given network (self.network) tracked.
        Differently from Tracker.do_complete_network_scan and
        Tracker.do_partial_scan, this function doesn't iterate
        over self.network to keep it tracked. Instead it calls
        self.highest_priority_host each time it has to scan a
        new host.
        Again, differently from Tracker.do_complete_network_scan
        and Tracker.do_partial_scan, this function implements a
        sleeping mechanisms between scans in order to reduce its
        weight on the network. The time it takes for sleeping
        can be set using Track.time_between_scans and Track.\
        maximum_seconds_randomly_added calculated as follows:
          sleep = time_between_scans + randint(0, maximum_seconds_randomly_added)
        randint being the random.randint function included in
        the Python's standard library.
        """
        self.outer_status = "Keeping network tracked."
        yield from asyncio.sleep(initial_sleep)
        host = self.highest_priority_host()
        while True:
            try:
                yield from self.do_single_scan(host)
            except discoveries.ParsingException as exc:
                logger.error("Error while parsing: {}".format(exc))
            sleep_for = self.time_between_checks.total_seconds() + random.randint(0, self.maximum_seconds_randomly_added)
            host = self.highest_priority_host()
            self.status = "sleeping for {} seconds. next ip to scan: {}.".format(sleep_for, host)
            yield from asyncio.sleep(sleep_for)

    def highest_priority_host(self):
        """Returns the host that has the highest priority
        in this moment.
        The calculation is made so that there can be no hosts
        with the same priority.
        It takes in account per-host set priorities in self.priorities.
        The calculation is done as follows:
          priority = host_priority + time_since_last_check|IP
        As shown, the IP added at the end prevents two hosts
        from having the same priority.
        Seen how the calculation is performed, priorities set in
        self.priorities should consider that if, for instance,
        the priority for host A is set to 10, every call within 10
        seconds since last scan will return host A.
        :return type: IPElement
        """
        self.status = 'calculating highest priority host.'
        priorities = {}  # priority: IP
        for host in self.ip_hosts.values():
            if self.ignore_networks_and_broadcasts:
                if host._ip.is_broadcast() and host._ip.is_network() and host._ip in self.ignore:
                    logger.debug("Ignoring: {}".format(host._ip))
                    continue
            else:
                if host._ip in self.ignore:
                    logger.debug("Ignoring: {}".format(host._ip))
                    continue
            if host._ip in self.priorities:
                priorities[
                    (self.priorities[host._ip] + int(host.ago.total_seconds())) * 10**12 + host._ip.as_int()
                ] = host._ip
            else:
                priorities[
                    int(host.ago.total_seconds()) * 10 ** 12 + host._ip.as_int()
                ] = host._ip
        return priorities[max(priorities)]

    def fire_notifiers(self, ip, mac, method, is_up):
        logger.info("{}@{} changed status. method: {}, is_up: {}.".format(ip, mac, method, is_up))
        if self.enable_notifiers:
            print("FIRING NOTIFIERS.")


class TrackersHandler(object):
    def __init__(self, network, hosts=16):
        self.network = network
        self.trackers = []
        start = 0
        while start < len(self.network):
            ip = self.network + start
            ip.mask = netmask_from_netlength(hosts)
            if self.network.broadcast() < ip + hosts:
                net = Network(ip)
                net.forced_length = len(self.network) - start - 1  # using forced_length, last ip would be next network
                tr = Tracker(net)
            else:
                tr = Tracker(Network(ip))
            tr.ignore_networks_and_broadcasts = False  # sub-networks broadcasts are not real broadcasts
            if sorted(tr.ip_hosts.keys())[-1].ip[0] == self.network.broadcast().ip[0]:
                # since broadcasts ignoring is inhibited by default, manually ignore real broadcast
                tr.ignore.append(sorted(tr.ip_hosts.keys())[-1])
            self.trackers.append(tr)
            start += hosts

    @property
    def enable_notifiers(self):
        return [tr.enable_notifiers for tr in self.trackers]

    @enable_notifiers.setter
    def enable_notifiers(self, value):
        for tr in self.trackers:
            tr.enable_notifiers = value

    @property
    def status(self):
        return [tr.status for tr in self.trackers]

    @status.setter
    def status(self, value):
        for tr in self.trackers:
            tr.status = value

    @property
    def outer_status(self):
        return [tr.outer_status for tr in self.trackers]

    @outer_status.setter
    def outer_status(self, value):
        for tr in self.trackers:
            tr.outer_status = value

    @property
    def time_between_checks(self):
        return [tr.time_between_checks for tr in self.trackers]

    @time_between_checks.setter
    def time_between_checks(self, value):
        for tr in self.trackers:
            tr.time_between_checks = value

    @property
    def maximum_seconds_randomly_added(self):
        return [tr.maximum_seconds_randomly_added for tr in self.trackers]

    @maximum_seconds_randomly_added.setter
    def maximum_seconds_randomly_added(self, value):
        for tr in self.trackers:
            tr.maximum_seconds_randomly_added = value

    @property
    def ip_hosts(self):
        ip_hosts = {}
        for tr in self.trackers:
            for ip_host in tr.ip_hosts:
                ip = IPElement(ip=ip_host._ip[0], mask=self.network.mask)
                ip_hosts.update({ip: tr.ip_hosts[ip_host]})
        return ip_hosts

    @property
    def mac_hosts(self):
        mac_hosts = {}
        for tr in self.trackers:
            for mac_host in tr.mac_hosts:
                mac_hosts.update({mac_host: tr.ip_hosts[mac_host]})
        return mac_hosts

    @property
    def discoveries(self):
        return [tr.discoveries for tr in self.trackers]

    @discoveries.setter
    def discoveries(self, value):
        for tr in self.trackers:
            tr.discoveries = value

    @property
    def arp(self):
        return [tr.arp for tr in self.trackers]

    @arp.setter
    def arp(self, value):
        for tr in self.trackers:
            tr.arp = value

    @coroutine
    def keep_network_tracked(self, initial_sleep=False):
        tasks = []
        i = 0
        for tr in self.trackers:
            tasks.append(tr.keep_network_tracked(initial_sleep=i))
            if initial_sleep:
                i += 2
        yield from asyncio.gather(*tasks)

    @coroutine
    def do_complete_network_scan(self):
        tasks = []
        for tr in self.trackers:
            tasks.append(tr.do_complete_network_scan())
        ups = yield from asyncio.gather(*tasks)
        return sum(ups)

# track.time_between_checks = datetime.timedelta(minutes=0, seconds=1); track.maximum_seconds_randomly_added = 1
# track.ip_hosts[IPElement("192.168.2.45/23")].print_histories()
# track.mac_hosts[MACElement("A4:5E:60:D2:8D:E5")].print_histories()
# for tr in track.trackers: print(tr.network, tr.status)
# print(track.time_between_checks)
