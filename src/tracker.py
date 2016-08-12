"""

Tracker implementation.

"""

import asyncio
from asyncio import coroutine
import logging
import datetime
import random
from net_elements import Network, IPElement, IPHost, MACElement, MACHost, NameHost, netmask_from_netlength
import discoveries

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Tracker(object):
    def __init__(self, network):
        if not isinstance(network, Network):
            raise TypeError("expected argument network to be a Network instance.")
        self.network = network
        self.mac_hosts = {}  # MACElement: MACHost
        self.name_hosts = {}  # str: NameHost
        self.ip_hosts = {}  # IPElement: IPHost
        for ip in self.network:
            self.ip_hosts[ip] = IPHost(ip)
        self.priorities = {}  # IP: priority
        self.ignore = []  # IP
        self.ignore_mac = []
        self.ignore_name = []  # str
        self.discoveries = [
            discoveries.DefaultICMPDiscovery,
            discoveries.DefaultSYNDiscovery
        ]
        self.arp = discoveries.DefaultARPDiscovery
        self.name_discovery = discoveries.HostNameDiscovery()
        self.time_between_checks = datetime.timedelta(minutes=0, seconds=0)
        self.maximum_seconds_randomly_added = 0
        self._outer_status = 'initialized'  # supply information to front-ends
        self._status = 'initialized'  #
        self.ignore_networks_and_broadcasts = True
        self.serializer = None
        self.force_notify = False
        self.auto_ignore_broadcasts = True
        self.warn_parsing_exception = True

    @property
    def up_hosts(self):
        """Number of IP hosts currently up."""
        up = 0
        for host in self.ip_hosts.values():
            if host.is_up:
                up += 1
        return up

    @property
    def up_ip_hosts(self):
        """IPHosts currently up. Result is a dictionary {IPElement: IPHost}."""
        up_ip_hosts = {}
        for host in self.ip_hosts:
            if self.ip_hosts[host].is_up:
                up_ip_hosts[host] = self.ip_hosts[host]
        return up_ip_hosts

    @property
    def up_mac_hosts(self):
        """MACHosts currently up. Result is a dictionary {MACElement: MACHost}.
        Determining how a MACHost is up is a little bit different
        from an IPHost. Since a MACHost doesn't hold any up state,
        a MACHost is considered up when any of the IPHosts related
        to it (found in MACHost.ip) is up. Therefore even if only
        one of the (possibly) many IPHosts is up, the MACHost is
        considered up."""
        up_mac_hosts = {}
        for host in self.mac_hosts.values():
            for ip in host.ip:
                if ip not in self.ip_hosts:  # IP not found in this tracker, skipping...
                    continue
                if self.ip_hosts[ip].is_up:
                    up_mac_hosts[host.mac] = self.mac_hosts[host.mac]
                    break  # at first ip found up, the MACHost is considered up.
        return up_mac_hosts

    @property
    def up_name_hosts(self):
        """Similar to Tracker.up_mac_hosts."""
        up_name_hosts = {}
        for host in self.name_hosts.values():
            for ip in host.ip:
                if ip not in self.ip_hosts:  # IP not found in this tracker, skipping...
                    continue
                if self.ip_hosts[ip].is_up:
                    up_name_hosts[host.name] = self.name_hosts[host.name]
                    break  # at first ip found up, the NameHost is considered up.
        return up_name_hosts

    @property
    def status(self):
        """Used to supply information to front-ends."""
        return self._status

    @status.setter
    def status(self, value):
        """Used to supply information to front-ends. Setting will trigger logging (DEBUG)."""
        self._status = value
        logger.debug(self._status)
        # tell front-ends about update here

    @property
    def outer_status(self):
        """Used to supply information to front-ends."""
        return self._outer_status

    @outer_status.setter
    def outer_status(self, value):
        """Used to supply information to front-ends. Setting will trigger logging (DEBUG)."""
        self._outer_status = value
        logger.debug(self._outer_status)
        # tell front-ends about update here

    @coroutine
    def do_complete_network_scan(self):
        """Runs complete network scan.
        Similarly to Track.do_partial_scan, this does not
        use self.highest_priority_host internally; iterates
        over self.network instead.
        """
        self.outer_status = "Scanning entire network: {}.".format(self.network)
        logger.debug(self.outer_status)
        ser = self.serializer  # disconnecting serializer for complete scan.
        self.serializer = None  #
        up = 0
        for ip in self.network:
            if self.ignore_networks_and_broadcasts:
                if ip.is_broadcast() or ip.is_network():
                    logger.debug("Ignoring: {}".format(ip))
                    continue
            if ip in self.ignore:
                logger.debug("Ignoring (found in self.ignore): {}".format(ip))
                continue
            try:
                if (yield from self.do_single_scan(ip)):
                    up += 1
            except discoveries.ParsingException as exc:
                if self.warn_parsing_exception:
                    logger.error("Error while parsing: {}".format(exc))
                else:
                    logger.debug("Error while parsing: {}".format(exc))
        self.serializer = ser  # reconnecting serializer
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
                if ip.is_broadcast() or ip.is_network():
                    logger.debug("Ignoring: {}".format(ip))
                    continue
            if ip in self.ignore:
                logger.debug("Ignoring (found in self.ignore): {}".format(ip))
                continue
            try:
                if (yield from self.do_single_scan(ip)):
                    up += 1
            except discoveries.ParsingException as exc:
                if self.warn_parsing_exception:
                    logger.error("Error while parsing: {}".format(exc))
                else:
                    logger.debug("Error while parsing: {}".format(exc))
            ip += 1
        return up

    @coroutine
    def do_single_scan(self, ip):
        """Runs a scan to the specified ip.
        Uses discovery methods found in self.discoveries.
        You can enable/disable each one of them by setting
        self.discoveries[x].enable to whatever suits you.
        This function takes care of detecting whether the host changed
        its status and if so it calls self.fire_notifiers.
        If one discovery method results positive others won't be run.
        Note: in order to provide the mac address of the scanning host,
        ARP will be run even if it had been disabled, but it
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
        # finding mac...
        try:
            mac = (yield from self.arp.run(ip))[1]
        except discoveries.PingedBroadcast:
            if self.auto_ignore_broadcasts and ip not in self.ignore:
                logger.error("Found broadcast at {}. Ignoring IP from now on.".format(ip))
                self.ignore.append(ip)
            return False
        names = (yield from self.name_discovery.run(ip))[1]
        # detecting is_up...
        for discovery in self.discoveries:
            if discovery.enabled:
                self.status = "scanning ip '{}' - running {}.".format(ip, discovery.short_name)
                method = discovery.short_name
                try:
                    is_up = yield from discovery.run(ip)
                except discoveries.PingedBroadcast:
                    if self.auto_ignore_broadcasts and ip not in self.ignore:
                        logger.info("Found broadcast at {}. Ignoring IP from now on.".format(ip))
                        self.ignore.append(ip)
                    return False
                if is_up:
                    break
                else:
                    method = None
        # detecting changes and finishing...
        self.status = "scanning ip '{}' - finishing.".format(ip)
        ip_changed = self.ip_hosts[ip].update(mac, method, is_up, names)
        if 'mac' in ip_changed[1]:
            try:
                self.mac_hosts[MACElement(self.ip_hosts[ip].second_last_mac)].update_ip_disconnected(ip)
            except (KeyError, TypeError):  # second_last_mac is None
                pass  # don't update it
        if 'name' in ip_changed[1]:
            try:
                self.name_hosts[self.ip_hosts[ip].second_last_name].update_ip_disconnected(ip)
            except (KeyError, TypeError):  # second_last_mac is None
                pass  # don't update it
        mac_elem = MACElement(str(mac))  # mac converted to str in order to prevent TypeErrors
        if mac_elem not in self.mac_hosts and mac is not None:
            host = MACHost(mac_elem)
            self.mac_hosts[mac_elem] = host
        if mac is not None:
            if mac_elem not in self.ignore_mac:
                mac_changed = self.mac_hosts[mac_elem].update(ip)
            else:
                mac_changed = (False, '')
        else:
            if self.ip_hosts[ip].mac is not None:  # mac went down
                mac = self.ip_hosts[ip].mac
                mac_changed = self.mac_hosts[MACElement(mac)].update(ip)
            else:
                mac_changed = (False, '')
        names_changed = []
        for name in names:
            if name not in self.name_hosts and name is not None:
                host = NameHost(name)
                self.name_hosts[name] = host
            if name is not None:
                if name not in self.ignore_name:
                    names_changed.append(self.name_hosts[name].update(ip))
                else:
                    names_changed.append((False, ''))
        if len(names) == 0:
            if self.ip_hosts[ip].name is not None:  # name went down
                names = self.ip_hosts[ip].name
                for name in names:
                    names_changed.append(self.name_hosts[name].update(ip))
            else:
                names_changed.append((False, ''))
        for name, name_changed in map(lambda *args: args, names, names_changed):
            if ip_changed[0] or mac_changed[0] or name_changed[0] or self.force_notify:
                yield from self.fire_notifiers(ip, mac, name, method, is_up,
                                               ip_changed[1],mac_changed[1], name_changed[1])
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
        maximum_seconds_randomly_added, calculated as follows:
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
                if self.warn_parsing_exception:
                    logger.error("Error while parsing: {}".format(exc))
                else:
                    logger.debug("Error while parsing: {}".format(exc))
            sleep_for = self.time_between_checks.total_seconds() + \
                        random.randint(0, self.maximum_seconds_randomly_added)
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
                if host._ip.is_broadcast() or host._ip.is_network():
                    logger.debug("Ignoring: {}".format(host._ip))
                    continue
            else:
                if host._ip in self.ignore:
                    logger.debug("Ignoring (found in self.ignore): {}".format(host._ip))
                    continue
            if host._ip in self.priorities:
                priorities[
                    (self.priorities[host._ip] + int(host.ago.total_seconds())) * 10 ** 12 + host._ip.as_int()
                    ] = host._ip
            else:
                priorities[
                    int(host.ago.total_seconds()) * 10 ** 12 + host._ip.as_int()
                    ] = host._ip
        return priorities[max(priorities)]

    @coroutine
    def fire_notifiers(self, ip, mac, name, method, is_up, ip_what, mac_what, name_what):
        if ip_what is None:
            ip_what = ''
        if mac_what is None:
            mac_what = ''
        if name_what is None:
            name_what = ''
        if ip_what is None and mac_what is None and name_what is None:
            logger.error("IP {}@{} changed without reasoning.".format(ip.ip[0], mac))
        what = "IP(" + ip_what + ") MAC(" + mac_what + ") Name(" + name_what + ")"
        if mac is None:
            mac = 'mac-not-found'
        if name is None:
            name = 'name-not-found'
        logger.info("{}@{}({}) changed {}. method: {}, is_up: {}.".format(ip.ip[0], mac, name, what, method, is_up))
        if self.serializer is not None:
            self.status = "saving changes."
            yield from self.serializer.save()

    @coroutine
    def changes(self, hosts, from_, to, json_compatible=False):
        """This function returns changes occurred
        to given hosts within the given time period.
        If argument json_compatible evaluates to True,
        in the returned dict there will be no objects
        as defined in net_elements. Instead they will
        be converted into builtin types as follows:
          - IPElement("192.168.0.0/24") -> "192.168.0.0"  # str
          - MACElement("a0:ff:e4:bc:66:70") -> "a0:ff:e4:bc:66:70"  # str
          - datetime() -> datetime().timestamp()  # float
        The returned dict will be in the following form:
        {
            IPElement("...") : {
                'discovery_history': {
                    datetime(...): 'icmp',  # or 'syn'
                    ...
                },
                'is_up_history': {
                    datetime(...): True,  # or False
                    ...
                },
                'mac_history': {
                    datetime(...): MACElement("..."),
                    ...
                }
            },
            MACElement("..."): {
                'history': {
                    datetime(...): [IPElement("..."), ...],
                    ...
                }
                'is_up_history': {
                  datetime(...): True,  # or False
                  ...
                }
            }
            IPElement("..."): {
                ...
            },
            ...
        }
        Since this function may do some heavy calculations
        and therefore block, it had been designed to be a
        coroutine, in order to prevent blocking.
        For filtering results to IPHosts only or MACHosts
        only, see Tracker.ip_changes and Tracker.mac_changes.
        :param hosts: IPHost,MACHost[]
        :param from_: datetime.datetime
        :param to: datetime.datetime
        :param json_compatible: bool
        :return: dict
        """
        changes = {}
        hosts_combined = list(self.ip_hosts.values())
        for machost in self.mac_hosts.values():
            hosts_combined.append(machost)
            yield
        for namehost in self.name_hosts.values():
            hosts_combined.append(namehost)
            yield
        for host in hosts_combined:
            if host in hosts or len(hosts) == 0:
                if json_compatible:
                    if isinstance(host, IPHost):
                        host_name = str(host._ip.ip[0])
                    elif isinstance(host, MACHost):
                        host_name = str(host.mac.mac)
                    elif isinstance(host, NameHost):
                        host_name = host.name
                    else:
                        host_name = str(host)
                else:
                    host_name = host
                yield
                changes[host_name] = {}
                for attr in dir(host):
                    if attr.find("history") > -1:
                        history = getattr(host, attr)
                        try:
                            iter(history)
                        except TypeError:
                            continue
                        changes[host_name][attr] = {}
                        for entry in history:
                            if from_ <= entry <= to:
                                if attr == 'history':  # MAC/NameHost.history are the only attributes called like this
                                    if json_compatible:
                                        changes[host_name][attr][str(entry.timestamp())] = []
                                        for ip in history[entry]:
                                            changes[host_name][attr][str(entry.timestamp())].append(ip.ip[0])
                                            yield
                                    else:
                                        changes[host_name][attr].update({entry: history[entry]})
                                else:
                                    if json_compatible:
                                        changes[host_name][attr].update({str(entry.timestamp()): history[entry]})
                                    else:
                                        changes[host_name][attr].update({entry: history[entry]})
                            yield
                    yield
        return changes

    @coroutine
    def ip_changes(self, hosts, from_, to, json_compatible=False):
        """Similar to Tracker.changes, but only iterates over IPHosts."""
        hosts_ = []
        if len(hosts) == 0:
            hosts_ = self.ip_hosts.values()
        else:
            for host in self.ip_hosts.values():
                if host in hosts:
                    hosts_.append(host)
                    yield
        return (yield from self.changes(hosts_, from_, to, json_compatible))

    @coroutine
    def mac_changes(self, hosts, from_, to, json_compatible=False):
        """Similar to Tracker.changes, but only iterates over MACHosts."""
        hosts_ = []
        if len(hosts) == 0:
            hosts_ = self.mac_hosts.values()
        else:
            for host in self.mac_hosts.values():
                if host in hosts:
                    hosts_.append(host)
                    yield
        return (yield from self.changes(hosts_, from_, to, json_compatible))

    @coroutine
    def name_changes(self, hosts, from_, to, json_compatible=False):
        """Similar to Tracker.changes, but only iterates over NameHosts."""
        hosts_ = []
        if len(hosts) == 0:
            hosts_ = self.name_hosts.values()
        else:
            for host in self.name_hosts.values():
                if host in hosts:
                    hosts_.append(host)
                    yield
        return (yield from self.changes(hosts_, from_, to, json_compatible))

    def __repr__(self):
        return "<{} monitoring {}>".format(self.__class__.__name__, self.network)


class TrackersHandler(object):
    """
    This is capable of handling different Tracker instances
    at the same time.
    For methods and attributes documentation you may refer
    to Tracker's documentation, since this class mimics
    most of its behaviour. Please, note that this is not
    a subclass of Tracker, though.
    In most cases Tracker's attributes are mapped to
    properties in order to provide the attributes of all
    Trackers this object is currently handling.
    Usually, setting one of these properties reflects
    the change to all Trackers objects currently handled.
    """

    def __init__(self, network, hosts=16):
        """
        This function handles splitting of the
        network into different sub-networks.
        Each sub-network's length is defined with
        the hosts argument. It, therefore, should be
        a valid network length (a power of 2).
        You can check if a value is ok for hosts argument
        by checking it against net_elements.netmask_from_netlength.
        Each sub-network will be passed to a Tracker
        as its network to keep track.
        """
        self.network = network
        self.mac_hosts = {}  # MACElement: MACHost
        self.name_hosts = {}  # str: NameHost
        self.hosts = hosts
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
                net = Network(ip)
                net.forced_length = len(net)  # this way net's broadcast will be checked: not a real broadcast
                tr = Tracker(net)
            tr.ignore_networks_and_broadcasts = False  # sub-networks broadcasts are not real broadcasts
            self.mac_hosts.update(tr.mac_hosts)
            tr.mac_hosts = self.mac_hosts  # using shared memory for MACHosts.
            tr.name_hosts = self.name_hosts  # using shared memory for NameHosts.
            self.trackers.append(tr)
            start += hosts
        # since broadcasts and networks ignoring is inhibited by default, manually ignore real broadcast and network
        network_and_broadcast = [self.network[0], self.network.broadcast()]
        self.ignore = network_and_broadcast

    @property
    def status(self):
        return [tr.status for tr in self.trackers]

    @status.setter
    def status(self, value):
        for tr in self.trackers:
            tr.status = value

    @property
    def up_hosts(self):
        up = 0
        for tr in self.trackers:
            up += tr.up_hosts
        return up

    @property
    def up_ip_hosts(self):
        up_ip_hosts = {}
        for tr in self.trackers:
            up_ip_hosts.update(tr.up_ip_hosts)
        return up_ip_hosts

    @property
    def up_mac_hosts(self):
        up_mac_hosts = {}
        for tr in self.trackers:
            up_mac_hosts.update(tr.up_mac_hosts)
        return up_mac_hosts

    @property
    def up_name_hosts(self):
        up_name_hosts = {}
        for tr in self.trackers:
            up_name_hosts.update(tr.up_name_hosts)
        return up_name_hosts

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
    def auto_ignore_broadcasts(self):
        return [tr.auto_ignore_broadcasts for tr in self.trackers]

    @auto_ignore_broadcasts.setter
    def auto_ignore_broadcasts(self, value):
        for tr in self.trackers:
            tr.auto_ignore_broadcasts = value

    @property
    def warn_parsing_exception(self):
        return [tr.warn_parsing_exception for tr in self.trackers]

    @warn_parsing_exception.setter
    def warn_parsing_exception(self, value):
        for tr in self.trackers:
            tr.warn_parsing_exception = value

    @property
    def ip_hosts(self):
        ip_hosts = {}
        for tr in self.trackers:
            for ip_host in tr.ip_hosts:
                ip = IPElement(ip=ip_host._ip[0], mask=self.network.mask)
                ip_hosts.update({ip: tr.ip_hosts[ip_host]})
        return ip_hosts

    @property
    def priorities(self):
        priorities = {}
        for tr in self.trackers:
            priorities.update(tr.priorities)
        return priorities

    @priorities.setter
    def priorities(self, value):
        for tr in self.trackers:
            tr.priorities = value

    @property
    def ignore(self):
        ignore = []
        for tr in self.trackers:
            for i in tr.ignore:
                if i not in ignore:
                    ip = IPElement(ip=i._ip[0], mask=self.network.mask)
                    ignore.append(ip)
        return ignore

    @ignore.setter
    def ignore(self, value):
        for tr in self.trackers:
            tr.ignore = value

    @property
    def ignore_mac(self):
        ignore = []
        for tr in self.trackers:
            for i in tr.ignore_mac:
                if i not in ignore:
                    ignore.append(i)
        return ignore

    @ignore_mac.setter
    def ignore_mac(self, value):
        for tr in self.trackers:
            tr.ignore_mac = value

    @property
    def ignore_name(self):
        ignore = []
        for tr in self.trackers:
            for i in tr.ignore_name:
                if i not in ignore:
                    ignore.append(i)
        return ignore

    @ignore_name.setter
    def ignore_name(self, value):
        for tr in self.trackers:
            tr.ignore_name = value

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

    @property
    def name_discovery(self):
        return [tr.name_discovery for tr in self.trackers]

    @name_discovery.setter
    def name_discovery(self, value):
        for tr in self.trackers:
            tr.name_discovery = value

    @property
    def serializer(self):
        sers = []
        for tr in self.trackers:
            sers.append(tr.serializer)
        return sers

    @serializer.setter
    def serializer(self, value):
        for tr in self.trackers:
            tr.serializer = value

    @property
    def force_notify(self):
        notifies = []
        for tr in self.trackers:
            notifies.append(tr.force_notify)
        return notifies

    @force_notify.setter
    def force_notify(self, value):
        for tr in self.trackers:
            tr.force_notify = value

    @coroutine
    def changes(self, hosts, from_, to, json_compatible=False):
        for host in hosts:
            if isinstance(host, IPHost):
                host._ip.mask = self.trackers[0].network.mask
                yield
        for tr in self.trackers:
            ch = yield from tr.changes(hosts, from_, to, json_compatible)
            if len(ch) > 0:
                return ch

    @coroutine
    def ip_changes(self, hosts, from_, to, json_compatible=False):
        for host in hosts:
            host._ip.mask = self.trackers[0].network.mask
            yield
        changes = {}
        if hosts:
            for tr in self.trackers:
                for host in hosts:
                    if host in tr.ip_hosts.values():
                        # print(tr, (yield from tr.ip_changes(hosts, from_, to, json_compatible)))
                        ch = yield from tr.ip_changes(hosts, from_, to, json_compatible)
                        changes.update(ch)
        else:
            for tr in self.trackers:
                ch = yield from tr.ip_changes(hosts, from_, to, json_compatible)
                changes.update(ch)
        return changes

    @coroutine
    def mac_changes(self, hosts, from_, to, json_compatible=False):
        # mac_hosts are shared between trackers
        return (yield from self.trackers[0].mac_changes(hosts, from_, to, json_compatible))

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

# track.time_between_checks = datetime.timedelta(minutes=0, seconds=0); track.maximum_seconds_randomly_added = 0
# track.ip_hosts[IPElement("10.224.2.85/24")].print_histories()
# track.mac_hosts[MACElement("FC:3F:7C:5C:00:D0")].print_histories()
# for tr in track.trackers: print(tr.network, tr.status)
# for tr in track.trackers: print(tr.network, tr.discoveries[1].enabled)
# print(track.time_between_checks)
# print(track.trackers[0].discoveries[1].enabled)
# print(track.ip_hosts[IPElement("192.168.2.100/")])
# track.ignore_mac = [MACElement("00:1B:0D:59:51:C2")]
# print(track.changes(hosts=[IPHost(IPElement("192.168.2.36/23"))], from_=datetime.datetime.fromtimestamp(0), to=datetime.datetime.now()))
# GET /mac_host_changes/48:51:b7:2b:88:60/1.1.1-1.1.1/now/ciao/ HTTP/1.0
# GET /ip_host_changes/192.168.2.44/1.1.1-1.1.1/now/ciao/ HTTP/1.0
