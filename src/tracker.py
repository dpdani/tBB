"""

Tracker implementation.

"""

import asyncio
from asyncio import coroutine
import logging
import datetime
import random
from net_elements import Network, IPElement, IPHost, MACElement, MACHost
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
        self.mac_hosts = {}
        self.icmp = discoveries.DefaultICMPDiscovery
        self.arp = discoveries.DefaultARPDiscovery
        self.syn = discoveries.DefaultSYNDiscovery
        self.do_icmp = True
        self.do_arp = True
        self.do_syn = True
        self.time_between_checks = datetime.timedelta(minutes=0, seconds=0)
        self.maximum_seconds_randomly_added = 0

    @coroutine
    def do_complete_network_scan(self):
        logger.debug("Scanning entire network: {}".format(self.network))
        up = 0
        for ip in self.network:
            if (yield from self.do_single_scan(ip)):
                up += 1
        return up

    @coroutine
    def do_partial_scan(self, start, end):
        if type(start) != int or type(end) != int:
            raise TypeError("expected argument start and end to be of type int. Got: {} and {}.".format(
                type(start), type(end)
            ))
        ip = self.network + start
        logger.debug("Scanning network from {} for {} hosts.", ip, end)
        for _ in range(end - start):
            yield from self.do_single_scan(ip)
            ip += 1

    @coroutine
    def do_single_scan(self, ip):
        if not isinstance(ip, IPElement):
            raise TypeError("expected argument ip to be an IPElement instance. Got: {}.".format(ip))
        logger.debug("scanning ip '{}'.".format(ip))
        method = None
        is_up = False
        arp_result = None
        if self.do_icmp:
            try:
                is_up = yield from self.icmp.run(ip)
                method = 'icmp'
            except discoveries.PingedBroadcast:
                return False
        if not is_up:
            if self.do_arp:
                is_up = yield from self.arp.run(ip)
                method = 'arp'
                arp_result = is_up
        try:
            if not is_up[0]:
                if self.do_syn:
                    is_up = yield from self.syn.run(ip)
                    method = 'syn'
        except TypeError:  # arp was disabled -> TypeError on is_up[0]
            if not is_up:
                if self.do_syn:
                    is_up = yield from self.syn.run(ip)
                    method = 'syn'
        if method == 'arp':
            mac = is_up[1]
            is_up = is_up[0]
        elif arp_result is not None:
            mac = arp_result[1]
        else:
            mac = (yield from self.arp.run(ip))[1]
        if ip not in self.ip_hosts.keys():
            logger.error("asked to scan '{}', but couldn't locate it in self.ip_hosts.", ip)
            raise RuntimeError("could not internally locate host '{}'.".format(ip))
        if is_up:
            self.ip_hosts[ip].update(mac, method)
        else:
            self.ip_hosts[ip].last_check = datetime.datetime.now()
        try:
            self.mac_hosts[MACElement(mac)].update(ip)
        except TypeError:  # mac not found
            pass
        except KeyError:
            host = MACHost(MACElement(mac))
            host.update(ip)
            self.mac_hosts[MACElement(mac)] = host
        return is_up

    @coroutine
    def keep_network_tracked(self):
        while True:
            yield from self.do_single_scan(self.highest_priority_host())
            yield from asyncio.sleep(
                self.time_between_checks.total_seconds() + random.randint(0, self.maximum_seconds_randomly_added)
            )

    @coroutine
    def start_tracking_network(self):
        yield from self.do_complete_network_scan()
        yield from self.keep_network_tracked()

    def highest_priority_host(self):
        priorities = {}  # priority: IP
        for host in self.ip_hosts.values():
            if host._ip in self.priorities:
                priorities[
                    (self.priorities[host._ip] + int(host.ago.total_seconds())) * 10**12 + host._ip.as_int()
                ] = host._ip
            else:
                priorities[
                    int(host.ago.total_seconds()) * 10 ** 12 + host._ip.as_int()
                ] = host._ip
        return priorities[max(priorities)]
