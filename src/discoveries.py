"""

Discovery methods implementations.
Library asyncio.subprocess is used to implement these methods.

"""


import asyncio
import logging
import time
from asyncio import coroutine
from asyncio.subprocess import PIPE, STDOUT
from net_elements import IPElement


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@coroutine
def shell(command):
    """
    Uses asyncio's subprocess internally.
    :param command: command to execute
    :type command: str
    :return type: list
    :return: stdout of command
    """
    if type(command) != str:
        raise TypeError("command must be a string. Got: '{}'.".format(type(command)))
    process = yield from asyncio.create_subprocess_shell(
        command,
        stdin=PIPE, stdout=PIPE, stderr=STDOUT
    )
    return (yield from process.communicate())[0].decode('utf-8').splitlines()


class PingedBroadcast(Exception):
    def __init__(self, ip):
        super().__init__("requested to ping broadcast '{}'.".format(ip))

class ParsingException(Exception):
    def __init__(self, ip, method, string):
        super().__init__("while running {} on {}. Got: {}.".format(method, ip, string))

class ICMPParsingException(ParsingException):
    def __init__(self, ip, string):
        super().__init__(ip, 'icmp', string)

class ARPParsingException(ParsingException):
    def __init__(self, ip, string):
        super().__init__(ip, 'arp', string)

class SYNParsingException(ParsingException):
    def __init__(self, ip, string):
        super().__init__(ip, 'syn', string)

class HostNameParsingException(ParsingException):
    def __init__(self, ip, string):
        super().__init__(ip, 'host_name', string)


class DiscoveryMethod:
    """Base-abstract class for all discovery methods."""

    def __init__(self, short_name, enabled=True):
        self.enabled = enabled
        self.short_name = short_name

    @coroutine
    def run(self, ip):
        """
        Wrapper for DiscoveryMethod._run.
        Does type checking.
        If ip is a string this function will create an
        IPElement and pass it to self._run.
        :param ip: ip to run for.
        :return: whatever is returned by self._run
        """
        if not isinstance(ip, IPElement) and type(ip) != str:
            raise TypeError("expected ip to be an IPElement instance or a string.")
        if type(ip) == str:
            ip = IPElement(ip)
        return (yield from self._run(ip))

    @coroutine
    def _run(self, ip):
        """Runs the actual discovery. Abstract."""
        raise NotImplementedError("run method of '{}' not implemented.".format(self.__class__.__name__))

    @coroutine
    def run_multiple(self, ips):
        """
        Runs discovery for many ips.
        :param ips: ips to run for.
        :return: dict<ip: result>
        """
        results = {}
        for ip in ips:
            results[ip] = yield from self.run(ip)
        return results


class ICMPDiscovery(DiscoveryMethod):
    """ICMP discovery method. Uses system's ping to perform requests."""

    def __init__(self, count, timeout, flood=False, enabled=True):
        """
        :param count: number of ping(s) to transmit. Has to be >= 1.
        :param timeout: pings timeout. 0 -> no timeout.
        :param flood: use ping option -f. Requires the script to be run as root.
        :type count: int
        :type timeout: int
        :type flood: bool
        """
        super().__init__('icmp', enabled)
        if count < 1:
            raise ValueError("count must be >= 1.")
        self.count = count
        self.timeout = timeout
        self.flood = flood

    @coroutine
    def _run(self, ip):
        """
        :param ip: see DiscoveryMethod.run
        :return: whether the host responded to the request
        :return type: bool
        """
        start = time.time()
        try:
            result = yield from shell("ping -c {} {} {} {} | grep 'received'".format(
                self.count,
                "-w {} -W {}".format(
                    self.timeout,
                    self.timeout,
                ) if self.timeout else "",
                "-f" if self.flood else "",
                ip.ip[0]
            ))
        except KeyboardInterrupt:
            return False
        took = time.time() - start
        # e.g.: ping = "1 packets transmitted, 1 received, 0% packet loss, time 0ms"
        #       filtered_result = 1 -----------^
        filtered_result = None
        for res in result:
            if res.find('broadcast') != -1:
                raise PingedBroadcast(ip)
            try:
                filtered_result = int(res.split(', ')[1].split(' ')[0])
            except:
                raise ICMPParsingException(ip, res)
        logger.debug("Pinging IP '{}' resulted '{}'.".format(ip, filtered_result))
        if not self.flood:
            if took >= self.count * 1.1 + 2:
                logger.warning("Ping to IP '{}' took {:.2f} seconds. Network congestion?".format(ip, took))
        else:
            if took >= self.timeout + 0.5:
                logger.warning("Ping to IP '{}' took {:.2f} seconds. Network congestion?".format(ip, took))
        return filtered_result != 0

DefaultICMPDiscovery = ICMPDiscovery(count=2, timeout=1)
HeavyICMPDiscovery = ICMPDiscovery(count=4, timeout=0)


class ARPDiscovery(DiscoveryMethod):
    """ARP discovery method. Uses system's arping to perform requests."""

    def __init__(self, count, timeout, quit_on_first=True, enabled=True):
        """
        :param count: number of arp requests to perform. Has to be >= 1.
        :param timeout: pings timeout. 0 -> no timeout.
        :param quit_on_first: quit on first response received.
        :type count: int
        :type timeout: int
        :type quit_on_first: bool
        """
        super().__init__('arp', enabled)
        if count < 1:
            raise ValueError("count must be >= 1.")
        self.count = count
        self.timeout = timeout
        self.quit_on_first = quit_on_first

    @coroutine
    def _run(self, ip):
        """
        :param ip: see DiscoveryMethod.run
        :return: whether the host responded to the
                 request and the MAC address it responded with
        :return type: tuple(bool, str)
        """
        start = time.time()
        try:
            result = yield from shell("arping -I eth0 -c {} {} {} {}".format(
                self.count,
                "-f" if self.quit_on_first else "",
                "-w {}".format(self.timeout) if self.timeout else "",
                ip.ip[0]
            ))
        except KeyboardInterrupt:
            return False, None
        took = time.time() - start
        try:
            up = int(result[-1].split(' ')[1])
        except ValueError:
            raise PingedBroadcast(ip)
        host = None
        for line in result:
            line = line
            if line.find('reply') > -1:
                try:
                    host = line[line.find('[')+1:line.find(']')]
                except:
                    raise ARPParsingException(ip, line)
        # e.g.:  ARPING 192.168.2.27 from 192.168.2.90 eth0
        #        Unicast reply from 192.168.2.27 [D4:BE:D9:49:D3:0C]  0.975ms
        #      host = ----------------------------^^^^^^^^^^^^^^^^^
        #        Sent 1 probes (1 broadcast(s))
        #        Received 1 response(s)
        #      up = ------^
        logger.debug("ARPinging IP '{}' resulted '{}'.".format(ip, up != 0))
        if took >= self.count * 1.1 + 2:
            logger.warning("ARPing to IP '{}' took {:.2f} seconds. Network congestion?".format(ip, took))
        return up != 0, host


DefaultARPDiscovery = ARPDiscovery(count=2, timeout=1, quit_on_first=True)
HeavyARPDiscovery = ARPDiscovery(count=4, timeout=0, quit_on_first=True)


class SYNDiscovery(DiscoveryMethod):
    """SYN discovery method. Uses system's netcat to perform requests."""

    def __init__(self, ports, timeout, enabled=True):
        """
        :param ports: ports to perform requests to.
        :param timeout: pings timeout. 0 -> no timeout.
        :type ports: str
        :type timeout: int
        """
        super().__init__('syn', enabled)
        self.ports = ports
        self.timeout = timeout

    @coroutine
    def _run(self, ip):
        """
        :param ip: see DiscoveryMethod.run
        :return: whether the host responded to the request
        :return type: bool
        """
        start = time.time()
        try:
            result = yield from shell("nc -zv -w {} {} {}".format(
                self.timeout,
                ip.ip[0],
                self.ports
            ))
        except KeyboardInterrupt:
            return False
        result = result[0]
        took = time.time() - start
        if result.find("No route to host.") > -1:
            return False
        try:
            filtered_result = result[result.find(') ')+2:result.find(': ', 10)]
        except:
            raise SYNParsingException(ip, result)
        # TODO: network congestion check
        if result.find("No route to host") > -1:
            filtered_result = 'timed out'
        logger.debug("Syn to IP '{}' resulted '{}'.".format(ip, filtered_result))
        if filtered_result in ('succeeded', 'failed'):  # not timed out
            return True
        return False
        # e.g.: nc: connect to 192.168.2.75 port 22 (tcp) failed: Connection refused
        #     filtered_result = --------------------------^^^^^^

DefaultSYNDiscovery = SYNDiscovery(ports='22', timeout=1)
HeavySYNDiscovery = SYNDiscovery(ports='22', timeout=4)


class HostNameDiscovery(DiscoveryMethod):
    def __init__(self):
        super().__init__("host_name", enabled=True)

    def _run(self, ip):
        start = time.time()
        try:
            result = yield from shell("host {}".format(
                ip.ip[0],
            ))
        except KeyboardInterrupt:
            return False
        result = result[0]
        try:
            filtered_result = result.split(' ')[-1][:-1]
        except:
            raise HostNameParsingException(ip, result)
        # e.g.: 90.2.168.192.in-addr.arpa domain name pointer portatile.hogwarts.local.
        #    filtered_result = -------------------------------^^^^^^^^^^^^^^^^^^^^^^^^
        took = time.time() - start
        # TODO: network congestion check
        if result.find('not found') > -1:
            logger.debug("Host name of IP '{}' resulted '{}'.".format(ip, 'not found'))
            return False, None
        else:
            if filtered_result == '':
                filtered_result = 'empty-name'
            logger.debug("Host name of IP '{}' resulted '{}'.".format(ip, filtered_result))
            return True, filtered_result
