"""

Network elements representations for Python.

"""

import datetime
import math


def netmask_from_netlength(hosts):
    if not (hosts != 0 and ((hosts & (hosts - 1)) == 0)):
        raise ValueError("expected argument hosts to be a power of 2. Got: {}".format(hosts))
    return 32 - math.log(hosts, 2)


class IPElement(object):
    """
    IP object representation for Python.
    This object responds to the following interfaces:
      - addition (and subtraction)
      - equality (and inequality)
      - hashable
    """

    def __init__(self, *args, **kwargs):
        """
        Possible initializations:
            IPElement('192.168.0.100/25')
            IPElement(ip='192.168.0.100', mask=25)
        """
        self._ip = ('', [0, 0, 0, 0])
        self._mask = 0
        if len(args) == 1:
            self.mask, self.ip = reversed(args[0].split('/'))  # mask needs to be initialized before ip
        else:
            self.ip = kwargs['ip']
            self.mask = kwargs['mask']
        # if 'detect_element_type' in kwargs and kwargs['detect_element_type']:
        #     if self.is_network():
        #         return Network(self)

    @property
    def ip(self):
        return self._ip

    @ip.setter
    def ip(self, *args):
        if len(args) == 1:
            self._ip = self.parse_ip(args[0])
        elif len(args) == 4:
            i = 0
            for elem in args:
                i += 1
                if elem < 0 or elem > 255:
                    raise ValueError("IP address (part {}) out of range: {}.".format(i, elem))
            self._ip = ('.'.join(args), args)
        else:
            raise TypeError("either a string or a 4-length iterable are required for ip.")

    @property
    def mask(self):
        return self._mask

    @mask.setter
    def mask(self, value):
        if type(value) == int:
            if value < 0 or value > 32:
                raise ValueError("IP mask out of range: {}.".format(value))
            self._mask = value
        self._mask = self.parse_mask(value)

    @staticmethod
    def parse_ip_with_mask(string):
        """
        Parses a string and returns the network IP and mask.
        :return: (ip: str, mask: int)
        """
        ip = IPElement.parse_ip(string[:string.find('/')])
        mask = IPElement.parse_mask(string[string.find('/')+1:])
        if ip and mask:
            return ip, mask

    @staticmethod
    def parse_ip(string):
        """
        Parses a string and checks if it is a valid IP.
        :return: string, list
        """
        split = string.split('.')
        if len(split) != 4:
            raise ValueError("IP address malformed.")
        i = 0
        for elem in split:
            elem = int(elem)
            split[i] = elem
            i += 1
            if elem < 0 or elem > 255:
                raise ValueError("IP address (part {}) out of range: {}.".format(i, elem))
        return string, split

    @staticmethod
    def parse_mask(string):
        """
        Parses a string and checks if it is a valid mask.
        :return: int
        """
        mask = int(string)
        if mask < 0 or mask > 32:
            raise ValueError("IP mask out of range: {}.".format(mask))
        return mask

    def is_network(self):
        """
        Returns True if self.ip is a network IP.
        :return: bool
        """
        num = ''
        for i in self.ip[1]:
            num += '{0:08b}'.format(i)
        for i in num[self.mask:]:
            if i != '0':
                return False
        return True

    def is_broadcast(self):
        """
        Returns True if self.ip is a network IP.
        :return: bool
        """
        num = ''
        for i in self.ip[1]:
            num += '{0:08b}'.format(i)
        for i in num[self.mask:]:
            if i != '1':
                return False
        return True

    def as_int(self):
        num = 0
        for i, ip_part in enumerate(reversed(self.ip[1])):
            num += ip_part * 10**(3*i)
        return num

    def __eq__(self, other):
        if type(other) == str:
            try:
                other = self.__class__(other)
            except (TypeError, ValueError):
                return False
        if not isinstance(other, self.__class__):
            return False
        if self.ip == other.ip and self.mask == other.mask:
            return True
        return False

    def __lt__(self, other):
        if type(other) == str:
            try:
                other = self.__class__(other)
            except (TypeError, ValueError):
                return False
        if not isinstance(other, self.__class__):
            raise TypeError("unorderable types: {} < {}.".format(self, other))
        return self.as_int() < other.as_int()

    def __hash__(self):
        return self.ip[0].__hash__()

    def __add__(self, other):
        if type(other) != int:
            raise TypeError("expected an integer.")
        ip = self.ip[1].copy()
        to_add = other
        for elem in reversed(range(4)):
            ip[elem] += to_add
            to_add = ip[elem] // 256  # truncated division
            ip[elem] %= 256
        return IPElement(ip='.'.join([str(x) for x in ip]), mask=self.mask)

    def __sub__(self, other):
        if type(other) != int:
            raise TypeError("expected an integer.")
        return self + (-other)

    def __repr__(self):
        try:
            return "<{} {}/{}>".format(self.__class__.__name__, self.ip[0], self.mask)
        except AttributeError:
            return "<{} not initialized>".format(self.__class__.__name__)


class MACElement(object):
    def __init__(self, mac):
        if type(mac) != str:
            raise TypeError("expected argument mac to be of type str. Got: {}.".format(type(mac)))
        self.mac = mac.lower()

    def __eq__(self, other):
        if type(other) == str:
            try:
                other = self.__class__(other)
            except (TypeError, ValueError):
                return False
        if not isinstance(other, self.__class__):
            return False
        return self.mac == other.mac

    def __hash__(self):
        return self.mac.__hash__()

    def __repr__(self):
        try:
            return "<{} {}>".format(self.__class__.__name__, self.mac)
        except AttributeError:
            return "<{} not initialized>".format(self.__class__.__name__)


class Network(IPElement):
    """
    IP network object representation for Python.
    This object responds to the following interfaces (inherited from IPElement):
      - addition (and subtraction)
      - equality (and inequality)
      - hashable
    In addition, also responds to the following:
      - iterable
      - sliceable
    """
    def __init__(self, *args, **kwargs):
        """
        Possible initializations:
            Network('192.168.0.0/25')
            Network(ip='192.168.0.0', mask=25)
            Network('192.168.0.0/25-10')
            Network(ip='192.168.0.0', mask=25, force_length=10)
        """
        if len(args) == 1 and isinstance(args[0], IPElement):
            self._ip = args[0].ip
            self._mask = args[0].mask
        else:
            if len(args) == 1:
                if len(args[0].split('-')) == 2:
                    ip, fl = args[0].split('-')
                    self.forced_length = int(fl)
                    super().__init__(ip)
                else:
                    super().__init__(*args, **kwargs)
            else:
                super().__init__(*args, **kwargs)
        if not self.is_network():
            raise ValueError("IP address must be a valid network IP address.")
        if not hasattr(self, 'forced_length'):
            self.forced_length = -1
        if 'force_length' in kwargs:
            # TODO: provide documentation for force_length and its behaviour
            self.forced_length = kwargs['force_length']
        self.__iter_index = 0

    @property
    def ip(self):
        return super().ip

    @ip.setter
    def ip(self, value):
        prev_ip = '/'.join([self.ip[0], str(self.mask)])
        super(Network, Network).ip.__set__(self, value)
        if not self.is_network():
            if not prev_ip.startswith('/'):
                super(Network, Network).ip.__set__(self, prev_ip)
            raise ValueError("IP address must be a valid network IP address.")

    def __len__(self):
        try:
            if self.forced_length >= 0:
                return self.forced_length
            return 2 ** (32 - self.mask)
        except AttributeError:
            return 0

    def __getitem__(self, item):
        if item >= len(self):
            raise ValueError("requested item '{}' out of network range ({}).".format(item, len(self)))
        return self + item

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        if self.forced_length == -1:
            if self.__iter_index >= len(self)-1:  # remove broadcast
                self.__iter_index = 0
                raise StopIteration()
        else:
            if self.__iter_index >= len(self):
                self.__iter_index = 0
                raise StopIteration()
        self.__iter_index += 1
        return self + self.__iter_index

    def broadcast(self):
        return self + (len(self) - 1)

    def last_host(self):
        return self + (len(self) - 2)

    def __repr__(self):
        return super().__repr__().replace('>', '-{}>'.format(len(self)))


class IPHost(object):
    def __init__(self, ip):
        if not isinstance(ip, IPElement):
            raise TypeError("expected an IPElement instance for argument ip. Got: {}".format(ip))
        self._ip = ip
        self.mac_history = {}
        self.is_up_history = {}
        self.discovery_history = {}
        self.last_check = datetime.datetime.now() - datetime.timedelta(days=100)

    @property
    def ip(self):
        return self._ip.ip

    @ip.setter
    def ip(self, value):
        self._ip.ip = value

    @property
    def is_up(self):
        try:
            return self.is_up_history[sorted(self.is_up_history.keys())[-1]]
        except IndexError:  # history is empty
            return None

    @property
    def mac(self):
        try:
            return self.mac_history[sorted(self.mac_history.keys())[-1]]
        except IndexError:  # history is empty
            return None

    @property
    def ago(self):
        return datetime.datetime.now() - self.last_check

    @property
    def last_discovery_method(self):
        try:
            return self.discovery_history[sorted(self.discovery_history.keys())[-1]]
        except IndexError:  # history is empty
            return None

    def add_to_mac_history(self, stuff):
        self.mac_history[datetime.datetime.now()] = stuff

    def add_to_discovery_history(self, stuff):
        self.discovery_history[datetime.datetime.now()] = stuff

    def add_to_is_up_history(self, stuff):
        self.is_up_history[datetime.datetime.now()] = stuff

    def update(self, mac, method, is_up):
        self.last_check = datetime.datetime.now()
        changed = False
        if mac != self.mac and mac is not None:
            self.add_to_mac_history(mac)
            changed = True
        if method != self.last_discovery_method and method is not None:
            self.add_to_discovery_history(method)
            changed = True
        if is_up != self.is_up:
            self.add_to_is_up_history(is_up)
            changed = True
        return changed

    def print_histories(self):
        print("MAC HISTORY FOR IPHOST: {}".format(repr(self)))
        for entry in sorted(self.mac_history):
            print(entry, " - ", self.mac_history[entry])
        print("UP HISTORY FOR IPHOST: {}".format(repr(self)))
        for entry in sorted(self.is_up_history):
            print(entry, " - ", self.is_up_history[entry])
        print("DISCOVERY HISTORY FOR IPHOST: {}".format(repr(self)))
        for entry in sorted(self.discovery_history):
            print(entry, " - ", self.discovery_history[entry])

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.ip == other.ip

    def __repr__(self):
        if self.mac is not None:
            return "<{} {}/{}@{}>".format(self.__class__.__name__, self.ip[0], self._ip.mask, self.mac)
        else:
            return "<{} {}/{}>".format(self.__class__.__name__, self.ip[0], self._ip.mask)


class MACHost(object):
    def __init__(self, mac):
        if not isinstance(mac, MACElement):
            raise TypeError("expected a MACElement instance for argument mac. Got: {}".format(mac))
        self.mac = mac
        self.history = {}
        self.is_up_history = {}
        self.last_update = datetime.datetime.now() - datetime.timedelta(days=100)

    @property
    def ip(self):
        try:
            return self.history[sorted(self.history.keys())[-1]]
        except IndexError:  # history is empty
            return None

    @property
    def ago(self):
        return datetime.datetime.now() - self.last_update

    @property
    def is_up(self):
        try:
            return self.is_up_history[sorted(self.is_up_history.keys())[-1]]
        except IndexError:  # history is empty
            return None

    def add_to_history(self, stuff):
        if not isinstance(stuff, tuple):
            stuff = (stuff,)
        self.history[datetime.datetime.now()] = stuff

    def add_to_is_up_history(self, stuff):
        self.is_up_history[datetime.datetime.now()] = stuff

    def update(self, ip, is_up):
        self.last_update = datetime.datetime.now()
        changed = False
        if self.ip is not None:
            if ip not in self.ip:
                self.add_to_history(ip)
                changed = True
        else:
            self.add_to_history(ip)
            changed = True
        if is_up != self.is_up:
            self.add_to_is_up_history(is_up)
            changed = True
        return changed

    def print_histories(self):
        print("IP HISTORY FOR macHOST: {}".format(repr(self)))
        for entry in sorted(self.history):
            print(entry, " - ", self.history[entry])
        print("UP HISTORY FOR macHOST: {}".format(repr(self)))
        for entry in sorted(self.is_up_history):
            print(entry, " - ", self.is_up_history[entry])

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.ip == other.ip

    def __repr__(self):
        if self.mac is not None:
            return "<{} {}@{}>".format(self.__class__.__name__, self.mac, self.ip)
        else:
            return "<{} {}>".format(self.__class__.__name__, self.mac)
