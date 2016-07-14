"""

Network elements definitions.

"""


class IPElement(object):
    def __init__(self, *args, **kwargs):
        """
        IPElement('192.168.0.100/25')
        IPElement(ip='192.168.0.100', mask=25)
        """
        self._ip = ('', [0, 0, 0, 0])
        self._mask = 0
        if len(args) == 1:
            self.mask, self.ip  = reversed(args[0].split('/'))  # mask needs to be initialized before ip
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

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if self.ip == other.ip and self.mask == other.mask:
            return True
        return False

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


class Network(IPElement):
    def __init__(self, *args, **kwargs):
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
        if self.__iter_index >= len(self)-1:
            raise StopIteration()
        self.__iter_index += 1
        return self + self.__iter_index

    def broadcast(self):
        return self + (len(self) - 1)

    def last_host(self):
        return self + (len(self) - 2)

    def __repr__(self):
        return super().__repr__().replace('>', '-{}>'.format(len(self)))


class Host(IPElement):
    # TODO: add discovery_method, known_ports, ...
    def __init__(self, *args, **kwargs):
        if len(args) == 1 and isinstance(args[0], IPElement):
            self._ip = args[0].ip
            self._mask = args[0].mask
        else:
            super().__init__(*args, **kwargs)

    def next(self):
        return self + 1
