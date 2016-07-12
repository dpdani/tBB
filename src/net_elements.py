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
            self.ip, self.mask = args[0].split('/')
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
        if type(value) == int and value < 0 or value > 32:
            self._mask = value
            return
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
        ip = self.ip[1]
        if (ip[0]*10^12 + ip[1]*10^9 + ip[2]*10^6 + ip[3]*10^3) % (32 - self.mask):
            # e.g.: 192.168.1.100/24 -> 192168001100 % 8 != 0 => not network ip
            #       192.168.1.0/24 -> 192168001000 % 8 == 0 => network ip
            return False
        return True


class Network(IPElement):
    def __init__(self, *args, **kwargs):
        if len(args) == 1 and isinstance(args[0], IPElement):
            self._ip = args[0].ip
            self._mask = args[0].mask
        else:
            super().__init__(*args, **kwargs)
        self.__iter_index = 0
        self.__iter_ip = []
        self.forced_length = -1
        if 'force_length' in kwargs:
            self.forced_length = kwargs['force_length']
        if not self.is_network():
            raise ValueError("IP address must be a valid network IP address.")

    def __len__(self):
        if self.forced_length >= 0:
            return self.forced_length
        return 2 ^ (32 - self.mask)

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        self.__iter_index += 1
        if self.__iter_index >= len(self):
            raise StopIteration()
        ip = self.ip[1].copy()
        to_add = self.__iter_index
        for elem in reversed(range(3)):
            ip[elem] += to_add
            to_add = ip[elem] / 256
            ip[elem] %= 256
        return IPElement(ip='.'.join([str(x) for x in ip]), mask=self.mask)


class Host(IPElement):
    def __init__(self, *args, **kwargs):
        if len(args) == 1 and isinstance(args[0], IPElement):
            self._ip = args[0].ip
            self._mask = args[0].mask
        else:
            super().__init__(*args, **kwargs)

    def next(self):
        ip = self.ip[1].copy()
        ip[3] += 1
        if ip[2] >= 256:
            ip[3] %= 256  # should be == 0
            ip[2] += 1
        return IPElement(ip='.'.join([str(x) for x in ip]), mask=self.mask)
