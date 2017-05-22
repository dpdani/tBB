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


import unittest
import sys
import os

path = os.path.abspath(os.path.join(os.getcwd(), '..', 'tBB', 'tBB'))
if path not in sys.path:
    sys.path.append(path)

from net_elements import IPElement, Network
import discoveries


def setUpModule():
    discoveries.asyncio.get_event_loop()

def tearDownModule():
    discoveries.asyncio.get_event_loop().close()


class UtilsTestCase(unittest.TestCase):
    def test_shell_invalid_argument(self):
        with self.assertRaises(TypeError):
            next(discoveries.shell(IPElement("192.168.1.0/24")))

    def test_shell_valid_argument(self):
        loop = discoveries.asyncio.get_event_loop()
        result = loop.run_until_complete(
            discoveries.shell("echo -n 'Lovely spam!!!'")
        )
        self.assertEqual(result, ["Lovely spam!!!"])


class ICMPDiscoveryTestCase(unittest.TestCase):
    def test_init_valid(self):
        icmp = discoveries.ICMPDiscovery(
            count=4,
            timeout=2,
            flood=True
        )
        self.assertEqual(icmp.count, 4)
        self.assertEqual(icmp.timeout, 2)
        self.assertEqual(icmp.flood, True)

    def test_init_invalid(self):
        with self.assertRaises(ValueError):
            discoveries.ICMPDiscovery(
                count=-25,
                timeout=1
            )

    def test_builtin_settings(self):
        self.assertTrue(hasattr(discoveries, 'DefaultICMPDiscovery'))
        self.assertTrue(hasattr(discoveries, 'HeavyICMPDiscovery'))

    def test_run_invalid_argument(self):
        with self.assertRaises(TypeError):
            next(discoveries.DefaultICMPDiscovery.run(1000))

    def test_present_host(self):
        loop = discoveries.asyncio.get_event_loop()
        self.assertTrue(loop.run_until_complete(
            discoveries.DefaultICMPDiscovery.run(IPElement("127.0.0.1/8"))  # loopback is always pingable
        ))

    def test_not_present_host(self):
        loop = discoveries.asyncio.get_event_loop()
        self.assertFalse(loop.run_until_complete(
            discoveries.DefaultICMPDiscovery.run(IPElement("192.0.2.1/24"))  # reserved address
        ))


class ARPDiscoveryTestCase(unittest.TestCase):
    def test_init_valid(self):
        arp = discoveries.ARPDiscovery(
            count=4,
            timeout=2,
            quit_on_first=True,
            interface='eth0'
        )
        self.assertEqual(arp.count, 4)
        self.assertEqual(arp.timeout, 2)
        self.assertEqual(arp.quit_on_first, True)

    def test_init_invalid(self):
        with self.assertRaises(ValueError):
            discoveries.ARPDiscovery(
                count=-25,
                timeout=1,
                interface='eth0'
            )

    def test_builtin_settings(self):
        self.assertTrue(hasattr(discoveries, 'DefaultARPDiscovery'))
        self.assertTrue(hasattr(discoveries, 'HeavyARPDiscovery'))

    def test_run_invalid_argument(self):
        with self.assertRaises(TypeError):
            next(discoveries.DefaultARPDiscovery.run(1000))

    # def test_present_host(self):
    #     loop = discoveries.asyncio.get_event_loop()
    #     self.assertTrue(loop.run_until_complete(
    #         discoveries.DefaultARPDiscovery.run(IPElement("127.0.0.1/8"))  # loopback is always pingable
    #     )[0])

    # def test_not_present_host(self):
    #     loop = discoveries.asyncio.get_event_loop()
    #     self.assertFalse(loop.run_until_complete(
    #         discoveries.DefaultARPDiscovery.run(IPElement("192.168.2.255/24"))  # broadcast doesn't respond to ARP
    #     )[0])


class SYNDiscoveryTestCase(unittest.TestCase):
    def test_init_valid(self):
        syn = discoveries.SYNDiscovery(
            ports="22",
            timeout=2
        )
        self.assertEqual(syn.ports, "22")
        self.assertEqual(syn.timeout, 2)

    def test_builtin_settings(self):
        self.assertTrue(hasattr(discoveries, 'DefaultSYNDiscovery'))
        self.assertTrue(hasattr(discoveries, 'HeavySYNDiscovery'))

    def test_run_invalid_argument(self):
        with self.assertRaises(TypeError):
            next(discoveries.DefaultSYNDiscovery.run(1000))

    # def test_present_host(self):
    #     loop = discoveries.asyncio.get_event_loop()
    #     self.assertTrue(loop.run_until_complete(
    #         discoveries.DefaultSYNDiscovery.run(IPElement("127.0.0.1/8"))  # loopback is always pingable
    #     ))

    def test_not_present_host(self):
        loop = discoveries.asyncio.get_event_loop()
        self.assertFalse(loop.run_until_complete(
            discoveries.DefaultSYNDiscovery.run(IPElement("192.0.2.1/24"))  # reserved address
        ))
