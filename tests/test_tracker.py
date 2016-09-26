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

Unittests for src.tracker.

"""

import unittest
import sys
import os
import asyncio
from asyncio import coroutine

path = os.path.abspath(os.path.join(os.getcwd(), '..', 'tBB', 'tBB'))
if path not in sys.path:
    sys.path.append(path)

from net_elements import *
import tracker


class TrackerFaker(tracker.Tracker):
    def __init__(self, network):
        self.scans = []
        super().__init__(network)

    @coroutine
    def do_single_scan(self, ip):
        self.scans.append(ip)


class TrackerTestCase(unittest.TestCase):
    def test_highest_priority_host(self):
        track = tracker.Tracker(Network("192.168.0.0/24-10"))
        self.assertEqual(track.highest_priority_host(), IPElement("192.168.0.10/24"))
        track.priorities[IPElement("192.168.0.5/24")] = 1000
        self.assertEqual(track.highest_priority_host(), IPElement("192.168.0.5/24"))

    def test_do_single_scan_invalid(self):
        track = tracker.Tracker(Network("192.168.0.0/24-10"))
        loop = asyncio.get_event_loop()
        with self.assertRaises(RuntimeError):
            loop.run_until_complete(
                track.do_single_scan(IPElement("127.0.0.1/8"))
            )

    def test_do_single_scan_valid(self):
        track = tracker.Tracker(Network("127.0.0.0/24"))
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            asyncio.set_event_loop(asyncio.new_event_loop())
            loop = asyncio.get_event_loop()
        self.assertTrue(loop.run_until_complete(
            track.do_single_scan(IPElement("127.0.0.1/24"))
        ))
        host = track.ip_hosts[IPElement("127.0.0.1/24")]
        self.assertAlmostEqual((host.last_check - datetime.datetime.now()).total_seconds(), 0, places=1)
        # self.assertTrue(host.mac)
        track = tracker.Tracker(Network("240.0.0.0/24"))
        self.assertFalse(loop.run_until_complete(
            track.do_single_scan(IPElement("240.0.0.1/24"))  # reserved address
        ))

    def test_do_complete_network_scan(self):
        net = Network("192.168.0.0/24")
        track = TrackerFaker(net)
        track.do_complete_network_scan()
        for i, ipelem in enumerate(net):
            try:
                self.assertEqual(ipelem, track.scans[i])
            except IndexError:
                pass

    def test_do_partial_scan(self):
        net = Network("192.168.0.0/24")
        track = TrackerFaker(net)
        track.do_partial_scan(12, 24)
        for i, ipelem in enumerate(net):
            try:
                self.assertEqual(ipelem, track.scans[i])
            except IndexError:
                pass
