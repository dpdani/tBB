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

Determine whether or not a change detected by tBB is suspicious.

"""


import discoveries
from net_elements import *


class Dispatcher:
    behaviors = {
        'static_up': None,
        'static_down': None,
        'static_power_saving': None,
        'dhcp_assigned': None,
    }

    def __init__(self, settings):
        # Parse behaviors from settings
        for behavior in self.behaviors.keys():
            for start_end in ('start', 'end'):
                behavior_settings = getattr(settings, behavior)
                attribute_settings = getattr(behavior_settings, start_end)
                if attribute_settings.value != '':
                    if not attribute_settings.value.endswith('/32'):
                        attribute_settings.value += '/32'
                    try:
                        attribute_settings.value = IPElement(attribute_settings.value)
                    except (TypeError, ValueError):
                        raise ValueError('settings item behaviors.{}.{} is not a '
                                         'valid IP address.'.format(
                            behavior, start_end
                        ))
            for include_exclude in ('include', 'exclude'):
                behavior_settings = getattr(settings, behavior)
                attribute_settings = getattr(behavior_settings, include_exclude)
                if attribute_settings.value != []:
                    converted = []
                    for n, ip in enumerate(attribute_settings.value):
                        if not ip.endswith('/32'):
                            ip += '/32'
                        try:
                            converted.append(IPElement(ip))
                        except (TypeError, ValueError):
                            raise ValueError('settings item behaviors.{}.{} at index {} '
                                             'is not a valid IP address.'.format(
                                behavior, include_exclude, n
                            ))
                    attribute_settings.value = converted
        # Generate behavior map
        self.behavior_map = {}
        for behavior in self.behaviors.keys():
            start = getattr(settings, behavior).start.value
            end = getattr(settings, behavior).end.value
            if start != '' and end != '':
                pointer = start
                while pointer <= end:
                    self.behavior_map[pointer] = behavior
                    pointer += 1
            for ip in getattr(settings, behavior).include.value:
                self.behavior_map[ip] = behavior
            for ip in getattr(settings, behavior).exclude.value:
                if ip in self.behavior_map:
                    del self.behavior_map[ip]

    def change_detected(self, ip, ip_host, mac_host, name_host):
        """A change was detected by Tracker, need to dispatch it to
        the correct behavior as defined in settings."""
        self.behaviors[self.behavior_map[ip]].\
            check_change(ip, ip_host, mac_host, name_host)


class BaseBehavior:
    def check_change(self, ip, ip_host, mac_host, name_host):
        """
        Check if the given ip host is behaving as expected.
        :param ip_host: IPHost
        :param mac_host: MACHost
        :param name_host: NameHost
        :return:
        """
        raise NotImplementedError('this method needs to be overridden by a '
                                  'non-abstract behavior.')
