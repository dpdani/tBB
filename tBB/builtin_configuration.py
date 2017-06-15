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

tBB's builtin configuration.

This is what tBB will fall back to if the user doesn't specify differently.

"""

import settings


root = settings.Settings.parse({
    'monitoring': {
        'discoveries': {
            'icmp': {
                'count': 1,
                'timeout': 4,
                'flood': True,
                'enable': True,
            },
            'syn': {
                'ports': '22',
                'timeout': 4,
                'enable': True,
            },
            'arp': {
                'count': 3,
                'interface': 'eth0',
                'timeout': 2,
                'quit_on_first': True,
            },
        },
        'least_record_update': '30:00',  # minimum time from which to reload monitoring
        'enable_notifiers': True,
        'time_between_checks': '00:02',
        'maximum_seconds_randomly_added': 2,
        'auto_ignore_broadcasts': True,
        'hosts': 16,
        'ignore': [],
        'ignore_mac': [],
        'ignore_name': [],
    },
    'frontends': {
        'host': 'localhost',
        'port': 1984,
        'maximum_port_lookup': 20,
        'ssl': {
            'enable': True,
            'check_hostname': False,
        }
    },
    'notifiers': {
        'enable': False,
    },
    'serialization': {
        'indent': 4,
        'do_sort': True
    },
    'logging': {
        'default_time_format': '%Y-%m-%d %H.%M.%S',
        'level': 'INFO',
        'formatters': {
            'complete': {
                'format': '%(levelname)s|%(name)s@%(asctime)s: %(message)s',
                'datefmt': '{default_time_format}',
            },
            'brief': {
                'format': '%(asctime)s: %(message)s',
                'datefmt': '{default_time_format}',
            },
            'syslog': {
                'format': '## %(levelname)s|%(name)s: %(message)s',
                'datefmt': '{default_time_format}',
            },
            'custom_1': {
                'format': 'Please override logging.formatters.custom_1.format in your '
                          'configuration file.',
                'datefmt': '{default_time_format}',
            },
            'custom_2': {
                'format': 'Please override logging.formatters.custom_2.format in your '
                          'configuration file.',
                'datefmt': '{default_time_format}',
            },
            'custom_3': {
                'format': 'Please override logging.formatters.custom_3.format in your '
                          'configuration file.',
                'datefmt': '{default_time_format}',
            },
        },
        'handlers': {
            'console': {
                'level': 'INFO',
                'formatter': 'brief'
            },
            'syslog': {
                'level': 'INFO',
                'formatter': 'syslog',
                'address': {'ip': '', 'port': ''},
                'socktype': 'DATAGRAM',
            },
            'file': {
                'level': 'DEBUG',
                'formatter': 'complete',
                'max_bytes': 10000000,
                'backup_count': 4,
                'filename': 'tBB.log'
            },
            'enable': ['console', 'file']
        },
    },
})

builtin = settings.Settings(tree=root)
