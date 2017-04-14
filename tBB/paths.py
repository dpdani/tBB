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

This module contains various utilities for finding correct paths for tBB.

"""


import os


executable = None
root = None
configs = None
scans = None
certs = None


def update_paths():
    """
    Updates the following global variables to paths:
        - ``executable``
        - ``root``
        - ``configs``
        - ``scans``
        - ``certs``
    """
    global root, executable, configs, scans, certs

    executable = os.path.dirname(os.path.abspath(__file__))
    root = os.path.expanduser(os.path.join('~', '.tBB'))
    configs = os.path.join(root, 'configs')
    scans = os.path.join(root, 'scans')
    certs = os.path.join(root, 'certs')


def check_required_paths():
    """
    This function checks for paths to be present on the filesystem.
    It checks for:
        - ~/.tBB/
        - ~/.tBB/scans/
        - ~/.tBB/certs/
        - ~/.tBB/configs/
    """
    for pth in (root, scans, certs, configs):
        if not os.path.exists(pth):
            os.mkdir(pth)


update_paths()