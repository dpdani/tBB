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

import settings


class SettingsItemTestCase(unittest.TestCase):
    static_conversions = {  # first is valid, rest is invalid
        settings.SettingsTypes.string:
            ['monty', 42, True, settings.SettingsItem(name='test', value_type=settings.SettingsTypes.boolean)],
        settings.SettingsTypes.integer:
            [42, 'monty', True, settings.SettingsItem(name='test', value_type=settings.SettingsTypes.boolean)],
        settings.SettingsTypes.timedelta:
            ['00:12', 'monty', True, settings.SettingsItem(name='test', value_type=settings.SettingsTypes.boolean)]
    }
    def test_init(self):
        with self.assertRaises(TypeError):
            settings.SettingsItem(name=42, value_type=settings.SettingsTypes.integer)
        with self.assertRaises(TypeError):
            settings.SettingsItem(name='spam', value_type=int)
        with self.assertRaises(ValueError):
            settings.SettingsItem(name='42_spam', value_type=settings.SettingsTypes.string)
        settings.SettingsItem(name='spam_42', value_type=settings.SettingsTypes.settingsitem)

    def test_convert(self):
        sett = settings.SettingsItem(name='spam', value_type=settings.SettingsTypes.string)
        sett.value = None
        with self.assertRaises(settings.UndefinedValueException):
            sett.convert()
        for conv_type in self.static_conversions:
            sett = settings.SettingsItem(name='test', value_type=conv_type)
            for val in self.static_conversions[conv_type][1:]:
                sett.value = val
                with self.assertRaises(settings.ConversionException):
                    sett.convert()
            sett.value = self.static_conversions[conv_type][0]
            sett.convert()
            if not isinstance(sett.value, settings.datetime.timedelta):
                self.assertEqual(sett.value, self.static_conversions[conv_type][0])
            else:
                self.assertEqual(sett.value, settings.datetime.timedelta(minutes=0, seconds=12))


class SettingsTestCase(unittest.TestCase):
    def test_init(self):
        with self.assertRaises(TypeError):
            settings.Settings({'spam': 42})
        settings.Settings(settings.SettingsItem(name='settings-toplevel',
            value_type=settings.SettingsTypes.settingsitem))

    def test_parse(self):
        parsed = settings.Settings.parse({
            'spam': 42,
            'subs': {
                'sure': '4:20'
            },
            'python': True
        })
        self.assertTrue(hasattr(parsed, 'spam'))
        self.assertTrue(hasattr(parsed, 'subs'))
        self.assertTrue(hasattr(parsed.subs, 'sure'))
        self.assertTrue(hasattr(parsed, 'python'))
        self.assertEqual(parsed.spam.value, 42)
        self.assertEqual(parsed.subs.sure.value, settings.datetime.timedelta(minutes=4, seconds=20))
        self.assertEqual(parsed.python.value, True)
