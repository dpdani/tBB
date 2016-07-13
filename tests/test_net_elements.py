import unittest
import sys
import os

path = os.path.abspath(os.path.join(os.getcwd(), '..'))
if path not in sys.path:
    sys.path.append(path)

from src import net_elements



class IPElementTestCase(unittest.TestCase):
    def test_init_valid_string(self):
        ipelem = net_elements.IPElement("192.168.3.119/24")
        self.assertEqual(ipelem.ip[0], '192.168.3.119')
        self.assertEqual(ipelem.ip[1], [192, 168, 3, 119])
        self.assertEqual(ipelem.mask, 24)

    def test_init_valid_keywords(self):
        ipelem = net_elements.IPElement(ip="192.168.3.119", mask=24)
        self.assertEqual(ipelem.ip[0], '192.168.3.119')
        self.assertEqual(ipelem.ip[1], [192, 168, 3, 119])
        self.assertEqual(ipelem.mask, 24)

    def test_init_invalid_string(self):
        with self.assertRaises(ValueError):
            net_elements.IPElement("spam/8")  # doesn't have dots
        with self.assertRaises(ValueError):
            net_elements.IPElement("ho.ho.ho.ho/8")  # not integers
        with self.assertRaises(ValueError):
            net_elements.IPElement("666.666.666.666/24")  # ip out of range
        with self.assertRaises(ValueError):
            net_elements.IPElement("192.168.3.119/8080")  # mask out of range

    def test_init_invalid_keywords(self):
        with self.assertRaises(ValueError):
            net_elements.IPElement(ip="spam", mask=8)  # doesn't have dots
        with self.assertRaises(ValueError):
            net_elements.IPElement(ip="ho.ho.ho.ho", mask="8")  # not integers
        with self.assertRaises(ValueError):
            net_elements.IPElement(ip="666.666.666.666", mask="24")  # ip out of range
        with self.assertRaises(ValueError):
            net_elements.IPElement(ip="192.168.3.119", mask="8080")  # mask out of range

    def test_is_network(self):
        net = net_elements.IPElement("192.168.3.0/24")
        not_net = net_elements.IPElement("192.168.3.119/24")
        self.assertTrue(net.is_network())
        self.assertFalse(not_net.is_network())

    def test_add(self):
        self.assertEqual(
            net_elements.IPElement("192.168.3.119/24") + 20,
            net_elements.IPElement("192.168.3.139/24")
        )

    def test_sub(self):
        self.assertEqual(
            net_elements.IPElement("192.168.3.119/24") - 19,
            net_elements.IPElement("192.168.3.100/24")
        )

    def test_repr(self):
        self.assertEqual(repr(net_elements.IPElement("192.168.3.0/24")), "<IPElement 192.168.3.0/24>")


class NetworkTestCase(unittest.TestCase):
    def test_init_valid_ipelement(self):
        net = net_elements.Network(
            net_elements.IPElement("192.168.3.0/24")
        )
        self.assertEqual(net.ip[0], "192.168.3.0")
        self.assertEqual(net.ip[1], [192, 168, 3, 0])
        self.assertEqual(net.mask, 24)

    def test_init_valid_string(self):
        net = net_elements.Network("192.168.3.0/24")
        self.assertEqual(net.ip[0], "192.168.3.0")
        self.assertEqual(net.ip[1], [192, 168, 3, 0])
        self.assertEqual(net.mask, 24)

    def test_init_invalid_ipelement(self):
        with self.assertRaises(ValueError):
            net_elements.Network(
                net_elements.IPElement("192.168.3.119/24")
            )

    def test_init_invalid_string(self):
        with self.assertRaises(ValueError):
            net_elements.Network("192.168.3.119/24")

    def test_len(self):
        net = net_elements.Network("192.168.3.0/24")
        self.assertEqual(len(net), 256)

    def test_force_length(self):
        net = net_elements.Network("192.168.3.0/24", force_length=10)
        self.assertEqual(net.forced_length, 10)
        self.assertEqual(len(net), 10)

    def test_iteration(self):
        net = net_elements.Network("192.168.3.0/24")
        for ipelem in net:
            pass
        self.assertEqual(ipelem.ip[0], "192.168.3.255")
        self.assertEqual(ipelem.mask, 24)

    def test_broadcast(self):
        self.assertEqual(net_elements.Network("192.168.3.0/24").broadcast(),
                         net_elements.IPElement("192.168.3.255/24")
        )

    def test_repr(self):
        self.assertEqual(repr(net_elements.Network("192.168.3.0/24")),
                         "<Network 192.168.3.0/24-256>"
        )


if __name__ == "__main__":
    unittest.main()
