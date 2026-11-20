import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from Network import normalize_addresses, local_addresses

class AddressTests(unittest.TestCase):
    def test_private_adapters_and_duplicate_addresses(self):
        records = [
            {"IPAddress":"172.20.1.5","InterfaceAlias":"VPN"},
            {"IPAddress":"192.168.1.2","InterfaceAlias":"Ethernet"},
            {"IPAddress":"10.1.2.3","InterfaceAlias":"WLAN"},
            {"IPAddress":"192.168.1.2","InterfaceAlias":"Ethernet"},
            {"IPAddress":"127.0.0.1","InterfaceAlias":"Loopback"},
            {"IPAddress":"169.254.1.1","InterfaceAlias":"Unassigned"},
            {"IPAddress":"8.8.8.8","InterfaceAlias":"Public"},
            {"IPAddress":"fe80::1","InterfaceAlias":"IPv6"},
            {"IPAddress":"invalid"},
            None,
        ]
        self.assertEqual(normalize_addresses(records), [
            ("192.168.1.2","Ethernet"),("172.20.1.5","VPN"),("10.1.2.3","WLAN")])

    @unittest.skipUnless(sys.platform == "win32", "Windows adapter query")
    def test_windows_single_and_multiple_adapter_output(self):
        for raw, count in [('{"IPAddress":"10.1.2.3","InterfaceAlias":"Ethernet"}',1),
                           ('[{"IPAddress":"10.1.2.3","InterfaceAlias":"Ethernet"},{"IPAddress":"172.20.1.5","InterfaceAlias":"VPN"}]',2),
                           ('',0)]:
            with patch("Network.subprocess.run") as command:
                command.return_value.stdout = raw
                self.assertEqual(len(local_addresses()),count)
                self.assertFalse(command.call_args.kwargs.get("shell",False))

    @unittest.skipUnless(sys.platform == "win32", "Windows adapter query")
    def test_real_windows_query(self):
        result=local_addresses()
        self.assertIsInstance(result,list)
        for ip, alias in result:
            self.assertTrue(alias)

if __name__ == "__main__":
    unittest.main()
