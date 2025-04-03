import unittest
import asyncio
from pathlib import Path
from webhunter.modules.port_scanner import PortScanner

class TestPortScanner(unittest.TestCase):
    def setUp(self):
        self.test_output_dir = Path("c:/Users/nabar/OneDrive/Desktop/Project/results/test")
        self.test_output_dir.mkdir(parents=True, exist_ok=True)
        self.scanner = PortScanner(self.test_output_dir)
        self.test_target = "127.0.0.1"

    def tearDown(self):
        for file in self.test_output_dir.glob("*"):
            file.unlink()
        self.test_output_dir.rmdir()

    async def test_scan_ports(self):
        results = await self.scanner.scan_ports(self.test_target, "80,443,8080")
        self.assertIsInstance(results, dict)
        self.assertIn(self.test_target, results)

    def test_validate_ports(self):
        self.assertTrue(self.scanner._validate_ports("80"))
        self.assertTrue(self.scanner._validate_ports("1-1000"))
        self.assertTrue(self.scanner._validate_ports("80,443,8080"))
        self.assertFalse(self.scanner._validate_ports("invalid"))

if __name__ == '__main__':
    unittest.main()

