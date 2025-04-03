import unittest
import asyncio
from pathlib import Path
from webhunter.modules.vuln_scanner import VulnerabilityScanner

class TestVulnerabilityScanner(unittest.TestCase):
    def setUp(self):
        self.test_output_dir = Path("c:/Users/nabar/OneDrive/Desktop/Project/results/test")
        self.test_output_dir.mkdir(parents=True, exist_ok=True)
        self.scanner = VulnerabilityScanner(self.test_output_dir)
        self.test_target = "http://testphp.vulnweb.com"

    def tearDown(self):
        # Cleanup test files
        for file in self.test_output_dir.glob("*"):
            file.unlink()
        self.test_output_dir.rmdir()

    async def test_scan_xss(self):
        results = await self.scanner.scan_xss([self.test_target])
        self.assertIsInstance(results, list)
        for result in results:
            self.assertIn('target', result)
            self.assertIn('vulnerability', result)

    async def test_run_nuclei(self):
        results = await self.scanner.run_nuclei([self.test_target])
        self.assertIsInstance(results, list)

    def test_save_results(self):
        test_results = [{
            'target': self.test_target,
            'vulnerability': 'XSS',
            'details': 'Test vulnerability'
        }]
        self.scanner.save_results(test_results)
        self.assertTrue((self.test_output_dir / "vulnerabilities.json").exists())

    def test_validate_target(self):
        self.assertTrue(self.scanner._validate_target("http://example.com"))
        self.assertTrue(self.scanner._validate_target("https://example.com"))
        self.assertFalse(self.scanner._validate_target("invalid-url"))

if __name__ == '__main__':
    unittest.main()

