import unittest
import asyncio
from pathlib import Path
from webhunter.modules.subdomain_enum import SubdomainEnumerator

class TestSubdomainEnumerator(unittest.TestCase):
    def setUp(self):
        self.test_output_dir = Path("c:/Users/nabar/OneDrive/Desktop/Project/results/test")
        self.test_output_dir.mkdir(parents=True, exist_ok=True)
        self.enumerator = SubdomainEnumerator(self.test_output_dir)
        self.test_domain = "example.com"

    def tearDown(self):
        # Cleanup test files
        for file in self.test_output_dir.glob("*"):
            file.unlink()
        self.test_output_dir.rmdir()

    def test_load_tools(self):
        tools = self.enumerator.available_tools
        self.assertIsInstance(tools, list)
        self.assertTrue(len(tools) > 0)

    async def test_run_subfinder(self):
        results = await self.enumerator.run_subfinder(self.test_domain)
        self.assertIsInstance(results, list)

    async def test_run_amass(self):
        results = await self.enumerator.run_amass(self.test_domain)
        self.assertIsInstance(results, list)

    def test_save_results(self):
        test_subdomains = ["test1.example.com", "test2.example.com"]
        self.enumerator._save_results("test_output.txt", test_subdomains)
        self.assertTrue((self.test_output_dir / "test_output.txt").exists())

    def test_validate_domain(self):
        self.assertTrue(self.enumerator._validate_domain("example.com"))
        self.assertFalse(self.enumerator._validate_domain("invalid@domain"))

if __name__ == '__main__':
    unittest.main()

