"""Tests: the test suite itself. Shared helpers and the safety net are in support.py."""
import importlib
import unittest
from pathlib import Path

import support

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


class SuiteTests(unittest.TestCase):
    def test_every_test_file_installs_the_safety_net(self):
        # without it, a test could reach the real network settings, the installed program or the user's folders
        files = sorted(Path(__file__).parent.glob("test_*.py"))
        self.assertGreater(len(files), 5)
        for f in files:
            module = importlib.import_module(f.stem)
            self.assertIs(getattr(module, "setUpModule", None), support.setUpModule, f.name)
            self.assertIs(getattr(module, "tearDownModule", None), support.tearDownModule, f.name)


if __name__ == "__main__":
    unittest.main()
