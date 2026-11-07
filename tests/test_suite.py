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


    def test_no_name_is_defined_in_two_modules(self):
        # `rg` finds each name in the one module that defines it; a second module with the same name would make
        # tests read or replace the wrong one (a self-check `run` once shadowed the monitor's main loop)
        import ast
        homes = {}
        for f in sorted((support.ROOT / "ransomguard").glob("*.py")):
            for node in ast.parse(f.read_text(encoding="utf-8")).body:
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    names = [node.name]
                else:
                    names = [t.id for t in getattr(node, "targets", []) if isinstance(t, ast.Name)]
                for name in names:
                    self.assertNotIn(name, homes, f"{name} is defined in {homes.get(name)} and {f.stem}")
                    homes[name] = f.stem


if __name__ == "__main__":
    unittest.main()
