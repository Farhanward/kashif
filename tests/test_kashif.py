from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from kashif.scanner import scan_path


class KashifTests(unittest.TestCase):
    def test_scans_vulnerable_project(self):
        report = scan_path(Path("examples") / "vulnerable_project")
        codes = {finding.code for finding in report.findings}
        self.assertIn("PY_SHELL_TRUE", codes)
        self.assertIn("PICKLE_LOAD", codes)
        self.assertIn("HARDCODED_SECRET", codes)
        self.assertGreaterEqual(report.stats["finding_count"], 4)

    def test_extracts_python_symbols(self):
        report = scan_path(Path("examples") / "vulnerable_project")
        app = next(item for item in report.files if item.path == "app.py")
        self.assertTrue(any("FunctionDef:run_user_command" in symbol for symbol in app.symbols))

    def test_python_ast_avoids_comments_and_strings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "safe.py").write_text(
                "# subprocess.check_output(command, shell=True)\n"
                "text = 'eval(user_input) and pickle.loads(data)'\n"
                "print(text)\n",
                encoding="utf-8",
            )
            report = scan_path(root)
            codes = {finding.code for finding in report.findings}
            self.assertNotIn("PY_SHELL_TRUE", codes)
            self.assertNotIn("PY_EVAL", codes)
            self.assertNotIn("PICKLE_LOAD", codes)


if __name__ == "__main__":
    unittest.main()
