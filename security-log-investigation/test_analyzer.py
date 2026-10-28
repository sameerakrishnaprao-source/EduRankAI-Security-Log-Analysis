import subprocess, sys, pathlib, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parent

class AnalyzerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = pathlib.Path(tempfile.mkdtemp()) / "out.txt"
        r = subprocess.run([sys.executable, str(ROOT / "analyze_logs.py"), "--out", str(out)],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        cls.text = r.stdout

    def test_brute_force_detected(self):
        self.assertIn("Failed logins from 203.0.113.45: 42", self.text)
        self.assertIn("SUCCESSFUL login 'deploy'", self.text)

    def test_powershell_decoded(self):
        self.assertIn("DownloadString('http://198.51.100.77/a.ps1')", self.text)

    def test_beaconing_detected(self):
        self.assertIn("BEACONING every ~60s", self.text)

    def test_web_attacks_detected(self):
        self.assertIn("SQL injection", self.text)
        self.assertIn("Path traversal", self.text)
        self.assertIn("Webshell", self.text)

if __name__ == "__main__":
    unittest.main()
