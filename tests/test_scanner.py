import unittest
from src.analyzer import PythonVulnerabilityScanner
from src.train_model import train_and_evaluate

class TestHybridVulnerabilityScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metrics = train_and_evaluate()
        cls.scanner = PythonVulnerabilityScanner()

    def test_detect_sql_injection(self):
        code = 'def get_u(cur, uid):\n    cur.execute(f"SELECT * FROM users WHERE id = {uid}")'
        res = self.scanner.scan_code(code)
        self.assertEqual(res["vulnerabilities_found"], 1)
        self.assertEqual(res["findings"][0]["vulnerability_type"], "SQL_INJECTION")
        self.assertEqual(res["findings"][0]["dangerous_lines"][0]["line_number"], 2)

    def test_detect_command_injection(self):
        code = 'import os\ndef ping(ip):\n    os.system("ping " + ip)'
        res = self.scanner.scan_code(code)
        self.assertEqual(res["vulnerabilities_found"], 1)
        self.assertEqual(res["findings"][0]["vulnerability_type"], "COMMAND_INJECTION")

    def test_detect_deserialization(self):
        code = 'import pickle\ndef load_p(data):\n    return pickle.loads(data)'
        res = self.scanner.scan_code(code)
        self.assertEqual(res["vulnerabilities_found"], 1)
        self.assertEqual(res["findings"][0]["vulnerability_type"], "INSECURE_DESERIALIZATION")

    def test_detect_hardcoded_secret(self):
        code = 'def auth():\n    password = "SuperSecretPassword123"\n    return password'
        res = self.scanner.scan_code(code)
        self.assertEqual(res["vulnerabilities_found"], 1)
        self.assertEqual(res["findings"][0]["vulnerability_type"], "HARDCODED_SECRET")

    def test_safe_code_no_false_positives(self):
        code = 'import json\ndef parse(s):\n    return json.loads(s)'
        res = self.scanner.scan_code(code)
        self.assertTrue(res["is_clean"])

if __name__ == "__main__":
    unittest.main()
