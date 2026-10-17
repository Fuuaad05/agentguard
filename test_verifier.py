
import unittest

from verifier import verify_code


class TestAgentGuardVerifier(unittest.TestCase):

    def check_categories(self, source, expected):
        result = verify_code(source)

        self.assertEqual(result["status"], "completed")

        actual = {
            item["category"]
            for item in result["evidence"]
        }

        self.assertEqual(actual, set(expected))

    def test_detects_eval(self):
        self.check_categories(
            "result = eval(user_input)",
            ["CWE-94"]
        )

    def test_ignores_eval_comment(self):
        self.check_categories(
            "# Never use eval(user_input)\nresult = 4",
            []
        )

    def test_ignores_eval_string(self):
        self.check_categories(
            'message = "eval(user_input) is dangerous"',
            []
        )

    def test_detects_sql_fstring(self):
        self.check_categories(
            'query = f"SELECT * FROM users WHERE id = {user_id}"',
            ["CWE-89"]
        )

    def test_ignores_parameterized_sql(self):
        self.check_categories(
            '''
import sqlite3
conn = sqlite3.connect(":memory:")
conn.execute(
    "SELECT * FROM users WHERE id = ?",
    (user_id,)
)
''',
            []
        )

    def test_detects_hardcoded_password(self):
        self.check_categories(
            '''
def login(password):
    return password == "admin123"
''',
            ["CWE-798"]
        )

    def test_ignores_password_hash_check(self):
        self.check_categories(
            '''
def login(password, stored_hash):
    return verify_password(password, stored_hash)
''',
            []
        )

    def test_detects_multiple_patterns(self):
        self.check_categories(
            '''
def calculate(expression):
    return eval(expression)

query = f"SELECT * FROM users WHERE name = '{username}'"

def authenticate(password):
    return password == "admin123"
''',
            ["CWE-94", "CWE-89", "CWE-798"]
        )

    def test_invalid_python(self):
        result = verify_code("def broken(")

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["evidence"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
