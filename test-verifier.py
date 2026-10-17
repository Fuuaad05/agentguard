
from verifier import verify_code

sample = '''
import sqlite3

def calculate(expression):
    return eval(expression)

def get_user(username):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()

def authenticate(password):
    if password == "admin123":
        return True
    return False
'''

result = verify_code(sample)

for item in result["evidence"]:
    print(
        f'{item["category"]} | '
        f'Line {item["line"]} | '
        f'{item["description"]}'
    )

print(f'\nTotal patterns confirmed: {result["total"]}')

assert result["total"] == 3, "Expected three security patterns"
print("VERIFIER TEST PASSED")
