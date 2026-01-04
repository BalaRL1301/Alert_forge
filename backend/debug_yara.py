import yara
import sys

rules_path = "rules.yar"

try:
    rules = yara.compile(filepath=rules_path)
    print("Rules compiled successfully.")
except Exception as e:
    print(f"Compilation Failed: {e}")
    sys.exit(1)

# Sample payloads from the logs
test_logs = [
    "Login attempt for user: ') OR ('1'='1 from IP: 127.0.0.1",
    "SELECT * FROM users WHERE username = '') OR ('1'='1'",
    "Login attempt for user: admin' # from IP: 127.0.0.1",
    "Login attempt for user: admin' -- from IP: 127.0.0.1"
]

print("\nTesting Logs:")
for log in test_logs:
    matches = rules.match(data=log)
    if matches:
        print(f"[MATCH] '{log}' -> {[m.rule for m in matches]}")
    else:
        print(f"[NO MATCH] '{log}'")
