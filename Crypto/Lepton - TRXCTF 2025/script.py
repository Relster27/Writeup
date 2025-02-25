import socket
import re
import hashlib
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def solve_lepton():
    # Server details
    host = "lepton.ctf.theromanxpl0.it"
    port = 7004
    
    # Pre-compute the AES key (SHA-256 hash of "0")
    # When we send (0,0), the isogeny will map it to (0,0) on the final curve
    # So the x-coordinate used for the key will be 0
    secret_key = hashlib.sha256(str(0).encode()).digest()
    print(f"Using secret key: {secret_key.hex()}")
    
    # Maximum number of attempts
    max_attempts = 10
    
    for attempt in range(max_attempts):
        print(f"\nAttempt {attempt+1}/{max_attempts}")
        
        # Connect to the server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)  # Set a timeout
        
        try:
            s.connect((host, port))
            
            # Read until we get the prompt
            buffer = ""
            while True:
                try:
                    data = s.recv(4096).decode('latin1', errors='replace')
                    if not data:
                        print("Connection closed")
                        break
                    
                    buffer += data
                    print(data, end="")
                    
                    if "[?] Send me your point on the curve" in buffer:
                        # Send our point (0,0)
                        s.sendall(b"0,0\n")
                        print("\nSent point: 0,0")
                        
                        # Get the response (encrypted flag)
                        response = s.recv(4096).decode('latin1', errors='replace')
                        print(f"Response: {response}")
                        
                        # Extract hex string (encrypted flag)
                        hex_match = re.search(r'([0-9a-f]{32,})', response)
                        if hex_match:
                            hex_ciphertext = hex_match.group(1)
                            try:
                                # Convert to bytes and decrypt
                                ciphertext = bytes.fromhex(hex_ciphertext)
                                cipher = AES.new(secret_key, AES.MODE_ECB)
                                decrypted = cipher.decrypt(ciphertext)
                                
                                # Try to unpad and decode
                                flag = unpad(decrypted, 16).decode()
                                if '{' in flag and '}' in flag:
                                    print(f"\nFlag found: {flag}")
                                    return flag
                                print(f"Decrypted text: {flag}")
                            except Exception as e:
                                print(f"Decryption error: {e}")
                        break
                except socket.timeout:
                    print("Timeout reading from socket")
                    break
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            s.close()
        
        # Wait before trying again
        time.sleep(1)
    
    print("Failed to retrieve the flag after multiple attempts")

if __name__ == "__main__":
    solve_lepton()