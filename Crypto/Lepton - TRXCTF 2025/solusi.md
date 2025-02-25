# CTF Challenge Writeup: Lepton

## Challenge Information
- **Name**: Lepton
- **Category**: Crypto
- **Solved by**: Trendo
- **Description**:
> In the final days of Rome's intellectual golden age, the philosopher Lucius Isogenius arrived before the Senate, disheveled, eyes burning with madness.
> "I have seen beyond numbers," he proclaimed. "Primes are shackles. Modular arithmetic is a crude tool for simple minds. But I— I have forged a cipher that bends the very fabric of reality!"
> The Senate groaned.
> "The key exchange is weightless," Isogenius continued. "The transformation exists in a space unseen. There are no inverses, no reductions—only a sequence of isogenies guiding the message through dimensions unknown."
> One senator raised a hand. "Lucius, will this work?"
> Isogenius laughed. "Work? This system is beyond working. It is untouchable. It is the final encryption."
> They let him build it. They let him encrypt the most delicate secrets of Rome. They let him construct his temple of mathematical absurdity. And then, as always, the Numerii began their work.
- **Server**: `lepton.ctf.theromanxpl0.it:7004`


## Analysis

### Code Analysis

The provided code implements a custom cryptographic scheme based on isogenies. Let's understand its key components:

```python
# CSIDH-512 prime construction
ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 
        149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 
        227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
        307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
p = 4 * prod(ells) - 1
F = GF(p)
E0 = EllipticCurve(F, [1, 0])  # Base curve in Montgomery form y^2 = x^3 + x

# Generate secret vector (fixed for each server instance)
secret_vector = [randint(0, 1) for _ in range(len(ells))]
```

The protocol works as follows:

1. The server starts with a base elliptic curve E0 in Montgomery form
2. It generates a fixed secret vector (an array of 0s and 1s)
3. For each connection:
   - It applies a random isogeny to get an intermediate curve E
   - It sends the A-coefficient of this Montgomery curve to the client
   - It asks the client to provide a point on this curve
   - It applies another isogeny (determined by the secret vector) to E
   - It maps the client's point using this isogeny to get a new point Q
   - It uses Q's x-coordinate to derive an AES key
   - It encrypts the flag with this key and sends it to the client

```python
def walk_isogeny(E, exponent_vector):
    # Generate a random point P
    P = E.random_point()
    o = P.order()
    # Calculate the order we need
    order = prod(ells[i] for i in range(len(ells)) if exponent_vector[i] == 1)
    # Find a point with the right order
    while o % order:
        P = E.random_point()
        o = P.order()
    # Scale P to have exactly the order we want
    P = o // order * P
    # Compute the isogeny with kernel <P>
    phi = E.isogeny(P, algorithm='factored')
    # Get the codomain (target curve)
    E = phi.codomain()
    return E, phi
```

## The Vulnerability

The key vulnerability lies in how Montgomery curves and isogenies interact with special points on the curve.

For a Montgomery curve of the form E: y² = x³ + ax² + x:
- The point (0,0) is always a 2-torsion point (i.e., 2·(0,0) = O, the point at infinity)

The most important property: **when applying isogenies of odd degree (all elements in `ells` are odd primes), the 2-torsion point (0,0) is preserved**.

This means:
1. The point (0,0) is not in the kernel of any of the isogenies used
2. When we apply the isogeny to (0,0), it will map to (0,0) on the new curve

## The Exploit

Our exploit is beautifully simple:
1. When the server presents the intermediate curve and asks for a point, we provide (0,0)
2. The server applies the secret isogeny, which maps (0,0) to (0,0) on the final curve
3. The x-coordinate used for AES key derivation will always be 0
4. We can pre-compute the key: `sha256("0".encode()).digest()`

This allows us to decrypt the flag without needing to know the secret vector.

## Implementation

Here's the exploit script:

```python
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
```

## Execution and Result

When running the exploit script, we connect to the server, send the point (0,0), and receive an encrypted flag. After decryption, we get:

![image](https://github.com/user-attachments/assets/743816c8-c451-4253-9be1-4c60e1960640)


## Mathematical Explanation

For those interested in the deeper mathematics:

1. A Montgomery curve E: y² = x³ + ax² + x has a point (0,0) that satisfies the equation (since 0³ + a·0² + 0 = 0)
2. This point has order 2 (doubling gives the point at infinity)
3. An isogeny ϕ: E → E' of degree ℓ (where ℓ is odd) cannot have (0,0) in its kernel
4. When applying such an isogeny to (0,0), it maps to the 2-torsion point on the image curve, which is again (0,0)
5. This property holds for compositions of such isogenies, which is exactly what the protocol uses


## Flag
```
TRX{1_R34lly_1n_l0v3_w17h_crypt0}
```

Unfortunately, I couldn't solve this challenge during the event. TRX CTF was indeed very difficult and challenging.
