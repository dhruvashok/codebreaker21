from nacl.secret import SecretBox
from hashlib import sha256

u, v, t = "ryder", "1.8.1.5", "1615896548"
key = sha256(f"{u}+{v}+{t}".encode()).digest()

box = SecretBox(key)
while True:
# a = bytes.fromhex(open("test.txt").read().strip())
	a = bytes.fromhex(input())
	nonce, ct = a[4:28], a[28:]
	print(box.decrypt(ct, nonce))
	print(box.decrypt(ct, nonce).hex())
