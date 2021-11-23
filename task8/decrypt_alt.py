from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
from hashlib import sha256
import time
import string
import multiprocessing as mp
import sys

# 1st: 1615896483 or before
# ab0433b868d241c801dc2c6b48f9e7f05406522375465be2, 3007f61b3cac5aa5fa815c93153adaf16fc0aad04b0df3f01e9f3129d826d2b150cbe2578fe0b98c2a86f137c0abca873c47
# 2nd: 1615896494 or before
# b6bab8e6bd616ceaf4290e4cab0765361f2c891690df1e06, 2323d74a8d49eb14e3090bae44abf17a45977bfee987f10fd3f001690d1ac5161eaf62912d9cd4c3a05e419fb7aba75c9a61
# 3rd: 1615896524 or before
# d7730c711c7190d23fa6b8b321629f2645fc9b6c24df0012, 8a9f205cfea6e977f42f57edcd67a5a09cad9e92252f2205c11bd3011c3e92c7ae51ef814527a39b0f39ef95779d5a9c5b99
# 4th: 1615896493 or before
# feeeada62f976f253b3d1fc5e1b5613e5189d77e6c24fcdd, a49a07c112abe6f0d577ef638819627c5c6ba56a442f20cc1c2e211b98ec450569a9819b6683ea3d1f4d82804df321076e56
# 5th: 1615896498 or before
# 95d3035aa49bc6714ef422aac8421aeec56bb5571e2ada8a, fb8d2317e08bed80e6bbeec14d208b0e58bc2df5e92dac3ed6a57afbf52ffde9789fcf0210de5ad7eda88eca7c30e0750711
# 6th: 1615896549 or before
# 2b5b4a5b952a2547ac7392da0594ff8fc93d81b51d490f11, c542a712ddb1c553fe2eb6a5f415b05a188e03f77136f63ed2f240c7dd23c58c08bffa65fa97d436fe3894d1764cdddde43a

def brute(n):
	magic_start = bytes.fromhex("17f4b888")
	magic_end = bytes.fromhex("efacc346")
	nonce = bytes.fromhex("feeeada62f976f253b3d1fc5e1b5613e5189d77e6c24fcdd")
	enc_uuid = bytes.fromhex("a49a07c112abe6f0d577ef638819627c5c6ba56a442f20cc1c2e211b98ec450569a9819b6683ea3d1f4d82804df321076e56")
	# firstnames = open("firstnames.txt", errors="ignore").readlines()
	# firstnames = open("xato-net-10-million-usernames.txt", errors="ignore").readlines()
	firstnames = open("names.txt", errors="ignore").readlines()
	# firstnames = string.ascii_lowercase
	lastnames = ['']
	# lastnames = open("familynames-usa-top1000.txt", errors="ignore").readlines()
	# lastnames = string.ascii_lowercase
	count = 0

	firstnames = firstnames[n:n+2099] # normally 480 or 50
	# lastnames = lastnames[:100]
	# lastnames = lastnames[n:n+250]

	for firstname in firstnames:
		for lastname in lastnames:
			for i in range(10000):
				for timestamp in range(1615896488, 1615896496): # expand this more??
					u = firstname.strip().lower() + lastname.strip().lower()
					version = ''.join(x+"." for x in str(i).zfill(4))[:-1]
					key = sha256(f"{u}+{version}+{timestamp}".encode()).digest()

					box = SecretBox(key)
					try:
						uuid = box.decrypt(enc_uuid, nonce)
						print("YOU ACTUALLY DECRYPTED SOMETHING YOU ABSOLUTE MADLAD.")
						print(f"The UUID is: {uuid.hex()}")
						print(f"The version is: {version}")
						print(f"The username is: {u}")
						print(f"The timestamp is: {timestamp}")
						sys.exit(0)
					except CryptoError:
						pass
		count += 1
		if count % 250 == 0:
			print(f"[+] {firstname.strip().lower()} at {int(time.time())}")

if __name__ == "__main__":
	i = 0 # change to 0 when done
	n = 2099
	process1 = mp.Process(target=brute, args=(i,))
	process2 = mp.Process(target=brute, args=(i+n,))
	process3 = mp.Process(target=brute, args=(i+n*2,))
	process4 = mp.Process(target=brute, args=(i+n*3,))

	process1.start()
	process2.start()
	process3.start()
	process4.start()

	process1.join()
	process2.join()
	process3.join()
	process4.join()