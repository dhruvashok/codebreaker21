from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
from hashlib import sha256
import time
import string
import multiprocessing as mp
import sys

# 1st: 1615896483 or before
# 2nd: 1615896494 or before
# 3rd: 1615896524 or before
# 4th: 1615896493 or before
# 5th: 1615896498 or before
# 6th: 1615896549 or before

def brute(n):
	magic_start = bytes.fromhex("17f4b888")
	magic_end = bytes.fromhex("efacc346")
	nonce = bytes.fromhex("2b5b4a5b952a2547ac7392da0594ff8fc93d81b51d490f11")
	enc_uuid = bytes.fromhex("c542a712ddb1c553fe2eb6a5f415b05a188e03f77136f63ed2f240c7dd23c58c08bffa65fa97d436fe3894d1764cdddde43a")
	# firstnames = open("firstnames.txt", errors="ignore").readlines()
	# firstnames = open("xato-net-10-million-usernames.txt", errors="ignore").readlines()
	# firstnames = string.ascii_lowercase
	firstnames = open("names.txt", errors="ignore").readlines()
	lastnames = ['']
	# lastnames = open("familynames-usa-top1000.txt", errors="ignore").readlines()
	# lastnames = string.ascii_lowercase
	# lastnames = ['a']
	count = 0

	firstnames = firstnames[n:n+2099]
	# lastnames = lastnames[:100]
	# lastnames = lastnames[n:n+250]

	for firstname in firstnames:
		for lastname in lastnames:
			for i in range(10000):
				for timestamp in range(1615896544, 1615896552):
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
	i = 0
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