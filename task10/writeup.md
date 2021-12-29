# Task 10
## Getting Persistence
Alright, this is gonna be a long one. Buckle up, y'all! 

After solving Task 9, your goal should be to get persistence on the LP as `lpuser`. If you've properly written your script to interact with the LP, this shouldn't be too difficult. Jumping around the home directory of `lpuser` (`/home/lpuser/`) reveals that there's a `.ssh` directory, along with a public/private keypair we can read! If we read `/home/lpuser/.ssh/id_rsa`, we should now have the private key to connect to the LP's SSH server as `lpuser`. This is the "**Gain access to the LP**" part of the task.
## Enumerating
The second goal for this task is to "**Provide the IP and port that the `psuser` account has trasmitted data to**". Since we're currently `lpuser`, we need to see what potential vectors we have to escalate our privileges to `psuser`. Digging around `/home/psuser` is a good place to start. We see some files, including a couple of logs (`ps_server.log` and `ps_data.log`), as well as a file named `powershell_lp`. Running `ps aux | grep psuser`, which lists running processes and filters them to those that `psuser` is running should also give us an idea of what `psuser` is up to on this box that we could exploit. We are able to see that it's running the `powershell_lp` file through another script (`runPs.sh`). At this point, we've sufficiently established that this is what we're looking for. To be safe, I copied off a couple other files in the home directory but only the `powershell_lp` file is really needed.
## Initial Analysis
We need to now analyze the `powershell_lp` file. Running `file powershell_lp` will give us ![](https://i.imgur.com/R9vpHIM.png)

Ah, a stripped binary with PIE. Fun.

Stripped binaries aren't very fun to look at, but disassemblers will often use function hashes to "put back" some common functions. Think of a stripped binary like getting a box of random fruits. You've probably seen some of the fruits before because they're common, even if there are some fruits that you don't recognize. In this way, disassemblers can tell where common functions like `read()` and `write()` are by storing their hashes and comparing the stored hashes to hashes of functions in the binary. Even though this is an NSA challenge and Ghidra was very helpful on prior tasks, I found more luck analyzing the binary with Binary Ninja. But let's look at this binary dynamically first.

The binary contains a **lot** of functions, but with function hashing, we can identify the subset that are user-written and not just part of a standard library. Let's start with some dynamic analysis first, though. If we run the binary with `./powershell_lp`, we see that two new files, `ps_server.log` and `ps_data.log`, are created. We also get an output message: "**Server started port 8080**". 

Let's connect to the server and see what's up. If we run `nc localhost 8080`, we're able to connect but don't seem to get anything back even if we send input. It looks like `ps_server.log` recorded the incoming connection's PID (process ID), IP/port, and exit code. It also says "**Child X handling...**", so this binary probably forks to a child process to handle an incoming connections. That piece of info is important for later, but for now, let's keep exploring.

Aha! Remember Task 3 where the **Powershell** malware communicated with an **HTTP** server on **port 8080** to send private keys? Let's try an HTTP request to `http://localhost:8080`, specifically a `POST` request like in the [malware](https://github.com/dhruvashok/codebreaker21/blob/main/task4/malicious.ps1#L311).

Ok, cool! We see that the dummy data we sent also got logged in the `ps_data.log` file now! Let's turn to some static analysis now.

## Finding the Vulnerability
This section would be *very* long if I went over all the different things in this binary. When I analyzed the binary, I assumed the vulnerability would be in how the HTTP request data was handled. I happened to be correct here. To make it simpler, I'm just going to show the disassembly of the vulnerable section and explain it.

![](https://i.imgur.com/hmjjQSy.png)

This doesn't look super useful or suspicious unless I add some context, so let's do that.

![](https://i.imgur.com/GA20GGN.png)

Ok, that's better. So what is the program doing here? The `recv()` function a minimum of three arguments: the file descriptor to read from, the buffer to read the bytes into, and the number of bytes to read. `recv()` is also placed in a while loop here, so while the number of bytes the program has received is less than the maximum number of bytes (which is `4096`), we will try to read more bytes from the socket into the buffer. Specifically, we are reading **4096** bytes EVERY time into the buffer.