# Description

Divide and Conquer is an algorithm that is commonly applied in programming to solve a complex problem by dividing it into many simpler sub-problems. We can apply this approach to offensive security with a different goal: consufe EDRs so they lose track of our activities, preventing them from raising any alert. This is something similar of what can be seen lately on almost any phishing campaing in the wild: long infection chains, running multiple files step by step (e.g. .url -> .one -> .js -> .bat -> .dll) instead of running directly the final payload. Each one of the files executed performs a simple task (download another file, make any change in the registry, move files between directories or change their names/extensions and so on) that is hard to tag as malicious by itself, preparing the environment for the final execution.

I decided to test this simple idea but applied to something different, in this case, a remote process injection. The code presented in this repository is nothing new, on the contrary, it is probably one of the most common and straightfoward ways to inject a shellcode in a remote process: to make use of NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory and NtCreateThreadEx. The shellcode simply spawns a new **cmd /k msg "hello from kudaes"**. The only difference is that I'm forking the process using NtCreateUserProcess after each one of those calls. Since the forked process continues with the execution from RIP + 1 and the memory is entirely copied from the parent, we can perform the remote process injection but using 5 different processes, we just need to make sure that any handle required for the subsequent API calls is properly inherited.

I've test this PoC against three of the most common EDRs nowadays: MDE, CrowdStrike and SentinelOne. The results speak for themselves: 2 out 3 EDRs raised a Remote Process Injection alert when running the PoC without the forks; on the contrary, none of them raised any alert once I introduced the forking mechanism. 

Of course, even with the fork mechanism we can see in the raw telemetry the events corresponding to process creation, thread creation and also all the cross process behavior, but it seems it is not enough for the EDRs to tag the activity as malicious, proving the point of this PoC. By spliting the malicious behaviour into simpler tasks and running them from a different process each one we confuse and prevent the EDRs from raising any alert.

This same result could be achieved in different ways, I just used the fork mechanism to simplify my code and reduce the cross process activity between the spawned processes. 

If you want to test this by yourself, compile the code with and without the calls to the function fork(), and then run both payloads in an environment with the desired EDR.

# Compilation 

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals (just for the Dinvoke_rs code), it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	C:\Users\User\Desktop\RustChain> set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

After that, simply compile the code and run the tool:

	C:\Users\User\Desktop\Split> cargo build --release
	C:\Users\User\Desktop\Split\target\release> split.exe -h

# Limitations

This technique by its own is not enough to bypass a EDR; if your code is none opsec at all, it is very probably that you will get caught anyway. This is not a golden bullet, just another layer of evasion that you can add to your tools. Nonetheless, the code presented in this repository is not opsec at all for the following reasons among others:

- Plain text shellcode. Moreover, the shellcode spawns a cmd once it is executed.
- No use of syscalls.
- No unhooking.
- Etw not pached. 
- Despite the use of Dinvoke_rs, im not encrypting some string literals that show away the APIs that im using.

On the other hand, I just have tested this approach against the mentioned EDRs, and I don't know if other EDRs will be bypassed as well. You can test it and let me know how it went ;)

# Credits

* [Deep Instinct](https://github.com/deepinstinct) for their [Dirty-Vanity](https://github.com/deepinstinct/Dirty-Vanity) tool and research and for the shellcode template.
