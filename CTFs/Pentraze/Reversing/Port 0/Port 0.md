# Writeup: Port 0 (Reversing + Cryptography (XorShift) )

> **By:** Randy Nin

---

## Initial Dynamic Reconnaissance

The challenge gives us a binary named `Port0.exe`, which is a 64-bit `PE32+` executable for Windows:

```bash
❯ file Port0.exe
Port0.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 7 sectionss
```

The first logical thing to do is run the binary to analyze it dynamically at runtime, and thus be able to observe what it does. When we run the binary it stays listening and initializes a server and shows us this output:  
![](resources/Pasted%20image%2020260921191539.png)

This output basically already tells us what this binary is about; keep the following in mind:

- **Lpc**Oracle.
- **Port Created**.
- **ProcCallCommandPort**.

This tells us that it created a "port". To verify well how it works and its type of communication, we proceed to inspect it at runtime with **Process Explorer** (from SysInternals).  
![](resources/Pasted%20image%2020260921192804.png)

The first thing we can observe is that it doesn't create any TCP or UDP port.

Enabling the lower pane view (Lower Pane View > Handles), we were able to review the handles opened by the process.  
![](resources/Pasted%20image%2020260921193409.png)

We found a handle of type **ALPC Port** pointing to the absolute path: `\BaseNamedObjects\ProcCallCommandPort` (the program was already giving us a "hint" about this).

### Summary of what ALPC is (Advanced Local Procedure Call)

> In summary, ALPC is an internal, high-speed, undocumented mechanism that Windows uses for inter-process communication (IPC). Unlike normal TCP ports where we can send plain text through tools like netcat or sockets, the Windows kernel is very strict with ALPC. If a client tries to connect and send data, it must do so using a structure called `PORT_MESSAGE`.

Trying to do fuzzing against this port can make us lose a lot of time trying to guess the exact size and structure of the message the server expects. Therefore, I decided to take it to **Ghidra** to decompile it and be able to inspect how it works from the source code.

---

## Static Analysis in Ghidra

Since we know that the binary uses ALPC, I proceeded to look for the server's main loop, searching for the Windows functions in charge of handling this port (like NtCreatePort, NtListenPort, NtReplyPort, etc.).

![](resources/Pasted%20image%2020260921205201.png)

![](resources/Pasted%20image%2020260921205422.png)

Finding two important functions in the structure of this server:

> - `FUN_1400033c0`: In this function we find calls to `NtCreatePort`, `NtListenPort`, and `NtAcceptConnectPort`. This function registers the path `\BaseNamedObjects\ProcCallCommandPort` in the operating system and handles the initial _handshake_ when a client knocks on the door.
> - `FUN_140003700`: In this one we find `NtReplyWaitReceivePort` and `NtReplyPort`. This function is an infinite loop (`while-true`) that catches the incoming messages, extracts the payload and returns a response.

---

## Analyzing

Analyzing in Ghidra's pseudocode, we discovered that the server reads and interprets our data. The program processes the client's input byte by byte.

When we send a message, there is a `for` loop that does the following:

- Reads the characters until it finds a space (`0x20`) or a null byte (`0`).
- Checks if the letter is lowercase and subtracts `0x20` from it to convert it to uppercase.
- Stores this first argument (the command) and separates the rest of the text as secondary arguments.

![](resources/Pasted%20image%2020260921212400.png)

Then the program uses a **Dispatch Table** located at memory address `0x14001f450`. The code compares our command with a list and if there is a match, it executes the associated function passing it our arguments.

The table exposes commands like (`STATUS`, `WHOAMI`, `UPTIME`), text manipulations (`REVERSE`, `UPPER`), and some commands that sound interesting

```assembly
                             PTR_DAT_14001f450
                             PTR_FUN_14001f468                               XREF[1]:     FUN_140003700:140003955(R)  
       14001f470 00 f9 01        addr       s_VERSION_14001f900                              = "VERSION"
       14001f490 10 f9 01        addr       s_WHOAMI_14001f910                               = "WHOAMI"
       14001f4a0 18 f9 01        addr       s_HOSTNAME_14001f918                             = "HOSTNAME"
       14001f4d0 2c f9 01        addr       s_TICKS_14001f92c                                = "TICKS"
       14001f4e0 34 f9 01        addr       s_UPTIME_14001f934                               = "UPTIME"
       14001f550 60 f9 01        addr       s_REVERSE_14001f960                              = "REVERSE"
       14001f560 68 f9 01        addr       s_UPPER_14001f968                                = "UPPER"
       14001f570 70 f9 01        addr       s_LOWER_14001f970                                = "LOWER"
       14001f5e0 9c f9 01        addr       s_EXISTS_14001f99c                               = "EXISTS"
       14001f5f0 a4 f9 01        addr       s_COUNT_14001f9a4                                = "COUNT"
       14001f620 bc f9 01        addr       s_SUMMON_14001f9bc                               = "SUMMON"
       14001f630 c4 f9 01        addr       s_PROVE_14001f9c4                                = "PROVE"
       14001f650 d4 f9 01        addr       s_UNVEIL_14001f9d4                               = "UNVEIL
```

After seeing the name "UNVEIL", I dug deeper into the function that executes that command.

---

## Analyzing `UNVEIL`

Analyzing the pseudocode of the function associated with `UNVEIL` (`FUN_140002d10`), we clearly see that its logic is divided into two parts:

- A validation.
- Decryption of the flag.

### The validation

The server generates a key in memory and compares it with the arguments we send (param_2). If we fail this validation, the program will enter an `if` where the hexadecimal `0x64657463656a6572` will be written in the response. Basically this message, which is in Little-Endian ("backwards"), is one that says "rejected".  
![](resources/Pasted%20image%2020260921230623.png)

### Encryption and Seed (The flag)

If we pass the validation we enter this `else` block, where basically the most important thing to solve this challenge is found (at least the way I did it). The program initializes an array of 64 bytes that may look random (the encrypted flag) and sets a variable (`uVar5`) equal to `0xdeadbeefcafebabe` (the cryptographic seed), which is a very well-known hexadecimal value very often seen in CTFs.

Then, it enters a block where it performs 64 iterations that do the following mathematical operations on the seed:

```c
uVar5 = uVar5 << 0x15 ^ uVar5;
uVar5 = uVar5 >> 0x23 ^ uVar5;
uVar5 = uVar5 << 4 ^ uVar5;
```

Basically, these operations are bit shifts to the left by 21, to the right by 35 and left by 4, combined with XORs against the seed. Looking into these I found that they are a super fast pseudo-random generator (PRNG) named `Xorshift64`.

The program uses this algorithm to mutate the seed on each iteration. From each mutation, it extracts a byte and applies a logical XOR operation (`^`) to the original 64-byte array to reveal the flag in clear text before sending it over the network.  
![](resources/Pasted%20image%2020260921232356.png) ![](resources/Pasted%20image%2020260921232427.png)

---

## Obtaining the flag

The normal thing to do here would be to continue and try to guess or somehow obtain the key that `UNVEIL` receives (`param_2`) and then try to develop a client that communicates with this server and send it.

However, since I don't reach that level of skill (xd), there is an advantage, and it is that XOR is a reversible mathematical operation. And since we already have the 64 encrypted bytes, the seed and the algorithm it is decrypted with, it is not necessary to try to interact with this server or do a much more complicated dynamic analysis. We can simply emulate this locally and reproduce the flag.

Simply taking the array with the encrypted bytes, the seed and the logic, we can make a simple C script that replicates this:

```c
#include <stdio.h>
#include <stdint.h>

int main() {
    // The initial seed extracted from Ghidra
    uint64_t seed = 0xdeadbeefcafebabe;

    // The 64 encrypted bytes extracted from the local_58 buffer
    uint8_t flag[64] = {
        0x07, 0xe6, 0xc9, 0x61, 0xca, 0xc3, 0x47, 0xee, 
        0x4f, 0xe6, 0x99, 0x6d, 0x2e, 0x6a, 0xb2, 0x56, 
        0x45, 0x63, 0x5f, 0xef, 0xc8, 0xca, 0x38, 0x1d, 
        0x8b, 0x1f, 0x96, 0x51, 0x25, 0x5e, 0x59, 0x09, 
        0x06, 0x59, 0xe1, 0x56, 0xcb, 0x60, 0x8e, 0x5d, 
        0x8f, 0x70, 0x1b, 0x69, 0x90, 0x61, 0xd2, 0xd6, 
        0x39, 0x23, 0x7d, 0x8d, 0x3c, 0xc4, 0xc7, 0x90, 
        0x05, 0xe7, 0xc0, 0x03, 0x0b, 0xc5, 0x7c, 0x11
    };

    printf("[+] Decrypting the flag...\n\n");

    for (int i = 0; i < 64; i++) {
        // Xorshift64 PRNG generator
        seed ^= seed << 21;
        seed ^= seed >> 35;
        seed ^= seed << 4;
        
        // Extraction of the dynamic 1-byte key and XOR operation
        uint8_t key_byte = (seed >> 24) ^ (seed >> 16) ^ (seed & 0xFF);
        flag[i] ^= key_byte;
        
        // Print the decrypted character
        printf("%c", flag[i]);
    }
    
    printf("\n\n[+] Process finished.\n");
    return 0;
}
```

This way, as I said before, we save ourselves all the complexity of interacting with this server, doing a dynamic analysis, researching more about this ALPC thing, etc. Simply by compiling and running this script we can obtain these bytes in clear text:

![](resources/Pasted%20image%2020260921233719.png)
