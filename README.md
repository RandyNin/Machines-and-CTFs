# Machines-and-CTFs

Writeups for **Hack The Box** machines and challenges, and for challenges from **CTF platforms and events**.

Each writeup covers the full path, from reconnaissance to the flag. It explains why each step works, not just which commands to run.

## Writeups

### Hack The Box: Machines

| Machine | OS | Difficulty | Highlights |
|---|---|---|---|
| [Nibbles](HTB/Machines/Nibbles/Nibbles.md) | Linux | Easy | Nibbleblog CMS, password brute-force, file upload to RCE, sudo misconfiguration |
| [Crafty](HTB/Machines/Crafty/Crafty.md) | Windows | Easy | Minecraft server, Log4Shell (CVE-2021-44228), hardcoded password in a plugin JAR, RunasCs |

### Hack The Box: Challenges

_Coming soon._

### CTFs: Platforms and Events

| Platform / Event | Challenge | Category | Highlights |
|---|---|---|---|
| Pentraze | [Infernal RPC](CTFs/Pentraze/PWN/InfernalRPC/InfernalRPC.md) | PWN | Custom RPC protocol, stack buffer overflow, ret2win, stack alignment |
| Pentraze | [manguheap](CTFs/Pentraze/PWN/manguheap/manguheap.md) | PWN | Use-after-free, tcache poisoning, safe-linking bypass |
| Pentraze | [Port 0](CTFs/Pentraze/Reversing/Port%200/Port%200.md) | Reversing | Windows ALPC, static analysis in Ghidra, XorShift PRNG |

### Planned

- **TryHackMe**: [PWN101](https://tryhackme.com/room/pwn101)
- **ROP Emporium**: [ROP challenges](https://ropemporium.com/)

## Repository layout

```
.
├── HTB/
│   ├── Machines/<Machine>/
│   └── Challenges/<Category>/<Challenge>/
├── CTFs/
│   └── <Platform or Event>/<Category>/<Challenge>/
└── resources/        # helper scripts shared across writeups
```

Every writeup has its own folder:

```
<Name>/
├── <Name>.md         # the writeup
└── resources/        # its screenshots
```

## Disclaimer

These writeups are for educational purposes only.
- Hack The Box writeups cover retired content only.
- CTF writeups are published after the event ends.
- Only use these techniques on systems you are authorized to test.

## Author

**Randy Nin** ([@RandyNin](https://github.com/RandyNin))
