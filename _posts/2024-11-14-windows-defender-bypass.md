---
title: Windows Defender Bypass
date: 2024-11-14 12:00:00 +0530
categories: [Projects, Cybersecurity]
tags: [Projects, System hacking, Steganography, Windows Defender]
description: Windows Defender bypass techniques using steganography and obfuscation methods
---

## Windows Defender Bypass

***

### Overview
This project demonstrates an **obfuscated PowerShell reverse shell (backdoor)** with a staged delivery, evading Windows Defender and gaining persistent remote access on a test Windows 11 system.

Github Repo: [Click here](https://github.com/yashrustagi2004/Windows-11-Defender-Bypass)

***

Wokring PoC: [Click here](https://drive.google.com/file/d/1iTEkN10lV6p9HQgOGtA8Kal_eJSIBo4s/view?usp=drive_link)

***

### Components

- **backdoor.ps1**
  - Obfuscated PowerShell script that, when executed, opens a reverse shell back to the attacker's machine
  - This file is hosted on the attacker's local server

  - Windows Defender scans PowerShell scripts for known malicious patterns and suspicious commands
  - Obfuscating our script disguises command strings and function names, making it much harder for signature-based antivirus tools to detect and block our payload

- ![Normal Script](/assets/img/projects/windows-defender-bypass/normal.png)
- ![Obfuscated Script](/assets/img/projects/windows-defender-bypass/obfuscated.png)

- **wallpaper.ps1**  
  - PowerShell script that:
    - Downloads `backdoor.ps1` from the attacker's server.
    - Executes it.
    - Sets up persistence for ongoing access.

- **wallpaper.exe**  
  - `wallpaper.ps1` converted to an executable using the `ps2exe` tool for stealthy distribution.

***

### Attack Workflow

1. **Prepare Server**  
   - Attacker hosts `backdoor.ps1` and sets up a netcat listener to listen for incoming reverse shell connections.

2. **Package the Payload**  
   - Convert `wallpaper.ps1` to `wallpaper.exe` using `ps2exe`

   - Hide both `wallpaper.exe` and `wallpaper.jpg` inside a self-extracting RAR archive (using WinRAR), configured to auto-open `wallpaper.jpg` upon extraction.

3. **Delivery**  
   - Deliver the malicious archive to the target via a USB device.

4. **Execution**  
   - When the victim opens the image from the USB drive, the image displays normally.
   - In the background, `wallpaper.exe` downloads and runs `backdoor.ps1`, granting the attacker remote access.
   - Persistence mechanisms ensure continued attacker access even after reboot.

***