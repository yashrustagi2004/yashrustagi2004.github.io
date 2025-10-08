---
title: Powershell Obfuscator 
date: 2025-10-03 12:00:00 +0530
categories: [Projects, Cybersecurity]
tags: [Projects, Javascript, Powershell]
---

# PowerShell Script Obfuscator v1.1

A browser-based tool to obfuscate PowerShell scripts by randomizing variable names, obfuscating tokens, and injecting comments, reducing Shannon entropy while preserving functionality.

Github Repo: [Click here](https://github.com/yashrustagi2004/psObfuscator)

--- 
## Features

- **Variable Randomization**: Replaces variable names with random 20–30 character alphanumeric strings
- **Token Obfuscation**: Randomizes string literals, command casing, and can split/concatenate strings to make detection harder
- **Comment Injection**: Adds comments at the beginning, after lines or semicolons, and at the end
- **Entropy Analysis**: Displays original and final Shannon entropy with reduction percentage
- **File Operations**: Supports file upload (`.ps1`/`.txt`) and download of obfuscated scripts

---

## How It Works

The obfuscator works by:

- Parsing PowerShell variables and replacing them with randomized names
- Obfuscating string literals and common cmdlets/keywords by randomizing case or splitting strings
- Injecting benign comments throughout the script
- Maintaining script functionality while reducing detectability
- Calculating and displaying entropy reduction metrics

***