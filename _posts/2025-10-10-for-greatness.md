---
title: "HuntressCTF 2025 - For Greatness"
date: 2025-10-10
categories: [Capture The Flags, HuntressCTF2025]
tags: [CTF, Writeups, Malware Analysis]
---

## Challenge Prompt

Oh great, another phishing kit. This has some functionality to even send stolen data over email! Can you track down the email address they send things to?

---

## 1. Getting Started

So, for this challenge we are given with a j.php file

```bash
~/Downloads/for_greatness ❯ ls -l j.php 
-rw-rw-r-- 1 lightning lightning 499260 Oct 10 22:09 j.php
```

On opening it, I noticed that it was a huge obfuscated code

```bash
<?php
goto oxiT1; KC3di: $sl5eq = $lFKwz($sl5eq); goto m4J3j; zEIti: $GGMnR = $sl5eq(); goto g0hmD; m4J3j: $VhLHm = $lFKwz($VhLHm); goto NmVIQ; g0hmD: $AQTh0(); goto FkkRP; C9ufu: $d8Mzs($fPdlo($lFKwz($FRczk))); goto zEIti; yLDSn: $VhLHm = "\x20\40\142\x32\112\x66\x63\x33\x52\x68\x63\156\121\x3d"; goto vZvXQ; vZvXQ: $sl5eq = "\x62\62\x4a\146\132\x32\126\60\130\62\116\x76\142\156\122\x6c\142\156\x52\x7a"; goto lo0I_; ddvsq: $fPdlo = $lFKwz($fPdlo); goto CcPTn; G3Rr2: $VhLHm(); goto C9ufu; a4yHD: $fPdlo = "\40\x5a\63\160\x31\x62\x6d\116\x76\x62\x58\x42\x79\132\x58\x4e\172"; goto yLDSn; zFUky: $OovTE = $lFKwz($OovTE); goto Cciv0; fDcHz: $AQTh0 = $lFKwz($AQTh0); goto KC3di; Cciv0: $d8Mzs = $iQPa4("\44\137", $OovTE); goto fDcHz; CMzN3: $iQPa4 = "\130\x31\71\x73\x59\127\x31\151\132\x47\x45\x3d"; goto a4yHD; CcPTn: if (!function_exists("\137\x5f\154\x61\x6d\x62\x64\141")) { function __lambda($sZ_lH, $AP_tK) { return eval("\x72\x65\164\165\x72\x6e\40\146\x75\156\143\x74\x69\157\156\x28{$sZ_lH}\51\x7b{$AP_tK}\x7d\x3b"); } } goto oSLxJ; NmVIQ: $FRczk = "\145\112\172\164\57\126\154\172\64\164\162\127\71\167\166\145\156\60\71\122\106\170\130\170\126\163\127\165\161\101\145\102\171\132\63\105\151\130\116\150\104\115\112\147\111\171\143\103\151\145\141\155\101\157\120\124\107\101\122\155\160\142\106\160\120\156\63\71\170\160\172\161\153\121\102\156\65\154\162\166\146\160\66\
```

Small sample from the j.php file ^

--- 

## 2. Decoding the code

My first intution was to decode the code and proceed further

For this I went to "https[:]//malwaredecoder[.]com/" and put the whole code

![decoded code](/assets/img/huntressCTF2025/for-greatness/decoded_j.png)

I tried making sense out of it and nothing informative came up

There was this "$FRczk" variable which was assigned a huge string 

I tried searching for flag keyword and found something which turned out to be a rabbit hole (lost count of how much time I spent into this)

![rabbit hole](/assets/img/huntressCTF2025/for-greatness/rabbitHole.png)


### 2.1 Extract b64 encoded strings 

Then my teammates and I started analysing the original code and observed that the code was obfuscated multiple times by nested base64 encoding, and by using gzuncompress

So we went ahead and wrote this python script to 
1. find all string literals in the file
2. detected base64-like strings
3. Recursively decode the nested base64 encoded strings
4. save all the decoded artifacts in bin file

```python
#!/usr/bin/env python3
import re, sys, os, json, base64, binascii, pathlib
from typing import List, Dict, Any, Tuple

def read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def is_probably_base64(s: str) -> bool:
    # Heuristic: length multiple of 4 (or near), allowed alphabet, at least 16 chars
    t = s.strip()
    if len(t) < 16:
        return False
    # Relaxed length check: many obfuscators omit padding; we can try add padding later
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", t):
        return False
    # Avoid hex-only strings
    if re.fullmatch(r"[0-9A-Fa-f]+", t):
        return False
    return True

def b64_decode_loose(data: str) -> bytes:
    # Try standard, then URL-safe, try padding variations
    cand = data.strip().replace("\n","").replace("\r","")
    # If contains '-' or '_', try urlsafe first
    variants = []
    if re.search(r"[-_]", cand):
        variants.append(("urlsafe", cand))
    variants.append(("std", cand))
    # try with padding up to 3 '='
    outs = []
    for kind, s in variants:
        for pad in range(4):
            ss = s + ("=" * pad)
            try:
                if kind == "urlsafe":
                    outs.append(base64.urlsafe_b64decode(ss))
                else:
                    outs.append(base64.b64decode(ss))
                # return first successful decode
                return outs[-1]
            except Exception:
                pass
    raise binascii.Error("base64 decode failed")

def php_unescape_double(s: str) -> bytes:
    # Decode PHP-style double-quoted escapes to raw bytes
    # Handles: \xHH, \OOO (octal), and \n \r \t \v \f \\"\\$\
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c != '\\':
            out.append(ord(c))
            i += 1
            continue
        # escape sequence
        i += 1
        if i >= n:
            out.append(ord('\\'))
            break
        e = s[i]
        i += 1
        if e in 'nrtvf"\\$':
            mapping = {'n':'\n','r':'\r','t':'\t','v':'\x0b','f':'\x0c','"':'"','\\':'\\','$':'$'}
            v = mapping[e]
            out.append(ord(v))
        elif e in 'xX':
            # hex up to 2 chars
            h = s[i:i+2]
            hh = ''.join(ch for ch in h if ch in '0123456789abcdefABCDEF')
            if len(hh) >= 2:
                out.append(int(hh[:2],16))
                i += 2
            elif len(hh) == 1:
                out.append(int(hh,16))
                i += 1
            else:
                out.append(ord('x'))
        elif e.isdigit():
            # octal: up to 3 oct digits, already consumed one
            oct_digits = e + s[i:i+2]
            m = re.match(r'[0-7]{1,3}', oct_digits)
            if m:
                val = int(m.group(0), 8)
                out.append(val & 0xFF)
                i += len(m.group(0)) - 1
            else:
                out.append(ord(e))
        else:
            # unknown escape -> literal
            out.append(ord(e))
    return bytes(out)

def php_unescape_single(s: str) -> bytes:
    # In single quotes, only \\ and \'
    s2 = s.replace("\\\\", "\\").replace("\\'", "'")
    return s2.encode('latin1', 'backslashreplace')

def extract_php_strings(src: str) -> List[Tuple[str, str, int, int]]:
    # Returns list of (quote, content, start, end)
    # Handle PHP comments to avoid matching inside // ... or /* ... */
    def strip_comments(text: str) -> str:
        # Replace comments with spaces of same length to preserve indices
        # Remove /* ... */ first
        def repl_block(m):
            return " " * (m.end()-m.start())
        text = re.sub(r"/\*.*?\*/", repl_block, text, flags=re.S)
        # Remove // ... to end of line
        text = re.sub(r"//.*?$", lambda m: " " * (m.end()-m.start()), text, flags=re.M)
        # Remove # ... to end of line
        text = re.sub(r"#.*?$", lambda m: " " * (m.end()-m.start()), text, flags=re.M)
        return text

    clean = strip_comments(src)
    # Regex for PHP strings - fixed escape sequences
    pattern = r'("(?:[^"\\]|\\.)*")|' + r"('(?:[^'\\]|\\.)*')"
    out = []
    for m in re.finditer(pattern, clean, flags=re.S):
        if m.group(1):  # double
            s = m.group(1)
            content = s[1:-1]
            out.append(('"', content, m.start(), m.end()))
        elif m.group(2):
            s = m.group(2)
            content = s[1:-1]
            out.append(("'", content, m.start(), m.end()))
    return out

def multi_stage_b64(data: bytes, max_depth: int = 8) -> List[bytes]:
    stages = [data]
    cur = data
    for _ in range(max_depth):
        s = cur.decode('latin1', 'ignore')
        if not is_probably_base64(s):
            break
        try:
            cur = b64_decode_loose(s)
            stages.append(cur)
        except Exception:
            break
    return stages

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 deob_php.py j.php")
        sys.exit(1)

    in_path = sys.argv[1]
    src_b = read_bytes(in_path)
    try:
        src = src_b.decode('latin1')
    except Exception:
        src = src_b.decode('utf-8', 'ignore')

    strings = extract_php_strings(src)
    out_dir = pathlib.Path("php_deob_out")
    (out_dir / "guesses").mkdir(parents=True, exist_ok=True)
    (out_dir / "stages").mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []
    concat_double = bytearray()

    for idx, (quote, content, start, end) in enumerate(strings):
        if quote == '"':
            raw = php_unescape_double(content)
            concat_double.extend(raw)
        else:
            raw = php_unescape_single(content)

        item: Dict[str, Any] = {
            "index": idx,
            "quote": quote,
            "start": start,
            "end": end,
            "len": len(content),
            "literal_preview": (content[:120] + ("…" if len(content) > 120 else "")),
            "decoded_hex_preview": raw[:64].hex(),
            "decoded_ascii_preview": "".join(chr(c) if 32 <= c < 127 else "." for c in raw[:64]),
        }

        # Try base64 chains on decoded-as-text
        try:
            txt = raw.decode('latin1', 'ignore')
        except Exception:
            txt = ""

        guesses = []
        if is_probably_base64(txt):
            stages = multi_stage_b64(raw, max_depth=12)
            for d, stage in enumerate(stages):
                stage_path = out_dir / "guesses" / f"literal{idx}_stage{d}.bin"
                stage_path.write_bytes(stage)
                guesses.append({
                    "stage": d,
                    "size": len(stage),
                    "hex_preview": stage[:64].hex(),
                    "ascii_preview": "".join(chr(c) if 32 <= c < 127 else "." for c in stage[:64]),
                    "path": str(stage_path)
                })
        item["base64_stages"] = guesses
        results.append(item)

    # Write per-literal report
    (out_dir / "literals.json").write_text(json.dumps(results, indent=2))

    # Write concatenated double-quoted bytes and attempt iterative base64 on it
    concat_path = out_dir / "stages" / "concat_double.bin"
    concat_path.write_bytes(bytes(concat_double))

    # Try to split concat by common separators (;) and (=) to extract tokens that might be base64
    concat_text = bytes(concat_double).decode('latin1', 'ignore')
    tokens = re.findall(r"[A-Za-z0-9+/=_-]{16,}", concat_text)
    b64finds = list(sorted(set(t for t in tokens if is_probably_base64(t)), key=len, reverse=True))

    summary_lines = []
    summary_lines.append(f"Total string literals found: {len(strings)}")
    summary_lines.append(f"Concatenated bytes (double-quoted only): {len(concat_double)} bytes -> {concat_path}")
    summary_lines.append(f"Unique base64-like tokens found in concatenated text: {len(b64finds)}")

    # Decode each token multi-stage
    for i, tok in enumerate(b64finds[:200]):
        try:
            stages = []
            cur = tok
            for depth in range(12):
                b = b64_decode_loose(cur)
                stage_file = out_dir / "stages" / f"concat_token{i}_stage{depth}.bin"
                stage_file.write_bytes(b)
                stages.append((len(b), stage_file))
                # Prepare next
                try:
                    cur = b.decode('latin1')
                    if not is_probably_base64(cur):
                        break
                except Exception:
                    break
            if stages:
                summary_lines.append(f"[TOK {i}] Decoded {tok[:40]}... for {len(stages)} stage(s): " + ", ".join(f"{sz}B->{p.name}" for sz,p in stages))
        except Exception:
            pass

    (out_dir / "summary.txt").write_text("\n".join(summary_lines))

    print("Done.")
    print("\n".join(summary_lines))
    print(f"Artifacts written to: {out_dir.resolve()}")

if __name__ == "__main__":
    main()
```

Running the script

```bash
~/Downloads/for_greatness ❯ python3 message.py j.php
Done.
Total string literals found: 13
Concatenated bytes (double-quoted only): 132447 bytes -> php_deob_out/stages/concat_double.bin
Unique base64-like tokens found in concatenated text: 6
[TOK 0] Decoded eJzt/Vlz4trW9wven09RFxXxVsWuqAeByZ3EiXNh... for 1 stage(s): 99187B->concat_token0_stage0.bin
[TOK 1] Decoded b2JfZW5kX2NsZWFubase64_decodeLoading... for 1 stage(s): 27B->concat_token1_stage0.bin
[TOK 2] Decoded NAMEcmV0dXJuIGV2YWwoJF8pOw==printf... for 1 stage(s): 19B->concat_token2_stage0.bin
[TOK 3] Decoded b2Jfc3RhcnQ=b2JfZ2V0X2NvbnRlbnRz... for 1 stage(s): 8B->concat_token3_stage0.bin
[TOK 4] Decoded _X19sYW1iZGE=__lambdareturn... for 1 stage(s): 19B->concat_token4_stage0.bin
[TOK 5] Decoded Z3p1bmNvbXByZXNz... for 1 stage(s): 12B->concat_token5_stage0.bin
Artifacts written to: /home/lightning/Downloads/for_greatness/php_deob_out
```

---

## 3. Analysing the decoded output

```bash
~/Downloads/for_greatness/php_deob_out/guesses ❯ file *
literal1_stage0.bin:              ASCII text, with no line terminators
literal1_stage1.bin:              ASCII text, with no line terminators
literal2_stage0.bin:              ASCII text, with no line terminators
literal2_stage1.bin:              ASCII text, with no line terminators
literal7_stage0.bin:              ASCII text, with very long lines (65536), with no line terminators
literal7_stage1.bin:              zlib compressed data
literal11_stage0.bin:             ASCII text, with no line terminators
literal8_stage0.bin:              ASCII text, with no line terminators
literal8_stage1.bin:              ASCII text, with no line terminators
literal11_stage1.bin:             ASCII text, with no line terminators
```

7 bin files and out of them only 1 is compressed using zlib

Running python code to decompress the literal8_stage1.bin


```python
import zlib
import sys
import os

def decompress_zlib(input_file, output_file=None):
    """Decompress zlib compressed file"""
    
    if output_file is None:
        # Auto-generate output filename
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_decompressed.bin"
    
    print("="*80)
    print("Zlib Decompressor")
    print("="*80)
    print(f"[*] Input file: {input_file}")
    print(f"[*] Output file: {output_file}")
    
    try:
        # Read compressed data
        with open(input_file, 'rb') as f:
            compressed_data = f.read()
        
        print(f"[*] Compressed size: {len(compressed_data)} bytes")
        
        # Try different decompression methods
        decompressed = None
        method_used = None
        
        # Method 1: Standard zlib decompress
        try:
            decompressed = zlib.decompress(compressed_data)
            method_used = "zlib.decompress()"
            print(f"[+] Successfully decompressed using {method_used}")
        except Exception as e:
            print(f"[-] Method 1 failed: {e}")
        
        # Method 2: zlib with negative wbits (raw deflate)
        if decompressed is None:
            try:
                decompressed = zlib.decompress(compressed_data, -zlib.MAX_WBITS)
                method_used = "zlib.decompress() with -MAX_WBITS"
                print(f"[+] Successfully decompressed using {method_used}")
            except Exception as e:
                print(f"[-] Method 2 failed: {e}")
        
        # Method 3: gzip decompress
        if decompressed is None:
            try:
                decompressed = zlib.decompress(compressed_data, zlib.MAX_WBITS | 16)
                method_used = "gzip mode"
                print(f"[+] Successfully decompressed using {method_used}")
            except Exception as e:
                print(f"[-] Method 3 failed: {e}")
        
        # Method 4: Try with decompressobj (incremental)
        if decompressed is None:
            try:
                decompressor = zlib.decompressobj()
                decompressed = decompressor.decompress(compressed_data)
                decompressed += decompressor.flush()
                method_used = "zlib.decompressobj()"
                print(f"[+] Successfully decompressed using {method_used}")
            except Exception as e:
                print(f"[-] Method 4 failed: {e}")
        
        if decompressed is None:
            print("\n[ERROR] All decompression methods failed")
            return False
        
        print(f"[*] Decompressed size: {len(decompressed)} bytes")
        print(f"[*] Compression ratio: {len(compressed_data)/len(decompressed)*100:.2f}%")
        
        # Write decompressed data
        with open(output_file, 'wb') as f:
            f.write(decompressed)
        
        print(f"\n[SUCCESS] Decompressed data written to: {output_file}")
        
        # Try to detect file type
        print("\n[*] Analyzing decompressed data...")
        
        # Check if it's text
        try:
            text = decompressed.decode('utf-8')
            print("[+] Content appears to be UTF-8 text")
            print(f"[*] Preview (first 500 chars):")
            print("-"*80)
            print(text[:500])
            if len(text) > 500:
                print("...")
            print("-"*80)
        except:
            print("[+] Content is binary data")
            print(f"[*] Hex preview (first 64 bytes):")
            print("-"*80)
            hex_preview = decompressed[:64].hex()
            for i in range(0, len(hex_preview), 32):
                print(hex_preview[i:i+32])
            print("-"*80)
        
        # Suggest next steps
        print("\n[*] Next steps:")
        print(f"    file {output_file}")
        print(f"    cat {output_file}")
        print(f"    strings {output_file}")
        print(f"    hexdump -C {output_file} | head")
        
        return True
        
    except FileNotFoundError:
        print(f"[ERROR] File not found: {input_file}")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False

def batch_decompress(directory="."):
    """Decompress all zlib files in a directory"""
    import glob
    
    print(f"[*] Searching for compressed files in: {directory}")
    files = glob.glob(os.path.join(directory, "*stage1.bin"))
    
    print(f"[*] Found {len(files)} potential compressed files")
    
    for filepath in files:
        # Check if it's zlib compressed
        try:
            with open(filepath, 'rb') as f:
                header = f.read(2)
            
            # Check for zlib header (78 9C, 78 01, 78 DA, 78 5E)
            if header[0:1] == b'\x78':
                print(f"\n[*] Processing: {filepath}")
                output = filepath.replace("_stage1.bin", "_stage2.bin")
                decompress_zlib(filepath, output)
        except:
            pass

def main():
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        decompress_zlib(input_file, output_file)
    else:
        print("Usage:")
        print("  Single file:  python zlib_extract.py <input_file> [output_file]")
        print("  Batch mode:   python zlib_extract.py --batch [directory]")
        print("\nExample:")
        print("  python zlib_extract.py literal7_stage1.bin")
        print("  python zlib_extract.py literal7_stage1.bin literal7_stage2.bin")
        print("  python zlib_extract.py --batch ~/Downloads/for_greatness/php_deob_out/guesses")
        
        print("\n" + "="*80)
        choice = input("\nEnter input file path: ").strip()
        if choice:
            output = input("Enter output file path (press Enter for auto): ").strip()
            decompress_zlib(choice, output if output else None)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
```

On running the script with `python3 code.py literal7_stage1.bin`, the output was saved to literal7_stage1_decompressed.bin which contained a long base64 encoded string

Using cyberchef, I decoded the output string and found a php code with 2672 lines

![decoded string](/assets/img/huntressCTF2025/for-greatness/final_decoded.png)

---

## 4. Retrieving the flag

We couldn't go through it manually so using the grep command to find the flag

and bummer, there was no string containing the word "flag" but hey there's still a trick left!

We know the flag format is flag{[0-9a-f]{32}\}, given on the ctf[.]huntress[.]com, so now we searched for this pattern in the text file

```bash
~/Downloads/for_greatness/php_deob_out/guesses ❯ grep -nPo '[0-9a-f]{32}' decode.txt 
178:f7113307018770d52d4f94fec013197f
1000:3fb9c7e87c04ff8f56dd61ef8b748c02
1000:fe87496cc7a44412f7893a72099c120a
1000:fe87496cc7a44412f7893a72099c120a
1190:b15dda889e9803e9d6befd60000fadf8
1190:27a6d18b56f46818420e60a773c36d4e
1190:27a6d18b56f46818420e60a773c36d4e
1658:942ac71f77cb04004b0ab25950e170b5
1658:b59c16ca9bf156438a8a96d45e33db64
1658:b59c16ca9bf156438a8a96d45e33db64
1860:942ac71f77cb04004b0ab25950e170b5
1860:b59c16ca9bf156438a8a96d45e33db64
1860:b59c16ca9bf156438a8a96d45e33db64
```

13 rows containing the desired pattern and yet no "flag" word in the text file

I started from the first row to grep the whole string to see what other content was there along with it and I got this

```bash
~/Downloads/for_greatness/php_deob_out/guesses ❯ cat decode.txt | grep f7113307018770d52d4f94fec013197f
		$headers='Content-type: text/html; charset=UTF-8' . "\r\nFrom: Greatness <ghost+}f7113307018770d52d4f94fec013197f{galf@greatness.com>" . "\r\n";
```

That's why searching for flag returned 0 result as the flag is written in reverse 

Reversing the string found to get the flag

```bash
~/Downloads/for_greatness/php_deob_out/guesses ❯ echo }f7113307018770d52d4f94fec013197f{galf | rev

flag{f791310cef49f4d25d0778107033117f}
```

Gotcha!

Thank you for reading!

***








