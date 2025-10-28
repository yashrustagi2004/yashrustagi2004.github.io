---
title: "HuntressCTF 2025 - Tabby's Date"
date: 2025-10-09
categories: [Capture The Flags, HuntressCTF2025]
tags: [CTF, Writeups, Forensics]
---

## Challenge Prompt

Ohhhh, Tab, Tab, Tab.... what has she done.

My friend Tabby just got a new laptop and she's been using it to take notes. She says she puts her whole life on there!

She was so excited to finally have a date with a boy she liked, but she completely forgot the details of where and when. She told me she remembers writing it in a note... but she doesn't think she saved it!!

She shared with us an export of her laptop files.

---

So, the challenge is to analyse the given zip file to find the hidden flag

## 1. Finding text files

Since it was written that Tabby has been taking notes I thought she might have saved it in a txt file and that's what my first step was. To look for all txt files in the given zip file:

```bash
~/Downloads/tabbys_date/C ❯ pwd
/home/lightning/Downloads/tabbys_date/C
~/Downloads/tabbys_date/C ❯ find . -type f -name "*.txt"
~/Downloads/tabbys_date/C ❯
```

**Result** - nothing

---

## 2. Finding all the files

I just thought of this randomly and searched for all the files:

```bash
~/Downloads/tabbys_date/C ❯ find . -type f -name "*"
./Windows/system.ini
./Windows/win.ini
./Windows/System32/drivers/etc/hosts
./Users/Tabby/Pictures/desktop.ini
./Users/Tabby/Downloads/desktop.ini
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/2e0dd6b6-ba93-4efc-9fd4-985dad74869a.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/414e4071-60e6-4bb6-9a5a-f1e5bf6fe79c.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/a9da0602-fcd2-4793-9bab-70276e881006.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/b5074fe7-4f54-4728-afe9-1c063d211a82.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/f1473e57-7637-4bd0-8158-53715ea20630.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/711f26f1-0eff-4a34-a78c-03562e44a36b.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/b5154796-9d23-43ce-8a6c-c373e63f22c0.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/68d7e607-77c4-4d35-8ef2-0170a84efe5f.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/dea21c9d-4534-4d38-a60b-0a5c1b9b5928.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/dcfa4d00-41c8-439a-b1bd-2706dd8dbe0d.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/14623d59-ad8c-43a8-b669-587f049a1516.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/45dcdbe4-26b5-4e0b-ba2d-29e9e9c1e11b.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/4f1c96a1-960c-4cee-9751-fe4b4f59fdd0.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/04165ca3-c82b-42ca-ab07-0c774ae66efd.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/17de440f-3f69-4d8a-94fe-f3d4b9cf0c3f.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/9bf7ca49-e491-4691-a21a-f3263bb695a2.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/5a57ac85-7e99-4bfc-9e13-f0d28a2bcc20.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/056941ef-d51d-4e57-9a55-b59d58bf3fcb.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/66f955a8-6994-47c6-8326-0f128dafd0b9.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/cb2f0c84-6293-4e63-8575-78dc879945e0.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/9e96bd4b-4155-4558-b97a-edcdf01d4584.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/9925cc8a-6440-4128-acae-f31541130a5e.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/002d2531-9aff-42b1-b54d-b178c88063b4.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/7ba066a2-e0cb-4c06-9339-316411a3da27.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/1aebb59c-5d51-41f1-918e-dec9e1a28ce1.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/cd01dd8e-32f6-4f88-b9bb-4009afca3fea.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/a16d5079-b2f7-4a54-b3d5-b32256c4f238.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/7458196e-e979-4d94-982a-246fca3db028.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/e6a849ab-6f02-452c-98e7-cdb03c577818.bin
./Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/e86c9910-afca-4e83-87f6-600ed08a0570.bin
./Users/Tabby/AppData/Local/Microsoft/Windows/UsrClass.dat
./Users/Tabby/Documents/desktop.ini
./Users/Tabby/Videos/desktop.ini
./Users/Tabby/NTUSER.DAT
./Users/Tabby/Desktop/desktop.ini
./Users/Tabby/Music/desktop.ini
```

Lot of bin files!

so that is what we have to analyse to get the flag

---

## 3. Analysing bin files

For this, first I used GHex Editor to view some bin files

### 3.1 Using GHex Editor

![bin file](/assets/img/huntressCTF2025/tabby's%20date/bin1.png)

Having a look at another bin file

![bin file 2](/assets/img/huntressCTF2025/tabby's%20date/bin2.png)

Now if I start doing this to find the flag it would have been time consuming, so I used a python script to automate the process

The script extracts readable text runs (ASCII/UTF-8 and UTF-16 LE/BE), and writes the output in a single txt file

## 3.2 Automation using python

{% raw %}

```python
#!/usr/bin/env python3
"""
combine_bin_texts.py
Extract printable text runs from all .bin files in current directory
and save them (deduplicated, in-order) into all_bins_combined.txt.
"""
import re
from pathlib import Path

MIN_LEN = 4                      # minimum printable run length to consider
OUTFILE = Path("all_bins_combined.txt")

def extract_ascii_runs(b):
    ascii_re = re.compile(rb'[\x09\x0A\x0D\x20-\x7E]{%d,}' % MIN_LEN)
    results = []
    for m in ascii_re.finditer(b):
        try:
            s = m.group(0).decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            s = m.group(0).decode('latin-1', errors='replace')
        results.append(s)
    return results

def extract_utf16_runs(b, endian='le'):
    try:
        s = b.decode('utf-16' + endian, errors='ignore')
    except Exception:
        return []
    return re.findall(r'[\u0020-\u007e]{%d,}' % MIN_LEN, s)
{% endraw %}

{% raw %}
def extract_from_file(path: Path):
    b = path.read_bytes()
    out = []
    out.extend(extract_ascii_runs(b))
    out.extend(extract_utf16_runs(b, 'le'))
    out.extend(extract_utf16_runs(b, 'be'))
    # strip and discard empty/whitespace-only lines
    cleaned = [line.strip() for line in out if line and line.strip()]
    return cleaned

def main():
    all_lines = []
    seen = set()
    bins = sorted(Path(".").glob("*.bin"))
    if not bins:
        print("No .bin files found in current directory.")
        return

    for p in bins:
        extracted = extract_from_file(p)
        for line in extracted:
            if line not in seen:
                seen.add(line)
                all_lines.append(line)

    OUTFILE.write_text("\n".join(all_lines), encoding="utf-8")
    print(f"Wrote {len(all_lines)} unique lines to {OUTFILE}")

if __name__ == "__main__":
    main()
```
{% endraw %}

Giving the permission and running the script:

```bash
~/Downloads/tabbys_date/C/Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState ❯ chmod +x code2.py
~/Downloads/tabbys_date/C/Users/Tabby/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState ❯ python3 code2.py
Wrote 187 unique lines to all_bins_combined.txt
```

## 3.3 Viewing the txt file

![text file](/assets/img/huntressCTF2025/tabby's%20date/flag.png)

Here we can see in line number 61 we have our flag

{% raw %}
Flag: `flag{165d19b610c02b283fc1a6b4a54c4a58}`
{% endraw %}

---