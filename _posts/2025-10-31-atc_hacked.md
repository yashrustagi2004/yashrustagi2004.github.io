---
title: "KPMG CTF 2025 - ATC Hacked"
date: 2025-10-23
categories: [Capture The Flags, KPMG2025]
tags: [CTF, Writeups, OSINT]
---

## Challenge Prompt

wee woo weee woo wee woo

150 164 164 160 163 72 57 57 167 167 167 56 154 151 156 153 145 144 151 156 56 143 157 155 57 151 156 57 162 141 147 150 141 166 141 163 141 151 163 163 150 57

boom boom boom

---

## 1. Getting started

Using cyberchef, I got the following linkedin link from the encoded string

`https://www.linkedin.com/in/raghavasaissh/`

On visiting the profile, I got a base64 encoded string in the person's bio

![linked](/assets/img/kpmg2025/actHacked/linkedin.png)

```
TmV2ZXIgZ29ubmEgZ2l2ZSB5b3UgdXAKTmV2ZXIgZ29ubmEgbGV0IHlvdSBkb3duCk5ldmVyIGdvbm5hIHJ1biBhcm91bmQgYW5kIGRlc2VydCB5b3UKTmV2ZXIgZ29ubmEgbWFrZSB5b3UgY3J5Ck5ldmVyIGdvbm5hIHNheSBnb29kYnllCk5ldmVyIGdvbm5hIHRlbGwgYSBsaWUgYW5kIGh1cnQgeW91CgpOb3cgdGhhdCB5b3UgYXJlIHJpY2tyb2xsZWQsIGNoZWNrIHRoaXMgb3V0CgpWSUxLIDMxMDUzMFogMDQwMDhLVCA0MDAwIEJSIFNDVDAxMCBCS04wMjAgT1ZDMDkwIDIzLzIzIFExMDExIE5PU0lHCgpCUVM/OEYja3MtRSsqZzBBUl1Aay9uOGc6MDViO1g8LGFSPEJhUmdRQUtZciNGKih0OUBWS14mRSsqZy9HQWhNNCtFcWFIQ2grWXRBS1opLkFLWCpQRGZeIkNAckg0JERmLVwtQDwtQyZBVEFvMkA7VFI+Lm0uWmVGKiZPN0RmJz8wREJOQSVFYXMsdUFvby80RGUqRXE0czRRVytDVCkmK0NlaSFFc2JUWkRlZ0owREJOQS5FYlRdKkNpXl8vQk9QcSckOlQySkQvYTwmKz9DVzI5MGxLQjV0T3NAMmAhQiI=
```

Using cyberchef I got the below result:

```
Never gonna give you up
Never gonna let you down
Never gonna run around and desert you
Never gonna make you cry
Never gonna say goodbye
Never gonna tell a lie and hurt you

Now that you are rickrolled, check this out

VILK 310530Z 04008KT 4000 BR SCT010 BKN020 OVC090 23/23 Q1011 NOSIG

BQS?8F#ks-E+*g0AR]@k/n8g:05b;X<,aR<BaRgQAKYr#F*(t9@VK^&E+*g/GAhM4+EqaHCh+YtAKZ).AKX*PDf^"C@rH4$Df-\-@<-C&ATAo2@;TR>.m.ZeF*&O7Df'?0DBNA%Eas,uAoo/4De*Eq4s4QW+CT)&+Cei!EsbTZDegJ0DBNA.EbT]*Ci^_/BOPq'$:T2JD/a<&+?CW290lKB5tOs@2`!B"
```

What a way to rickroll :/

---

## 2. Pastebin password - 1/2

The last string is base85 encoded and upon decoding I got a pastebin url which had a password and we need to figure it out in order to move forward

```
https://pastebin.com/nd5Tp1zi
The paste bin password would be the <most common carrier name>+<most common aircraft model> in all caps
Look in arrivals chart
Example : AKASAAIRB737
```

Alright, then I moved onto the other string which was given `VILK 310530Z 04008KT 4000 BR SCT010 BKN020 OVC090 23/23 Q1011 NOSIG`.

Upon searching here and there, I found out that this is a METAR (Meteorological Aerodrome Report) data. METAR  is a coded message that summarizes current weather conditions at an airport. It provides essential data for aviation, including wind speed and direction, visibility, precipitation, cloud cover, temperature, and pressure.

VILK is the code for Amausi Airport (Lucknow) or Chaudhary Charan Singh International Airport. So next step is to find the most common flight carrier in this airport and the aircraft name.

![metar data](/assets/img/kpmg2025/actHacked/metar.png)

Most commong flight carrier was easy, it's INDIGO but finding the aircraft name took me some time but in the end I got it, it's 32N

So the password for this pastebin is INDIGO32N

![pastebin 1 content](/assets/img/kpmg2025/actHacked/pastebin-1.png)

```
Woah you came till here?
Really proud of you
 
Now take this and solve it
 
uggcf://cnfgrova.pbz/CfdJIYFM
Gur cnffjbeq bs gur arkg cnfgr ova jbhyq or gur anzr bs gur pybfrfg nvecbeg gb gur bar lbh sbhaq - nyy fznyyf
```

---

## 3. Pastebin password - 2/2

The ciphered text was ROT13 and using dcode I got another pastebin link

```
https://pastebin.com/PsqWVLSZ
The password of the next paste bin would be the name of the closest airport to the one you found - all smalls
```

Finding password for this was a second long task; it's kanpur as stated on the flightradar website

![kanpur](/assets/img/kpmg2025/actHacked/kanpur.png)

password: kanpur

Upon entering the password I got the flag!

Flag: KPMG_CTF{Fl1ghTR@d4R_1S_FuN_t0_Expl0r3}

Hope you enjoyed reading it!
***
