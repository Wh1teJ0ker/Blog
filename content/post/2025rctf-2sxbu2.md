---
title: 2025RCTF
slug: 2025rctf-2sxbu2
url: /post/2025rctf-2sxbu2.html
date: '2025-11-15 11:24:18+08:00'
lastmod: '2025-12-10 15:23:23+08:00'
categories:
  - CTF-Writeup
description: 社工大赛了，属于是
toc: true
isCJKLanguage: true
---



# 2025RCTF

# Misc

## Speak Softly Love

```python
1.8ssDGBTssUI
2.r178
3.https://mateusz.viste.fr/mateusz.ogg
4.16TofYbGd86C7S6JuAuhGkX4fbmC9QtzwT
```

第一问

根据视频试图先找到电脑型号，然后结合关键词music，youtube搜索找到这个。

![57d102e55a86e97acc04f71e4258e41e](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic57d102e55a86e97acc04f71e4258e41e-20251115120444-cvv7p27.png)

```python
8ssDGBTssUI
```

第二问

查找DOSmid

```python
https://www.vogons.org/viewtopic.php?t=44947
```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251115120716-3rjoeb3.png)

先找到关于这个的大致信息

使用的svn

```python
svn co svn://svn.mateusz.fr/dosmid dosmid-svn
```

然后基于上述关键词去查找

```python
root@DESKTOP-LV8V93U:/home/2025RCTF/dosmid-svn# svn log -r 200:350 | egrep -i "playlist|m3u|freeze|empty|loop|soft"
freezed v0.9 to tags
freezed v0.9.1 to tags
sequential playing of playlists, inspired by a patch proposed by Graham Wiseman
freezed v0.9.2 into tags
freezed v0.9.3 to tags
m3u playlist uses fio calls instead of fopen() and friends
fix: /random was always playing first song of the m3u list, now it is random from the start
fixed playlist gap delay computation (fixed /delay behavior, too)
freezed v0.9.4 to tags
freezed v0.9.5 to tags
root@DESKTOP-LV8V93U:/home/2025RCTF/dosmid-svn# svn log -r 1:200 | egrep -i "playlist|m3u|freeze|empty|loop|soft"
do not freeze when no MPU401 is responding
setting volume in software again, reinstated default delay=2ms, improved keyboard reaction times and adjusted documentation
added INT28h powersaving during idle loops
detecting when a playlist is passed on command-line (but no m3u support yet)
first semi-experimental M3U support
freezed v0.6 into tags
freezed v0.6.1 into tags
freezed v0.7 in tags
freezed v0.8 into tags
added an empty and self-documented configuration file
2s silence gap is inserted only in playlist mode (no reason to wait 2s for a single file)
fixed freezing when fed with an empty playlist
if too many 'soft' errors occur in a row, dosmid aborts (protects against 'soft errors loops', typically with playlist filled with non-existing files)
add a note about empty titles, when no textual data could be found in the midi file
ignore leading empty title lines
freezed v0.9 to tags
root@DESKTOP-LV8V93U:/home/2025RCTF/dosmid-svn# svn log -r 1:200 | grep -n "soft"
260:setting volume in software again, reinstated default delay=2ms, improved keyboard reaction times and adjusted documentation
712:if too many 'soft' errors occur in a row, dosmid aborts (protects against 'soft errors loops', typically with playlist filled with non-existing files)
root@DESKTOP-LV8V93U:/home/2025RCTF/dosmid-svn# svn log -r 1:200 | sed -n '710,720p'
r178 | mv_fox | 2016-05-09 01:21:38 +0800 (Mon, 09 May 2016) | 1 line

if too many 'soft' errors occur in a row, dosmid aborts (protects against 'soft errors loops', typically with playlist filled with non-existing files)
------------------------------------------------------------------------
r179 | mv_fox | 2016-05-09 01:25:49 +0800 (Mon, 09 May 2016) | 1 line

replaced sleep() calls with equivalent udelay() calls (makes the binary 128 bytes lighter)
------------------------------------------------------------------------
r180 | mv_fox | 2016-05-10 02:04:00 +0800 (Tue, 10 May 2016) | 1 line

fetching more textual data from MIDI files (text events, tracks titles, marker events...) and displaying it on a little scrolling window
```

可以锁定在r178-180，然后试r178就直接对了

```python
r178
```

第三问  
​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic20251115115854053_23433-20251115120223-va46xu9.png)  
根据评论区找到主页

```python
主页里
想联系我吗？我的电子邮件地址与此网页的地址几乎相同（firstname@lastname.fr）。
令人惊讶的是，很多人难以念出我的名字，所以这里附上我的名字（图片来自 Wikimedia）。
https://mateusz.viste.fr/mateusz.ogg
```

第四问

在主页发现了

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251115121145-jyj4lr0.png)

```python
gopher://gopher.viste.fr
```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251115121223-lweqyex.png)

在26里找到了

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251115121241-lp0qf7m.png)

```python
16TofYbGd86C7S6JuAuhGkX4fbmC9QtzwT
```

## The Alchemist's Cage

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251115235437-axt39pe.png)

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251115235558-i6oyv93.png)

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251115235631-szogfwu.png)

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251115235650-m69vpuo.png)

## Wanna Feel Love

Challenge 1

She only wanted to sing, but her voice was hidden in silence. What is this email trying to tell you? Look beyond what you hear — seek the whispers in the shadows, the comments that were never meant to be seen.

邮件隐写

```bash
https://www.spammimic.com
```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251116150220-i3m16fv.png)

```python
Don't just listen to the sound; this file is hiding an 'old relic.' Try looking for the 'comments' that the player isn't supposed to see.
```

Challenge 2

She wants to tell you something, encoded in melodies. Within the digital symphony, her true voice emerges. What is the hidden message found in the XM file? The words she longed to sing, the feeling she wanted to share.

然后下载openmpt

评论和乐曲名有提示

![88e607d2431d6d3e663259e0bb02ddc4](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic88e607d2431d6d3e663259e0bb02ddc4-20251117114419-15y23nx.jpg)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Decode hidden message from feel.wav binary-bar waveform.
Expected output: I Feel Fantastic heyheyhey
"""

import numpy as np
from scipy.io import wavfile


def read_mono_pcm(path: str):
    rate, data = wavfile.read(path)
    data = data.astype(float)
    if data.ndim > 1:   # 立体声只取一个声道
        data = data[:, 0]
    return rate, data


def compute_envelope(data: np.ndarray, window_size: int = 100) -> np.ndarray:
    """对绝对值做滑动平均，得到能量包络"""
    abs_data = np.abs(data)
    n = len(abs_data) // window_size * window_size
    reshaped = abs_data[:n].reshape(-1, window_size)
    env = reshaped.mean(axis=1)
    return env


def binarize_envelope(env: np.ndarray) -> np.ndarray:
    """根据能量双峰分布自动求阈值，得到 0/1 序列"""
    median_env = np.median(env)
    low_level = np.median(env[env < median_env])
    high_level = np.median(env[env > median_env])
    threshold = (low_level + high_level) / 2.0
    bits_raw = (env > threshold).astype(int)
    return bits_raw


def run_length_encode(bits: np.ndarray):
    runs = []
    current = bits[0]
    length = 1
    for b in bits[1:]:
        if b == current:
            length += 1
        else:
            runs.append((current, length))
            current = b
            length = 1
    runs.append((current, length))
    return runs


def expand_runs_to_bits(runs):
    """
    每一串 0/1 在时间上会持续若干个“单位长度”，
    大部分长度约是 22 的倍数，这里固定 base_unit = 22，
    再按 round(length / base_unit) 还原成重复 bit。
    """
    base_unit = 22.0  # 针对 feel.wav 这题是固定的
    bit_list = []
    for v, l in runs:
        n = int(round(l / base_unit))
        if n <= 0:
            n = 1
        bit_list.extend([v] * n)
    return bit_list


def bits_to_ascii(bit_list):
    bitstr = "".join(str(b) for b in bit_list)
    bitstr = bitstr[: len(bitstr) // 8 * 8]  # 截断到 8 的倍数
    bytes_vals = [int(bitstr[i : i + 8], 2) for i in range(0, len(bitstr), 8)]
    msg = "".join(chr(b) for b in bytes_vals)
    return msg, bytes_vals, bitstr


def decode_hidden_message(path: str):
    rate, data = read_mono_pcm(path)
    env = compute_envelope(data, window_size=100)
    bits_raw = binarize_envelope(env)
    runs = run_length_encode(bits_raw)
    bit_list = expand_runs_to_bits(runs)
    msg, bytes_vals, bitstr = bits_to_ascii(bit_list)
    return msg, bytes_vals, bitstr


if __name__ == "__main__":
    # 把这里改成你的文件名（与脚本在同一路径下）
    wav_path = "feel.wav"

    msg, bytes_vals, bitstr = decode_hidden_message(wav_path)

    print("Decoded bytes:", bytes_vals)
    print("Decoded message:")
    print(msg)

```

```python
I Feel Fantastic heyheyhey
```

Challenge 3

She just feels love, and her legend once spread across YouTube. Her song touched hearts, but the original video on the YouTube platform has been removed — deleted, re-uploaded, distorted, like memories fading with time. Through the fragments of public records, find where her voice first echoed: the original video ID, upload date (YYYY-MM-DD), and the one who first shared her song.

在网络存档上找到原视频

```python
https://archive.org/details/youtube-rLy-AwdCOmI
```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251117114508-42qyuk7.png)

```python
rLy-AwdCOmI
Creepyblog
2009-04-15
```

Challenge 4

Her creator captured her voice, preserved in a 15-minute audio/video DVD. She only wanted to sing, and he gave her that chance. If you wish to purchase her album, to hear her songs of love, which link should you visit? After purchasing, who is the sender? And what is the actual creation year when these musical compositions first came to life?

查找购买，基本AI就能出

![1cf1a70d2de5cb4aa4a0eaa7b27b8a77](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic1cf1a70d2de5cb4aa4a0eaa7b27b8a77-20251117114617-a4bubk4.png)

```python
https://androidworld.com/prod68.htm
Chris Willis
2004
```

Challenge 5

本题也是基本AI出的，多提示词几次，就会给出下面这个，但是有个坑点

john-louis-bergeron和john_louis-bergeron都会导航到那个网站，但是交后面那个是错误，因为这个卡住了，错失三血

```python
https://www.findagrave.com/memorial/63520325/john-louis-bergeron
```

‍
