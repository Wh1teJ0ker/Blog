---
title: 2024强网拟态
slug: 2024-strong-network-arabia-z2jdx0
url: /post/2024-strong-network-arabia-z2jdx0.html
date: '2024-10-20 02:38:59+08:00'
lastmod: '2025-04-05 00:37:39+08:00'
toc: true
categories:
  - CTF-Writeup
isCJKLanguage: true
---

# 2024强网拟态

备注：图片图床使用为Github，打不开需要挂梯子！

---

备注：图片图床使用为Github，打不开需要挂梯子！

---

# Misc

## ezflag

打开流量包，关注到这两个长度异常的

​![QQ_1729363793177](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1729363793177-20241020024956-0yg1obu.png)​

全部提取出来放到010中，进行十六进制转字符串

​![QQ_1729363897398](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1729363897398-20241020025138-ud14vz7.png)​

然后使用bandzip进行解压缩的操作

新的压缩包拖到010中一看原来是PNG

​![QQ_1729364009062](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1729364009062-20241020025336-n4ffrf1.png)​

转换即得flag

## PvZ

```yaml
李华的梦想是攒钱买毁灭菇加农炮，可是他总攒不住钱，请帮他理财，算一下他刚开始的这局游戏花了多少钱
```

看到数字，图片都懒得看了，直接爆破（爆破大法好了）

先生成1-10000的数字的md5值，然后直接开爆

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20241020031249-u2w6yxi.png)​

得到一张歪斜的不全的二维码和一个角上的信息

​![64dbfc6f48039c277b700e8b958e1be](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/64dbfc6f48039c277b700e8b958e1be-20241020032302-phb2u7z.jpg)​

先使用夸克进行矫正，然后利用

​![QQ_1729365950101](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1729365950101-20241020032552-h39yam9.png)​

然后稍微确定一下定位符的位置，利用ppt进行拼接即可扫得到一串

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20241020032702-qb4h8j9.png)​

微信扫码得到

```yaml
D'`_q^K![YG{VDTveRc10qpnJ+*)G!~f1{d@-}v<)9xqYonsrqj0hPlkdcb(`Hd]#a`_A@VzZY;Qu8NMqKPONGkK-,BGF?cCBA@">76Z:321U54-21*Non,+*#G'&%$d"y?w_uzsr8vunVrk1ongOe+ihgfeG]#[ZY^W\UZSwWVUNrRQ3IHGLEiCBAFE>=aA:9>765:981Uvu-2+O/.nm+$Hi'~}|B"!~}|u]s9qYonsrqj0hmlkjc)gIedcb[!YX]\UZSwWVUN6LpP2HMFEDhHG@dDCBA:^!~<;:921U/u3,+*Non&%*)('&}C{cy?}|{zs[q7unVl2ponmleMib(fHG]b[Z~k
```

结合图片名称猜测得到

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20241020032848-2tbelr8.png)​

## Find way to read video

在gitcode上找到这个相关的用户名

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20241020033230-zvbob7y.png)​

然后一个隐写[spammimic - decoded](https://www.spammimic.com/decode.cgi)

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20241020033204-cp0cmg3.png)​

得到以下信息

```yaml
BV1P62EYHEZd eyJ2IjozLCJuIjoiZmw0ZyIsInMiOiIiLCJoIjoiZGExMTcyNSIsIm0iOjkwLCJrIjo4MSwibWciOjIwMCwia2ciOjEzMCwibCI6NDMsInNsIjoxLCJmaGwiOlsiMjUyZjEwYyIsImFjYWM4NmMiLCJjYTk3ODExIiwiY2QwYWE5OCIsIjAyMWZiNTkiLCIyYzYyNDIzIiwiY2E5NzgxMSIsIjRlMDc0MDgiLCJlN2Y2YzAxIiwiMmM2MjQyMyIsIjI1MmYxMGMiLCI1ZmVjZWI2IiwiZWYyZDEyNyIsIjM5NzNlMDIiLCJjYTk3ODExIiwiNGIyMjc3NyIsImU3ZjZjMDEiLCI3OTAyNjk5IiwiMzk3M2UwMiIsIjRiMjI3NzciLCI3OTAyNjk5IiwiZWYyZDEyNyIsIjI1MmYxMGMiLCIzOTczZTAyIiwiY2E5NzgxMSIsImVmMmQxMjciLCJkNDczNWUzIiwiMjUyZjEwYyIsIjM5NzNlMDIiLCI2Yjg2YjI3IiwiM2UyM2U4MSIsImQ0NzM1ZTMiLCJlN2Y2YzAxIiwiMmU3ZDJjMCIsIjJlN2QyYzAiLCI0YjIyNzc3IiwiNWZlY2ViNiIsIjI1MmYxMGMiLCIyZTdkMmMwIiwiNGIyMjc3NyIsIjNmNzliYjciLCJkMTBiMzZhIiwiMDFiYTQ3MSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiNmUzNDBiOSIsIjZlMzQwYjkiLCI2ZTM0MGI5IiwiMDg0ZmVkMCIsIjE4ZjUzODQiLCIxODlmNDAwIiwiZWY2Y2JkMiIsIjI3OTUyMTciLCJhOTI1M2RjIiwiNGM5NDQ4NSIsIjI1MmYxMGMiLCI4NWY5N2UwIl19
```

得到一个b站的av号和一段base64

```yaml
{"v":3,"n":"fl4g","s":"","h":"da11725","m":90,"k":81,"mg":200,"kg":130,"l":43,"sl":1,"fhl":["252f10c","acac86c","ca97811","cd0aa98","021fb59","2c62423","ca97811","4e07408","e7f6c01","2c62423","252f10c","5feceb6","ef2d127","3973e02","ca97811","4b22777","e7f6c01","7902699","3973e02","4b22777","7902699","ef2d127","252f10c","3973e02","ca97811","ef2d127","d4735e3","252f10c","3973e02","6b86b27","3e23e81","d4735e3","e7f6c01","2e7d2c0","2e7d2c0","4b22777","5feceb6","252f10c","2e7d2c0","4b22777","3f79bb7","d10b36a","01ba471","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","6e340b9","084fed0","18f5384","189f400","ef6cbd2","2795217","a9253dc","4c94485","252f10c","85f97e0"]}
```

研究了一下，猜测v应该是version，n是name

然后扔给gpt帮忙联想猜测

```yaml
v: 可能代表 video（视频）或 version（版本）。
n: 可能是视频的 name（名称）。
s: 可能表示 status（状态），例如播放状态、加载状态等。
h: 可能代表视频的 hash，用于校验或标识视频文件的唯一性。
m: 可能是视频的 duration（时长）或 minutes（分钟数）。
k: 可能是 keyframe（关键帧）数量或某个视频处理的关键值。
mg 和 kg: 可能代表 megabytes 和 kilobytes，表示视频的文件大小。
l: 可能是 length（长度），即视频的总时长。
sl: 可能是 stream level，表示视频流的清晰度等级（如高清、标清）。
fhl: 可能是 frame hash list，即视频每一帧的哈希值列表，用于校验或追踪视频帧。
```

然后爆破sha256的前缀(挺离谱的，真服了)

```python
import hashlib
import string
# 字典范围
chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+-={}|[]\\:\";'<>?,./"
#chars = ''.join(chr(i) for i in range(128))
#chars = string.ascii_letters + string.digits + string.punctuation + string.whitespace

hash_prefixes = ["252f10c", "acac86c", "ca97811", "cd0aa98", "021fb59", "2c62423", "ca97811", 
                 "4e07408", "e7f6c01", "2c62423", "252f10c", "5feceb6", "ef2d127", "3973e02", 
                 "ca97811", "4b22777", "e7f6c01", "7902699", "3973e02", "4b22777", "7902699", 
                 "ef2d127", "252f10c", "3973e02", "ca97811", "ef2d127", "d4735e3", "252f10c", 
                 "3973e02", "6b86b27", "3e23e81", "d4735e3", "e7f6c01", "2e7d2c0", "2e7d2c0", 
                 "4b22777", "5feceb6", "252f10c", "2e7d2c0", "4b22777", "3f79bb7", "d10b36a", 
                 "01ba471", "6e340b9", "084fed0", "18f5384", "189f400", "ef6cbd2", "2795217", 
                 "a9253dc", "4c94485", "252f10c", "85f97e0"]

matched_chars = []


def find_matching_hashes():
    for prefix in hash_prefixes:
        found = False
        for char in chars:

            hash_value = hashlib.sha256(char.encode()).hexdigest()

            if hash_value.startswith(prefix):
                matched_chars.append(char) 
                print(f"匹配字符为: '{char}', Hash: {hash_value}, Prefix: {prefix}")
                found = True
                break
        if not found:
            print(f"前缀未知: {prefix}")

find_matching_hashes()#
final_string = ''.join(matched_chars)
print(f"flag: {final_string}")
#flag{8a368f05-a467-475f-a52f-1b26cc40fc4e}
```

‍
