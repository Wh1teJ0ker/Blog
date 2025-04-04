---
title: 2023HITCTF
slug: 2023hitctf-kovrz
url: /post/2023hitctf-kovrz.html
date: '2023-10-20 13:44:59+08:00'
lastmod: '2025-04-04 18:06:02+08:00'
toc: true
isCJKLanguage: true
categories:
  - CTF-Writeup
---

# 2023HITCTF

# 前言

希望自己下次能有更大的贡献，太菜啦，哭哭（

​![We3CjlQpxTPSgcK](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-We3CjlQpxTPSgcK-20240826134632-ijrfal7.png)​

# Misc

## leftover file

首先查看了一下，发现是modbus协议相关，检查了一下相关功能码

​![pUu1vYTSV2F8Gwe](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-pUu1vYTSV2F8Gwe-20240826134632-e8bkrms.png)​

发现response存在异常

​![6vpOtLGRNk7WuCS](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-6vpOtLGRNk7WuCS-20240826134633-h99mb68.png)​

​![9aefbxp7ENLOMd1](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-9aefbxp7ENLOMd1-20240826134633-nr0pivo.png)尝试根据flag头寻找相关规律

​![vkmWO1qZ74jMobi](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-vkmWO1qZ74jMobi-20240826134634-hzhemc6.png)​

然后每次的功能码3，进行一次新的修改操作

​![GMP5fUcgob2DmRV](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-GMP5fUcgob2DmRV-20240826134634-xb7ktab.png)​

​![K1mdlh3nTRjkWJe](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-K1mdlh3nTRjkWJe-20240826134635-zkgh8w1.png)​

​![27M6IRgJvsZUCxy](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-27M6IRgJvsZUCxy-20240826134635-jbhdp55.png)​

到90 93发现flag已经格式完整

完整exp：

```python
c = [71, 71, 81, 63, 79, 64, 43, 40, 41, 41, 112, 65, 35, 86, 83, 101, 98, 77, 96, 91, 74, 93, 88, 71, 90, 85, 68, 73, 68, 85, 90, 93]
def decrypt(c, x):
    return ''.join([chr(c[i] + i + x) for i in range(len(c))])
def find(c):
    for i in range(26):
        decrypted = decrypt(c, i)
        if decrypted.startswith("HIT"):
            return i, decrypted
    return None, None
x, flag = find(c)
if x :
    print(f"flag: {x}: {flag}")
```

​![rz5YT8Ai2fogaIu](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-rz5YT8Ai2fogaIu-20240826134635-mh0wkdx.png)​

这是仅完成的一题，剩下的是根据官方wp的思路来学习的

单纯菜，qwq\~\~

## network-in-network

**考点：神经网络逆向**

先来看一下官方给的

​![3IeufHGkZVx2Bdw](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-3IeufHGkZVx2Bdw-20240826134636-bsvax9s.png)​

我再研究研究，qwq

## H1F1

**考点：音频反向**

这道题就讲一下思路吧，不想动手复现了

根据官方wp和吉大师傅的简单操作了一下

[2023HITCTF wp (qq.com)](https://mp.weixin.qq.com/s/O14tELa2JCkhJUPA7RNfRw)

只能说学到了一个新的知识：音频diff

首先根据峰值将两端音频对齐，然后对其中一段音频反向

可以发现下图的怪异bit点

​![hvCyXY5inZpN6fS](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-hvCyXY5inZpN6fS-20240826134637-5zvntl8.png)​

进行读取二进制0和1，最后转字符串就行了

# 总结

都什么年代了，哪还有什么传统Misc啊（乐

还有这次比赛的web也确实让人有一种脑干缺失的美

出题人太懂出题了（悲
