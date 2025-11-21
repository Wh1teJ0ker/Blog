---
title: 2025黑龙江省大学网络安全竞赛
slug: 2025-heilongjiang-university-network-security-competition-tm0yk
url: /post/2025-heilongjiang-university-network-security-competition-tm0yk.html
date: '2025-09-19 09:31:42+08:00'
lastmod: '2025-11-21 10:45:01+08:00'
categories:
  - CTF-Writeup
description: 不吐不快，嘻嘻😁
toc: true
isCJKLanguage: true
---



# 2025黑龙江省大学网络安全竞赛

# 前言

OK，不吐不快，有的学校真是脸都不要了，黑龙江那么大点地，打比赛的基本谁不认识谁，什么神秘学五年CTF狠狠拿下PWN一血，哎哟我去，比赛的时候看到有队伍打PWN狠拿一血，我都怀疑了是天才少年了😊，甚至准备社交一下，如果真是技不如人，心甘情愿，结果，你的意思是前两年PWN毫无长进，今年突飞猛进，直到赛后拿到手机，才知道原来是赛题比我先出赛场了😅🤣，至少演一下呢🥺，什么神秘PWN+Crypto大手子啊，还有打那么久比赛也是第一次见线下光明正大换座位，更别说有的平台故障频出，先是时间校准不对，导致平台提前上题，然后网络隔离做的一坨，第一次见同队使用思源同步进度，被强行Ban，看那队女生少，好欺负？😈

# Web

## WEB-1

```python
changeSunNum (num = 25) { let self = this window._main.allSunVal += num self.sun_num += num var xhr = new XMLHttpRequest(); xhr["\x6f\x70\x65\x6e"]('\x50\x4f\x53\x54', '\x2e\x2f\x67\x65\x74\x67\x61\x6d\x65\x2e\x70\x68\x70', true); xhr["\x73\x65\x74\x52\x65\x71\x75\x65\x73\x74\x48\x65\x61\x64\x65\x72"]('\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x54\x79\x70\x65', '\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x2d\x77\x77\x77\x2d\x66\x6f\x72\x6d\x2d\x75\x72\x6c\x65\x6e\x63\x6f\x64\x65\x64'); var $mmzGo1 = '\x73\x75\x6e\x6e\x75\x6d\x3d' + encodeURIComponent(self["\x73\x75\x6e\x5f\x6e\x75\x6d"]); xhr["\x73\x65\x6e\x64"]($mmzGo1); xhr.onreadystatechange = function() { if (xhr.readyState === 4 && xhr.status === 200) { var response = xhr.responseText; console.log(response); } }; } }
```

解混淆

然后得到

```python
xhr.open('POST', './getgame.php', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
 var $mmzGo1 = 'sunnum=' + encodeURIComponent(self.sun_num);
```

![QQ_1758245496106](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/PicQQ_1758245496106-20250919093205-zdlolng.png)

## Web-3

前端提示两位数字

![QQ_1758248444795](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/PicQQ_1758248444795-20250919102113-xq7ysej.png)

发现密码81

然后有一张图片

![QQ_1758248504244](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/PicQQ_1758248504244-20250919102147-kaljcv5.png)

![QQ_1758248513125](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/PicQQ_1758248513125-20250919102158-lxg6fv0.png)

# Misc

## MISC-1

比赛的时候觉得线下出这种东西就是SB，感谢@NepCTF2022

(当然赛后朋友告诉我IDAT里有，这是后话

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20250919100159-yxidbpf.png)

```python
Kafkaisthebest
```

压缩包密码

直接爆破宽高得

![QQ_1758247411131](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/PicQQ_1758247411131-20250919100337-ey2tbfx.png)

## Misc-2

Ok，又不得不说我们某比赛的选题质量和裁判人员的能力问题了

一个基础的鼠标流量，但是知识点出的基础，题目就不基础

```python
import matplotlib.pyplot as plt
import numpy as np

def get_XY():
    posx = 0
    posy = 0
    out = []

    with open("data.txt") as f:
        for line in f:
            hexs = line.strip()
            if len(hexs) != 12:
                continue
            
            flag = int(hexs[2:4], 16)
            dx   = int(hexs[4:6], 16)
            dy   = int(hexs[6:8], 16)

            if dx > 127: dx -= 256
            if dy > 127: dy -= 256

            posx += dx
            posy += dy

            if flag == 1:        # 只记录左键轨迹
                out.append(f"{posx} {posy}")

    with open("xy.txt", "w") as f:
        f.write("\n".join(out))


def plot():
    x, y = np.loadtxt("xy.txt", unpack=True)

    segments = []
    current = [0]

    for i in range(1, len(x)):
        dx = abs(x[i] - x[i-1])
        dy = abs(y[i] - y[i-1])
        if dx > 50 or dy > 50:   ）
            current.append(i)

    current.append(len(x))

    colors = ["red", "blue", "green", "purple", "orange", "cyan"]

    plt.figure(figsize=(6, 10))
    for idx in range(len(current)-1):
        s = current[idx]
        e = current[idx+1]
        color = colors[idx % len(colors)]
        plt.plot(x[s:e], -y[s:e], ".", markersize=2, color=color)

    plt.savefig("plot.png")


if __name__ == "__main__":
    get_XY()
    plot()

```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251121102719-7rezj0s.png)

答案是2004113，但是前面还有两个字母SB😅，问裁判答案格式是什么也不说，一直说你再想想🤣

## Misc-3

一个BMP，由于位深度为0，导致打不开

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251121103239-13o0i2k.png)

恢复两个值

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251121103339-nlnhjvj.png)

得到原始图片![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251121103432-5azt77b.png)

zsteg无结果，但是stegsolve能出，不太清楚为什么，有知道的师傅可以解释一下

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251121103622-ppx9s2d.png)

## KeePass数据泄漏-1

可以发现 online-list 的请求，其中存有聊天室内所有在线⽤⼾，如图：

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251121104129-tzv6c7d.png)

```python
JusticeEnforcement-DeepMountains-nullSecurity-zhaowendao
```

从 updated-chats JSON 记录中可以查找到这样⼀条信息：（再次质疑审题质量和能力，非得最后发公告，赛前但凡审一遍呢？）

```python
{"updated_chats":
[{"id":30,"sender_id":11,"group_id":2,"room_id":2,"type":5,"message":"
{\"message\":\"\u6211\u8fd9\u91cc\u6709\u6700\u65b0\u7248\u7684keepass\uff0c\u4f60\u7
6f4\u63a5\u4ece\u8fd9\u4e2a\u94fe\u63a5\u4e0a\u4e0b\u8f7d\u5c31\u884c\u3002\\nhttp:\\
\/\\\/124.221.70.199:8877\\\/KeePass_latest.zip\\n\",\"title\":\"http:\\\/\\\/124.221
.70.199:8877\\\/KeePass_latest.zip\",\"description\":null,\"image\":null,\"code\":\"\
",\"url\":\"http:\\\/\\\/124.221.70.199:8877\\\/KeePass_latest.zip\"}","status":2,"ti
me":"2024-01-26 14:26:14","updated_at":"2024-01-26 14:26:50"},
{"id":31,"sender_id":10,"group_id":2,"room_id":2,"type":1,"message":"\u8c22\u8c22\uff
01dalao","status":2,"time":"2024-01-26 14:26:30","updated_at":"2024-01-26
14:26:50"}]}
```

```python
2024/01/26/14:26:30 （根据公告修改为24）
```

按照攻击者聊天信息给出的链接，在流量包内找到了压缩包，其中的 Keepass.config.xml 包含了可疑内容

![QQ_1758252814728](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/PicQQ_1758252814728-20250919113338-t8ke0y5.png)

获取 giao.xml 这个⽂件查找

![QQ_1758252125609](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/PicQQ_1758252125609-20250919112208-qxdahu9.png)

‍
