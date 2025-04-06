---
title: 2024网鼎杯
slug: 2024-net-ding-cup-xltap
url: /post/2024-net-ding-cup-xltap.html
date: '2024-10-29 11:59:39+08:00'
lastmod: '2025-04-05 00:37:09+08:00'
toc: true
categories:
  - CTF-Writeup
isCJKLanguage: true
---
也是笑话了，p成什么鬼样子了
<!--more-->
# 2024网鼎杯

# Misc

## MISC01

首先打开流量，发现存在多种协议

```shell
S1AP
GTPv2
DIAMETER
```

```shell
在移动通信协议中，S1AP、GTPv2 和 Diameter 协议都可能涉及位置信息。这些协议通常携带不同层级的位置信息，用于不同的功能，如位置更新、会话管理和用户的移动性管理。以下是每种协议中与位置信息相关的字段：

---

### 1. **S1AP (S1 Application Protocol)**
S1AP 是 EPC 和 eNodeB 之间的接口协议，用于管理和信令。以下是 S1AP 中一些与位置信息相关的字段：

- **eCGI (E-UTRAN Cell Global Identifier)**: 包含了小区的唯一标识符。
  - **组成**：PLMN ID (包含 MCC 和 MNC) 和 Cell ID。
  
- **TAI (Tracking Area Identity)**: 标识用户当前所在的跟踪区域。
  - **组成**：PLMN ID 和 TAC (Tracking Area Code)。

- **MME Code 和 MME Group ID**: 用于标识用户接入的 MME。
  
- **Location Reporting Information**: 包含用户的位置报告设置，用于位置更新和用户的移动管理。

- **Global-ENB-ID**: 标识特定的 eNodeB，包含 PLMN ID 和 eNodeB ID。
  
这些字段用于位置更新、移动管理和跟踪用户在网络中的位置变化。

---

### 2. **GTPv2 (GPRS Tunneling Protocol Version 2)**
GTPv2 用于 EPC 中的信令和会话管理，特别是在 S-GW 和 P-GW 之间。以下是 GTPv2 中常见的位置信息字段：

- **User Location Information (ULI)**: 包含用户的位置信息。
  - 可能包含多个字段，如 CGI (Cell Global Identity)、SAI (Service Area Identity)、RAI (Routing Area Identity)、TAI、ECGI 等。
  
- **CGI (Cell Global Identity)**: 包含 PLMN ID 和 Cell ID，用于标识具体的小区。

- **SAI (Service Area Identity)**: 包含 PLMN ID 和 Service Area Code，用于标识服务区域。

- **RAI (Routing Area Identity)**: 包含 PLMN ID 和 Routing Area Code，用于路由区域标识。

- **TAI (Tracking Area Identity)**: 用于标识用户所在的跟踪区域，与 S1AP 中的 TAI 类似。

这些字段在位置更新和会话管理消息中经常使用，例如位置更新请求和建立会话时。

---

### 3. **Diameter (用于 S6a/S6d 接口)**
Diameter 协议用于 MME 和 HSS 之间的信令，通常承载用户订阅和认证信息。在 Diameter 中，位置信息通常存在于以下字段中：

- **EPS-Location-Information**: 包含 eNodeB 信息，用于标识用户的位置信息。
  - 可能包含 MME Code、MME Group ID、ECGI、TAI 等。

- **Location-Information**: 包含用户的位置信息，可用于鉴权或更新位置请求。
  
- **RAT-Type**: 虽然不直接是位置字段，但可以指示用户接入的无线接入类型（如 LTE），这与位置信息一起使用。

- **Origin-Host 和 Origin-Realm**: 表示请求的来源 MME 和域，用于标识服务的源位置。

- **Serving-Node**: 表示服务节点的信息，包括可能的 MME 信息。

这些字段在用户位置更新和设备连接的认证请求中被频繁使用。

---

### 总结

| 协议      | 位置相关字段                               | 说明                                            |
|-----------|-------------------------------------------|-------------------------------------------------|
| **S1AP**  | eCGI, TAI, MME Code, MME Group ID         | 小区标识、跟踪区域标识、MME 标识                |
| **GTPv2** | ULI, CGI, SAI, RAI, TAI                   | 用户位置信息、服务区域、路由区域、跟踪区域      |
| **Diameter** | EPS-Location-Information, Location-Information, Origin-Host | 用户位置信息、位置更新                           |

这些字段用于标识用户的位置和当前连接的网络组件，在不同的通信阶段为用户提供会话管理和位置更新支持。
```

根据gpt的回复，再加上附件名称位MME，重点怀疑是Diameter

依次寻找尝试

​![QQ_1730190191264](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1730190191264-20241029162313-4j2oci3.png)​

最终在这个流中发现EPS-Location-Information字段

​![QQ_1730190262965](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1730190262965-20241029162426-zut3olm.png)​

```shell
da18bee581c4ae
```

md5加密一下

```shell
daedc32bdeceb78094502e481c90c6cc
```

## MISC02

```shell
LinuxUbuntu_6_5_0-41-generic_profilex64
```

## MISC03

一个数据很多的流量

开始的时候查找到有相关webshell的信息

开始的时候一直怀疑需要将webshell进行解密

​![QQ_1730189599339](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1730189599339-20241029161324-441xbp1.png)​

但是解了半天，一直有问题，后来发现原来是将源ip直接提交就行

过滤一下200响应的流，就很容易找到了

​![QQ_1730189771130](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1730189771130-20241029161616-l31904r.png)​

最终提交这个ip即可

```shell
39.168.5.60
```

## MISC04

原题在IrisCTF2024peanoscramble

然后找到原题的wp

https://almostgph.github.io/2024/01/08/IrisCTF2024/

```python
from PIL import Image
from tqdm import tqdm

def peano(n):
    if n == 0:
        return [[0,0]]
    else:
        in_lst = peano(n - 1)
        lst = in_lst.copy()
        px,py = lst[-1]
        lst.extend([px - i[0], py + 1 + i[1]] for i in in_lst)
        px,py = lst[-1]
        lst.extend([px + i[0], py + 1 + i[1]] for i in in_lst)
        px,py = lst[-1]
        lst.extend([px + 1 + i[0], py - i[1]] for i in in_lst)
        px,py = lst[-1]
        lst.extend([px - i[0], py - 1 - i[1]] for i in in_lst)
        px,py = lst[-1]
        lst.extend([px + i[0], py - 1 - i[1]] for i in in_lst)
        px,py = lst[-1]
        lst.extend([px + 1 + i[0], py + i[1]] for i in in_lst)
        px,py = lst[-1]
        lst.extend([px - i[0], py + 1 + i[1]] for i in in_lst)
        px,py = lst[-1]
        lst.extend([px + i[0], py + 1 + i[1]] for i in in_lst)
        return lst

order = peano(6)

img = Image.open(r"C:\Users\ASUSROG\Desktop\chal.png")

width, height = img.size

block_width = width # // 3
block_height = height # // 3

new_image = Image.new("RGB", (width, height))

for i, (x, y) in tqdm(enumerate(order)):
    # 根据列表顺序获取新的坐标
    new_x, new_y = i % width, i // width
    # 获取原图像素
    pixel = img.getpixel((x, height - 1 - y))
    # 在新图像中放置像素
    new_image.putpixel((new_x, new_y), pixel)

new_image.save("rearranged_image.jpg") 
```

​![QQ_1730189087698](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1730189087698-20241029160451-lo0ip5f.png)​

翻转图像后使用微信扫码得到flag

```shell
wdflag{3f531c43-3b8b-42ab-babf-567f1216fa06}
```

‍
