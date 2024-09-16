---
title: 2024NepCTF
date: '2024-08-24 14:18:12'
updated: '2024-09-16 16:48:36'
permalink: /post/2024nepctf-jlgr9.html
comments: true
toc: true
---

# 2024NepCTF

(PS:今年刚开始在研究硬件那个，后来也没花太多时间在这个上面，hhh)

# Misc

## NepMagic —— CheckIn

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916165038.png)​

确信，我没意见

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916165039.png)​

## 3DNep

‍

​![00003458](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916165040.png)​

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916165043.png)​

ps不会用，所以用excel

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916165045.png)​

## Nemophila

先完成一个挑战

```python
import base64

print("这里有一个藏宝室，镇守着一个宝箱怪，当你说出正确的口令时，你也就快获得了这个屋子里最至高无上的宝物。")
print("提示：宝箱怪只会提示你口令正确与否，请你试试吧！")
flag = input('Turn in your guess: ')

if len(flag) !=48:
    print("长度不对！")
    exit(1)

if ord(flag.capitalize()[0]) != 83 or not flag[0].islower():
    print("Please try again!")
    exit(1)

if flag[-3:] != "ve}":
    print("Please try again!")
    exit(1)  

if flag.count(chr(95)) != 4:
    print("Please try again!")
    exit(1)

if base64.b64encode((flag[10:13]+flag[28:31]).encode('utf-8')).decode() != 'RnJpSGlt':
    print("Please try again!")
    exit(1)

if int(flag[24:26]) > 10 and int(flag[24:26]) < 20 and pow(int(flag[24:26]),2,5) != 0:
    print("好像有点不对！")
    exit(1)

number = flag[33] + flag[41] + flag[43:45]
if int(number) * 9_27 != 1028970 and not number.isnumeric():
    print("还是不对呢！")
    exit(1)

if flag[35:41].replace("e", "1") != "1t1rna":
    print("Please try again!")
    exit(1)

if flag[31:33].swapcase() != "ME":
    print("这不是我!")
    exit(1)

if list(map(len,flag.split("_"))) != [6, 12, 14, 7, 5] and list(map(len,flag.split("&"))) != [17, 9, 20]:
    print("换个顺序！")
    exit(1)  

if ord(min(flag[:2].swapcase())) != 69:
    print("Please try again!")
    exit(1)  

if flag[2] + flag[4:6] != "cet4"[:3]:
    print("我不想考四级！")
    exit(1)

new=""
for i in flag[7:10] + flag[18] + flag[26]: new += chr(ord(i) + 1)
if new != "jt|Df":
    print("Please try again!")
    exit(1)  

if "SunR" in flag and "eren" in flag:
    print("好像对了！可以先去试试！")
    exit(1)

print("恭喜你~发现了上个世纪的秘密~快去向冒险家协会索要报酬吧！")
```

然后浅浅完成一下

```python
#1flag 必须是48个字符长，已经满足。
flag = list('?' * 48)
#2第一字符要为 's'
flag[0] = 's'

#3最后三个字符为 've}'
flag[-3:] = list("ve}")

#4需要4个下划线
flag[6] = '_'
flag[19] = '_'
flag[34] = '_'
flag[42] = '_'
# 5. 部分位置的Base
flag[10:13] = "Fri"
flag[28:31] = "Him"
#6
flag[24:26] = "15"
#7
flag[33] = "1"
flag[41] = "1"
flag[43:45] = "10"
#8
flag[35:41]= "eterna"
#9
flag[31:33]= "me"
#10
flag[17] = '&'
flag[27] = '&'
#11
flag[:2] = "se"
#12
flag[2] = "c"
flag[4:6] = "et"
#13
flag[7:10] = "is{"
flag[18] = "C"
flag[26] = "e"

flag = ''.join(flag)
print(flag)
#sec?et_is{Fri????&C_????15e&Himme1_eterna1_10ve}
#Frieren&C_????15e&Himme1_eterna1_10ve
#secret_is{Frieren&C_????15e&Himme1_eterna1_10ve}
```

中间根据镜莲华的花语以及《葬送的芙莉莲》猜测了一下得到相关的单词，然后再进行爆破

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916165046.png)​

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916165047.png)​

得到了压缩包密码

```python
secret_is{Frieren&C_SunR15e&Himme1_eterna1_10ve}
```

然后用这个进行异或

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916165049.png)​

保存图片，爆破宽高

​![download-修复高宽](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916165050.png)​

```python
NepCTF{1f_I_were_the_on1y_one_i_would_N0T_be_able_to_see_this_Sunrise}
```

（PS:骂一句，sb吧，图片里搞大写的i和小写的l，还不弄个特殊的能看出区别的字体，简直了，出题人狠狠地该被骂，做出来了体验感极差）

## NepCamera

（PS：会记得赛后复现的）

```python
tshark -r ./NepCamera.pcapng -T fields -e usb.iso.data -c 1 > ./out1
tshark -r ./NepCamera.pcapng -T fields -e usb.iso.data -c 2 > ./out2
tshark -r ./NepCamera.pcapng -T fields -e usb.iso.data -c 3 > ./out3
tshark -r ./NepCamera.pcapng -T fields -e usb.iso.data -c 4 > ./out4
tshark -r ./NepCamera.pcapng -T fields -e usb.iso.data -c 5 > ./out5
tshark -r ./NepCamera.pcapng -T fields -e usb.iso.data -c 7 > ./out7
tshark -r ./NepCamera.pcapng -T fields -e usb.iso.data -c 8 > ./out8
tshark -r ./NepCamera.pcapng -T fields -e usb.iso.data -c 42 > ./out42
tshark -r ./NepCamera.pcapng -T fields -e usb.iso.data -c 50 > ./out50
```

提出来后，结构没搞懂，图片只能恢复出模糊的一部分，修不好，等wp
