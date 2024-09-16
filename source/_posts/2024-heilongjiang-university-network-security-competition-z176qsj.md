---
title: 2024黑龙江省大学网络安全竞赛
date: '2024-09-16 16:30:59'
updated: '2024-09-16 18:31:41'
permalink: /post/2024-heilongjiang-university-network-security-competition-z176qsj.html
comments: true
toc: true
---

# 2024黑龙江省大学网络安全竞赛

备注：图片图床使用为Github，打不开需要挂梯子！

---

# 前言

遗憾告北，没能守住（

整体成绩很糟糕

这里有比赛当时的题解，也有复现（

不会密码，crypto方向的赛题都是强行出来的

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916185107.png)​

# Web

## Crawl

这边使用WinHTTrack.exe做一个爬取的操作

得到一个静态的网页文件

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916183124.png)​

然后使用递归查找，发现flag

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916185117.png)​

## FileInclusion

使用日志包含进行getshell

先在User-Agent传入phpinfo

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916185119.png)​

然后读取日志文件，发现flag

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916185121.png)​

```python
DASCTF{22743534597924607412099622973209}
```

‍

## Minesweepe

将原有的jms代码复制到新的文件

然后在失败中加入那串疑似flag判断的内容

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916185123.png)​

选择替换原有文件为本地文件

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916185126.png)​

然后初级，中级，高级各玩输一次，就得到全部flag了

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916185129.png)​

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916185132.png)​

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916185135.png)​

```python
DASCTF{c4a204599255589b065eb366cf514aee}
```

## 龙龙的getshell

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916182738.png)先进行爆破

然后得到第一个地址

```python
/funcccccccccccccccction.php
```

```php
<?php
error_reporting(0);
highlight_file(__FILE__);

if(isset($_GET['boy']) && isset($_GET['girl']))
{
    $Boy = $_GET['boy'];
    $Girl = $_GET['girl'];

    if(preg_match("/[0-9]/",$Girl)){
        die("hacker!");
    }
    else{
        if(intval($Girl)){
            if(preg_match("flag|system|ls|pass|cat|chr|tac|nl|od|ini_set|eval|exec|dir|\.|\`|show|file|assert|\<|popen|pcntl|var_dump|print|var_export|echo|implode|print_r|getcwd|head|more|less|tail|vi|sort|uniq|sh|include|scandir|\/| |\?|mv|cp|next|fopen|show_source|highlight_file|zip|data|http|input|glob|\~|\^|\||\&|\*|\%/i",$Boy)){
                die("hacker!!!");
            }
            else{
                if(strlen($Boy)<17){
                eval($Boy);
                }
                else{
                die("hacker!!!!");
                } 
            }
        }
        else{
            die("hacker!!");
        }
    }
    }
```

最后竟然直接phpinfo就出了，是预期？还是非预期？

```php
?girl[]=a&boy=phpinfo();
```

## web小结

难度不高，但有点脑洞（大概？

外加线下，单人看三个方向还是超出我的能力范畴了

唉，下次加油吧（

# Misc

## what\_flag

首先解压缩文件，得到shaflag.zip，然后伪加密进行修复

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916185138.png)​

得到一个hash字符串，四十位的，是sha1算法的，然后挨个爆破即可（手动的

```python
DASCTF{22c12dadc508e5fea12f2eb8c9eb4567}
```

## wav

```php
# 使用：.\wv音频处理.py 2333.wav
# author: CHTXRT
import sys
import wave
import struct

wav = wave.open('./dududu.wav','r')
frame = wav.getnframes()
data = wav.readframes(frame)

h = [0] * (len(data) // 2)
for i in range(len(data) // 2):
    h[i] = (struct.unpack('<h', data[i * 2:i * 2 + 2]))[0]  

threshold = 15000  

for i in range(0, len(h), 1): 
    if h[i] > threshold:  
        print('1', end='')
    else:  
        print('0', end='')
```

然后转成压缩包，爆破即得flag

PS：赛场的时候差一点点，太可惜了，当时忘记取做调参了

## 特殊流量

不会，给了一共莫名其妙的流量，给了一共提示crc32

实在是对不上这个的脑洞，还有三个pwd1.dat，pwd2.dat，pwd3.dat

爆破完之后就不知道了，hhhh

flag

```php
303030303030303030303032303031303630353131303944383639374530353832313334303031304130343130303931303030303030343730303837303034373030453230303736303031363030433630303636303033313131303039313130353030303030333033343931324431304130383030303038303841354330303031303030313031323132363638463437373841423631304441344338363133463131454231434139374146303335323131303730314636303432323030303130423037303030303639303130303036303430313042414243393846353443463434443745304230333944353644433338423235433843444533324230304332313237373934454239454341423943343833333443443345314144444231354131443633424532463046464137343330384141363332364237304236433536304341383644313039324445413231424645324632433232374246343431424436364346463743413733323045324337314145303833374337463332433841433135423139374436353434333836393945333137323546393745413843423030303030303030303030303030413630303030303030303030303030303036383244334236333734303030433137324641434241373733
```

pwd1

```python
38ed5de6
```

pwd2

```python
b5186978
```

pwd3

```python
82350eb0
```

# Crypto

## bd

```python
import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad


input_str = "DASCTF{******}"

base64_encoded = base64.b64encode(input_str.encode('utf-8'))
base32_encoded = base64.b32encode(base64_encoded)

iv = b"11111111" 
key = b"DASCTFKY"  
cipher = DES.new(key, DES.MODE_CBC, iv)
padded_data = pad(base32_encoded, DES.block_size)


encrypted_data = cipher.encrypt(padded_data)
print(encrypted_data.hex())
# c76c12c485ca0c8e1a457b3893f976c84c8da18968424d23fb7128792de3ee59047ada411c55fb4141f825caedc85aae1a3d6c8d8236049c472c28cd7890e189c91244413c047184cd5758394dd8293150ea54d809e3256d585ff6e20c0e1c3ac7314e5eb655443b
```

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916185141.png)​

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916183741.png)​

## FactorMe

首先用yafu将n进行分解

```python
P39 = 237510599882137395180233128864117180669
P39 = 302882412196760256820503629389005355153
```

然后按照原有加密方式生成出所有字符集的密文

```python
from Crypto.Util.number import *
from gmpy2 import *

def rsa_decode(flag):
    p = 237510599882137395180233128864117180669
    q = 302882412196760256820503629389005355153
    #n = 71937783414601336597987417717160068788392507962292384623285467144953411137357
    n = p*q
    e = 37139
    m = ord(flag)
    c = hex(pow(m, e, n))
    return c

char_set = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_{}'

for i in range(0, len(char_set)):
    rsa_re = rsa_decode(char_set[i])
    print(f"rsa({char_set[i]}) = {rsa_re}")
```

人工对照后得到flag

```python
DASCTF{8bea8e30-d8c1-4ac9-baa9-9b1f21e1a3f4}
```
