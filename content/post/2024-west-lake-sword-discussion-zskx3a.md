---
title: 2024西湖论剑
slug: 2024-west-lake-sword-discussion-zskx3a
url: /post/2024-west-lake-sword-discussion-zskx3a.html
date: '2024-08-26 13:49:49+08:00'
lastmod: '2025-04-04 19:41:01+08:00'
toc: true
isCJKLanguage: true
categories:
  - CTF-Writeup
---

# 2024西湖论剑

# 2024西湖论剑

## easy\_rawraw

**考点：内存分析，密码提取**

重新对这道题剖析一下

本题的描述为easy raw! many passwords!

关键词为passwords

有端联想，可能存在的就是账户的密码，剪切板中是否存在密码，是否有密码的hash，以及一些可能的爆破操作

首先看一下账户的密码，有两种方法

第一种是PasswareKitForensic

​![Zgcjdf7PslzYxia](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-Zgcjdf7PslzYxia-20240826135201-p5rrfxi.png)​

第二种是使用mimikatz

```plain
#确定镜像版本
vol.py -f rawraw.raw imageinfo
vol.py --plugins=./volatility/plugins/ -f rawraw.raw  --profile=Win7SP1x64 mimikatz
```

​![bMwQquC2hcr5iax](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-bMwQquC2hcr5iax-20240826135201-5c5x2ww.png)​

其次还存在一个密码

也有两种方法

第一种是010打开，搜索关键词检索我们可以发现

​![aCFMNyxAcOGQep7](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-aCFMNyxAcOGQep7-20240826135201-gh381a1.png)​

第二种我们检索一下剪切板内容

```plain
vol.py -f rawraw.raw --profile=Win7SP1x64 clipboard
vol.py -f rawraw.raw --profile=Win7SP1x64 clipboard -v  #查看详细内容
```

​![FdwmvIgG2kbYhio](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-FdwmvIgG2kbYhio-20240826135202-yhtoqzg.png)​

​![MJdNU1CocaFPOxS](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-MJdNU1CocaFPOxS-20240826135203-oo2a2uc.png)​

接着，继上面得到两个密码后，我们来搜索密码关键词

```plain
vol.py -f rawraw.raw --profile=Win7SP1x64 filescan | grep pass
```

​![TY7WsbnJz6Lli1C](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-TY7WsbnJz6Lli1C-20240826135203-hqlcfwh.png)​

发现存在一个压缩包

然后将其dump出来

```plain
vol.py -f rawraw.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003df8b650 -D ./
```

分离出一张图片，图片里有压缩包

```plain
root@DESKTOP-BESI31C:/home/wjy/tools/volatility-master# binwalk pass.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 510 x 133, 8-bit/color RGBA, non-interlaced
3185          0xC71           TIFF image data, big-endian, offset of first image directory: 8
9831          0x2667          Zip archive data, encrypted at least v2.0 to extract, compressed size: 1906, uncompressed size: 3299, name: pass.txt
11881         0x2E69          End of Zip archive, footer length: 49, comment: "Have a good New Year!!!!!!!"
```

然后根据这个提示很容易猜出秘密就是20240210，当然直接爆破也是很快的

于是得到了一个密码本

我们查看进程可以发现存在一个VeraCrypt.exe

​![5XBzJ2vFIbu73ZD](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-5XBzJ2vFIbu73ZD-20240826135204-089nc2n.png)​

先使用`DasrIa456sAdmIn987`​去解压mysecretfile.rar

然后进行挂载，并使用pass.txt作为密码本去解密`das123admin321`​

在隐藏项目中发现一个data.xlsx，但也存在密码，我们使用第一个获取的`das123admin321`​

​![tfXjoNUalyiwS64](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-tfXjoNUalyiwS64-20240826135204-m53w6e5.png)​

‍
