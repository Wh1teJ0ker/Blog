---
title: Tryhackme-easy-Agent Sudo
slug: tryhackmeeasyagent-sudo-z1k6ga4
url: /post/tryhackmeeasyagent-sudo-z1k6ga4.html
date: '2024-08-14 14:04:54+08:00'
lastmod: '2025-05-07 21:31:14+08:00'
toc: true
categories:
  - penetration
isCJKLanguage: true
---

# Tryhackme-easy-Agent Sudo

# +Agent Sudo

## Enumerate

1. How many open ports?  
    可能是因为网络延迟的问题，导致开始的时候一个端口都没扫描出来，延时可以适当开高一点点

```plain
3
```

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-pV4LatyfSXNCl35-20250507212926-cbjebbe.png)​

2. How you redirect yourself to a secret page?

```plain
user-agent
```

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-OlMXjakTzYwE74N-20250507212926-z7uw9w0.png)​

3. What is the agent name?  
    user-agent参数为C的时候，可以收到回复

```plain
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!

From,
Agent R
```

因此可以获取本题的答案是

```plain
chris
```

## Hash cracking and brute-force

FTP password

1. FTP password

```plain
crystal
```

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-LI6Zid3JzXKVAYE-20250507212926-d9bjf3w.png)​

2. Zip file password

```plain
ftp> ls
229 Entering Extended Passive Mode (|||57590|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> mget *
mget To_agentJ.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||37193|)
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
100% |*************************************************************************************************************|   217       53.09 KiB/s    00:00 ETA
226 Transfer complete.
217 bytes received in 00:00 (0.75 KiB/s)
mget cute-alien.jpg [anpqy?]? y
229 Entering Extended Passive Mode (|||42821|)
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
100% |*************************************************************************************************************| 33143      113.24 KiB/s    00:00 ETA
226 Transfer complete.
33143 bytes received in 00:00 (57.12 KiB/s)
mget cutie.png [anpqy?]? y
229 Entering Extended Passive Mode (|||18497|)
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
100% |*************************************************************************************************************| 34842       60.41 KiB/s    00:00 ETA
226 Transfer complete.
34842 bytes received in 00:00 (40.51 KiB/s)
```

ftp登录之后将文件进行下载，然后寻找相关线索  
将图片分析后发现存在一个压缩包

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ binwalk -e cutie.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression

WARNING: Extractor.execute failed to run external extractor 'jar xvf '%e'': [Errno 2] No such file or directory: 'jar', 'jar xvf '%e'' might not be installed correctly
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

分离开后确实有密码，开始爆破

```plain
┌──(kali㉿kali)-[~/桌面/_cutie.png.extracted]
└─$ john hash                                         
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
alien            (8702.zip/To_agentR.txt)   
1g 0:00:00:00 DONE 2/3 (2024-03-05 01:33) 1.315g/s 58478p/s 58478c/s 58478C/s 123456..Peter
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

得到密码

```plain
alien
```

3. steg password  
    解压上述压缩包后我们得到一段信息

```plain
Agent C,
We need to send the picture to 'QXJlYTUx' as soon as possible!
By,
Agent R
```

base64后得到

```plain
Area51
```

4. Who is the other agent (in full name)?  
    从cute-alien.jpg中提取数据，然后得到

```plain
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

5. SSH password

```plain
hackerrules
```

## Capture the user flag

1. What is the user flag?

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ ^[[200~ssh james@10.10.212.207   ~
zsh: bad pattern: ^[[200~ssh
                                                                                                                                                      
┌──(kali㉿kali)-[~/桌面]
└─$ ssh james@10.10.212.207   
The authenticity of host '10.10.212.207 (10.10.212.207)' can't be established.
ED25519 key fingerprint is SHA256:rt6rNpPo1pGMkl4PRRE7NaQKAHV+UNkS9BfrCy8jVCA.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.212.207' (ED25519) to the list of known hosts.
james@10.10.212.207's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
james@agent-sudo:~$ cat user_flag.txt 
b03d975e8c92a7c04146cfa7a5a313c7
```

因此可以得到本题的flag

```plain
b03d975e8c92a7c04146cfa7a5a313c7
```

2. What is the incident of the photo called?  
    在该文件下还发现存在一个图片，传输至本地查看

```plain
sudo scp james@10.10.212.207:Alien_autospy.jpg ~/
```

尝试传输发现权限不足

```plain
Sorry, user james is not allowed to execute '/usr/bin/scp james@10.10.212.207:Alien_autospy.jpg /home/james/' as root on agent-sudo.
```

枚举一下权限组信息

```plain
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Sorry, try again.
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

提权步骤看下面

```plain
Roswell alien autopsy
```

## Privilege escalation

1. CVE number for the escalation  
    查询关键词

```plain
(ALL, !root) /bin/bash
```

发现存在漏洞[sudo 1.8.27 - Security Bypass - Linux local Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/47502)

```plain
CVE-2019-14287
```

2. What is the root flag?

```plain
root@agent-sudo:/root# ls
root.txt
root@agent-sudo:/root# cat root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
```

3. (Bonus) Who is Agent R?

```plain
DesKel
```

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-vhJLdnYr8VDmCqj-20250507212927-e4xmfx1.png)​
