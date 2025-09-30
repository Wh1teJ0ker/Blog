---
categories:
- penetration
date: '2024-08-14 14:06:02+08:00'
description: 日常练习
isCJKLanguage: true
lastmod: '2025-05-07 21:30:11+08:00'
slug: tryhackmeeasyrootme-1bz4w8
title: Tryhackme-easy-RootMe
toc: true
url: /post/tryhackmeeasyrootme-1bz4w8.html
---
# Tryhackme-easy-RootMe

# Reconnaissance

1. Scan the machine, how many ports are open?

```plain
2
```

nmap扫描

```plain
─$ nmap -sV 10.10.24.147            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-27 03:47 EST
Nmap scan report for 10.10.24.147 (10.10.24.147)
Host is up (0.29s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.87 seconds
```

2. What version of Apache is running?  
    根据上述扫描结果得出

```plain
2.4.29
```

3. What service is running on port 22?

```plain
ssh
```

4. Find directories on the web server using the GoBuster tool  
    ​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-JAeXCag7i4V6nPt-20250507212933-k85p9yu.png)​
5. What is the hidden directory?

```plain
/panel/
```

# Getting a shell

在上面找到相关路径之后，是一个文件上传的入口，同时还有一个uploads，是上传文件的存放地址

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-CNL5VpRXo1xe3dy-20250507212933-ub67t0s.png)​

经测试仅对后缀名进行了过滤

通过后缀名加数字成功绕过，但是直接使用正向的连接失效，可能是禁了进口的流量，开始反弹shell

不知道什么缘故，kali虚拟机一直接受不到shell，主机上成功弹出来了，卡了好久，不知道什么原因（

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-DpksGFN39Htuigq-20250507212933-aj01zpv.png)​

```plain
$ cd var/www
$ ls
html
user.txt
```

第一个shell的位置

# Privilege escalation

到了提权的位置。第一个提示说SUID提权

```plain
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} ;
```

得到以下信息

```plain
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/traceroute6.iputils
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/snap/core/8268/bin/mount
/snap/core/8268/bin/ping
/snap/core/8268/bin/ping6
/snap/core/8268/bin/su
/snap/core/8268/bin/umount
/snap/core/8268/usr/bin/chfn
/snap/core/8268/usr/bin/chsh
/snap/core/8268/usr/bin/gpasswd
/snap/core/8268/usr/bin/newgrp
/snap/core/8268/usr/bin/passwd
/snap/core/8268/usr/bin/sudo
/snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8268/usr/lib/openssh/ssh-keysign
/snap/core/8268/usr/lib/snapd/snap-confine
/snap/core/8268/usr/sbin/pppd
/snap/core/9665/bin/mount
/snap/core/9665/bin/ping
/snap/core/9665/bin/ping6
/snap/core/9665/bin/su
/snap/core/9665/bin/umount
/snap/core/9665/usr/bin/chfn
/snap/core/9665/usr/bin/chsh
/snap/core/9665/usr/bin/gpasswd
/snap/core/9665/usr/bin/newgrp
/snap/core/9665/usr/bin/passwd
/snap/core/9665/usr/bin/sudo
/snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9665/usr/lib/openssh/ssh-keysign
/snap/core/9665/usr/lib/snapd/snap-confine
/snap/core/9665/usr/sbin/pppd
/bin/mount
/bin/su
/bin/fusermount
/bin/ping
/bin/umount
```

这是靶机上的信息，我们需要找到异常，此此时尝试在自己主机上使用相同命令

```plain
/usr/bin/fusermount3
/usr/bin/kismet_cap_hak5_wifi_coconut
/usr/bin/kismet_cap_linux_bluetooth
/usr/bin/netkit-rsh
/usr/bin/ntfs-3g
/usr/bin/kismet_cap_nxp_kw41z
/usr/bin/kismet_cap_linux_wifi
/usr/bin/chfn
/usr/bin/kismet_cap_rz_killerbee
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/netkit-rcp
/usr/bin/su
/usr/bin/kismet_cap_ti_cc_2540
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/kismet_cap_ti_cc_2531
/usr/bin/kismet_cap_nrf_51822
/usr/bin/kismet_cap_ubertooth_one
/usr/bin/kismet_cap_nrf_52840
/usr/bin/vmware-user-suid-wrapper
/usr/bin/kismet_cap_nrf_mousejack
/usr/bin/gpasswd
/usr/bin/netkit-rlogin
/usr/bin/sudo
/usr/sbin/mount.cifs
/usr/sbin/mount.nfs
/usr/sbin/pppd
/usr/lib/openssh/ssh-keysign
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/xorg/Xorg.wrap
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

发现/usr/bin/python不应该存在

[python | GTFOBins](https://gtfobins.github.io/gtfobins/python/#suid)

在这里找到相关的提权方式

​![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-tPw5OLoF8iXcBaA-20250507212934-cez2ojq.png)​

```plain
cd root
ls
root.txt
cat root.txt
```

‍
