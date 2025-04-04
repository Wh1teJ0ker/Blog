---
title: 2024数信杯北区决赛
slug: 2024-digital-cup-north-district-final-z1f5wbd
url: /post/2024-digital-cup-north-district-final-z1f5wbd.html
date: '2024-09-30 17:35:28+08:00'
lastmod: '2025-04-05 00:39:32+08:00'
toc: true
categories:
  - CTF-Writeup
isCJKLanguage: true
---

# 2024数信杯北区决赛

# 数据分析

## secret\_1

> 小强离开电脑的时候，某人把小强的秘密给偷走了，还把文件修改覆盖了，作案脚本也删了。请帮助小强找到丢失的相关数据。
>
> 1.提交加密算法工具当中的flag值。（提交示例：flag{\*}）

010直接搜索到了

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929105902-unfy12s.png)​

## secret\_2

> 2.恢复图片中的flag值。

```bash
python2 vol.py -f ../data1.raw --profile=Win7SP1x64 filescan | grep flag
python2 vol.py -f ../data1.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000007f3f17b0 -D ./
```

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929154653-6xnpnk7.png)​

找到了flagg.png

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929154923-zhdadtq.png)​

然后在相同目录下发下了一个pyc文件，提取出来进行反编译得到源码

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929155248-l5hfsb2.png)​

```bash
#!/usr/bin/env python
# Version: Python 3.7

def encode(png):
    flag = 'flag{eba771fd-2b03-418f-b11a-60f1141c99ee}'
    lens = len(flag)
    with open(png, 'rb') as f:
        pic_bytes = f.read()
        output_bytes = bytearray()
        for i in range(len(pic_bytes)):
            output_bytes.append(pic_bytes[i] ^ ord(flag[i * 2 % lens]))
    with open(png, 'wb') as f:
        f.write(output_bytes)

def decode(png):
    flag = 'flag{eba771fd-2b03-418f-b11a-60f1141c99ee}'
    lens = len(flag)
    with open(png, 'rb') as f:
        pic_bytes = f.read()
        output_bytes = bytearray()
        for i in range(len(pic_bytes)):
            output_bytes.append(pic_bytes[i] ^ ord(flag[i * 2 % lens]))
    with open(png, 'wb') as f:
        f.write(output_bytes)

# 示例文件路径
file_path = './flag.png'

# 使用示例
#encode(file_path)  # 加密
decode(file_path)  # 解密

```

最终得到flag

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929155314-wtpmccl.png)​

## secret\_3

> 3.提交压缩包当中的flag值。

待复现（

## history\_1&&history\_2

> 浏览器历史数据查找。
>
> 1.提交flag中uuid值32位小写md5加密第一位为4的uuid（提交示例：9c26d7a6-ea44-4beb-96a8-bc9c75866fef)
>
> 2.提交flag中uuid值32位小写md5加密第一位为a的uuid（提交示例：9c26d7a6-ea44-4beb-96a8-bc9c75866fef）

```bash
python2 vol.py -f ../data2.raw --profile=Win7SP1x64  filescan | grep ".ipynb"
```

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929155457-glljhw5.png)​

```bash
python2 vol.py -f ../data2.raw --profile=Win7SP1x64  dumpfiles -Q 0x000000007d843bd0 -D ../
python2 vol.py -f ../data2.raw --profile=Win7SP1x64  dumpfiles -Q 0x000000007da54b40 -D ../
```

分别提取出来得到两个flag

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929155627-cqijbes.png)​

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929155637-tkgvloq.png)​

```bash
3d45f56a-b63c-44bd-adea-9aad22ae2e20
fe55e2fb-ae4f-4b6d-b93d-da42479b5d69
```

# 数据安全

## ez\_sign

弱密码爆破出来，123456

然后part1直接在图片

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929155801-iqodphc.png)​

part2流量包直接得到

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929155845-w281ibg.png)​

part3将异或FF得到压缩包

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929102759-bvl6c0h.png)​

```bash
flag{266c7354-0817-4694-9494-c727479d8f1a}
```

## 签到寄语

找到开源项目[libcimbar](https://github.com/sz3/libcimbar)

扫码即得

## Pixel

先把文件头改一下得到png图片

同时文件头有提示sm4

然后lsb隐写得到三个参数

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/image-20240929170251-rtlsrki.png)​

​![42f55394355b851f5adfaa50b5f0480](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/42f55394355b851f5adfaa50b5f0480-20240929170301-qi1ipqv.jpg)​

# 数据算法

## 水印攻击

这个版本分不是很高（

```python
import cv2
import numpy as np

def add_gaussian_noise(image, mean=0, var=0.01):
    sigma = var**0.5
    gauss = np.random.normal(mean, sigma, image.shape).astype('uint8')
    noisy_image = cv2.add(image, gauss)
    return noisy_image

def add_salt_and_pepper_noise(image, salt_prob=0.01, pepper_prob=0.01):
    noisy_image = np.copy(image)
    total_pixels = image.size
    num_salt = np.ceil(salt_prob * total_pixels)
    num_pepper = np.ceil(pepper_prob * total_pixels)

    # 添加盐噪声
    coords = [np.random.randint(0, i - 1, int(num_salt)) for i in image.shape]
    noisy_image[coords[0], coords[1], :] = 1

    # 添加胡椒噪声
    coords = [np.random.randint(0, i - 1, int(num_pepper)) for i in image.shape]
    noisy_image[coords[0], coords[1], :] = 0

    return noisy_image

# 读取原图
input_image = cv2.imread('./input.png')

# 添加高斯噪音
noisy_image = add_gaussian_noise(input_image)

# 添加椒盐噪音
final_image = add_salt_and_pepper_noise(noisy_image)

# 保存结果
cv2.imwrite('result1.png', final_image)

```
