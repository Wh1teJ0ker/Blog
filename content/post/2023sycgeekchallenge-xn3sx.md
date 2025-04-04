---
title: 2023SYCGeekchallenge
slug: 2023sycgeekchallenge-xn3sx
url: /post/2023sycgeekchallenge-xn3sx.html
date: '2023-12-21 13:46:49+08:00'
lastmod: '2025-04-04 19:12:07+08:00'
toc: true
categories:
  - CTF-Writeup
isCJKLanguage: true
---

# 2023SYCGeekchallenge

# 2023SYCGeekchallenge

## Misc

除区块链以外，还差一题ak，太菜啦，qwq\~\~

### cheekin

**考点：LSB隐写**

公众号发送flag，得到一张图片

检查为LSB隐写

​![2zahuAKp7Bx4iTI](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-2zahuAKp7Bx4iTI-20240826134813-mk6znk3.png)​

### ez\_smilemo

**考点：反编译，字符串搜索**

发现存在data.win文件，搜索后发现反编译工具UndertaleModTool

检索后发现存在一段base字符串

​![ZegbPd1kE59r3h4](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-ZegbPd1kE59r3h4-20240826134814-pwm1vqo.png)​

解密后得到flag

​![fECjwTMqQnR6BWu](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-fECjwTMqQnR6BWu-20240826134814-rvdgvq5.png)​

### 下一站是哪儿呢

**考点：文件分离，银河文字密码，信息搜集**

猪猪侠图片分离出一张图片，银河文字密码解密出得到IWANGTOGOYTOLIQUORCITY

​![a4Jy6OXvd2EhnmI](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-a4Jy6OXvd2EhnmI-20240826134815-6psq3mh.jpg)​

然后搜索酒城得到泸州

查询8月25日航班得到答案

​![pnAdREa6PMzX7sC](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-pnAdREa6PMzX7sC-20240826134815-t81pm93.png)​

### Qingwan心都要碎了

**考点：信息搜集**

做题流程  下载附件，是个网页；点进去，可以看到Yxx发的朋友圈；保存下来，用百度识图；发现是重庆中国三峡博物馆

### xqr

**考点：文件分离，二维码xor**

首先使用foremost分离得到了两张二维码

由于其中有一张是模糊的，刚开始愣生生把那张修复好，但是完全扫不出东西

后来有了hint，才恍然大悟

一张尺寸为15×15，一张为75×75

首先 将两张恢复到同一尺寸，然后使用stegsolve的image combiner功能进行XOR

​![oQXf1PbvkL7g2YE](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-oQXf1PbvkL7g2YE-20240826134815-7ll14j8.png)​

得到的二维码用微信扫码就得到flag

​![bGOlcXa8ekYJ4FE](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-bGOlcXa8ekYJ4FE-20240826134816-xf4mu72.png)​

### Tears of the times

**考点：取证痕迹分析**

发现可疑地址

​![gb6V9ZC1MYpeq7R](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-gb6V9ZC1MYpeq7R-20240826134816-3tvac7o.png)​

找到相应图片买得到flag

​![hLcjIl7mYRrz4Vx](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-hLcjIl7mYRrz4Vx-20240826134817-hy5u4sl.png)​

### extractMe

**考点：crc32碰撞**

crc32碰撞4字节的，结果看图

​![mxFMAk7o5NqtrQ6](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-mxFMAk7o5NqtrQ6-20240826134817-pdr9lxq.png)​

### DEATH\_N0TE

**考点：像素点提取，LSB隐写**

给了一张图片，010打开发现末尾有一段base，解密后无用

lsb查看发现存在一段base，解密后得到前半段flag

同时stegsolve查看发现像素点异常，故尝试提取

最终在每隔5个像素点得到需要的图片

脚本如下

```python
from PIL import Image
# 存放于同名文件夹之下
im = Image.open('start.png')
pix = im.load()
width = im.size[0]
height = im.size[1]
# 根据实际所需填写像素间隔
a = 5
new_width = width // a
new_height = height // a
# 创建一个新的图像对象
new_img = Image.new("RGB", (new_width, new_height))
for x in range(0, width, a):
    for y in range(0, height, a):
        rgb = pix[x, y]
        new_img.putpixel((x // a, y // a), (int(rgb[0]), int(rgb[1]), int(rgb[2])))
new_img.save('new_image.png')
```

​![nDFfAt9IH7wJ5pq](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-nDFfAt9IH7wJ5pq-20240826134817-iy6c3iy.png)​

对照得到字符串

TkFNRV9vMnRha3VYWH0\=

得到一半flag

还有一段藏在lsb隐写给的一长段base64中

​![yjqiaQmLWRSrAfb](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-yjqiaQmLWRSrAfb-20240826134818-9lax2lm.png)​

### DEATH\_N1TE

**考点：gaps拼图，sstv音频隐写**

将图片分帧，gaps拼图，得到一半flag

​![ZehOUiNatAV1oM4](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-ZehOUiNatAV1oM4-20240826134819-raicwba.png)​

使用rx-sstv播放mp3文件获取第一部分flag

​![vTPGmZuJ7QMbX2q](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-vTPGmZuJ7QMbX2q-20240826134819-vysr7j0.png)​

SYC{H4xr0t0r\_14\_Ki114R}

### DEATH\_N2TE

**考点：视频像素点提取**

先视频分帧

```python
import cv2
import os
cap = cv2.VideoCapture('kira.mp4')
output_folder = 'frames'
os.makedirs(output_folder, exist_ok=True)
frame_count = 0
while True:
    ret, frame = cap.read()
    if not ret:
        break
    frame_count += 1
    frame_filename = f"{output_folder}/frame_{frame_count:04d}.jpg"
    cv2.imwrite(frame_filename, frame)
    cv2.imshow('Processed Frame', frame)
    if cv2.waitKey(25) & 0xFF == ord('q'):
        break
cap.release()
cv2.destroyAllWindows()
```

提取所有白色的像素点

```python
import cv2
import numpy as np
import os
input_folder = './frames'
output_image = 'output_combined_image.jpg'
image_files = [f for f in os.listdir(input_folder) if f.endswith(('.jpg', '.png', '.jpeg'))]
max_x, max_y = 0, 0
for image_file in image_files:
    image_path = os.path.join(input_folder, image_file)
    image = cv2.imread(image_path)
    max_x = max(max_x, image.shape[0])
    max_y = max(max_y, image.shape[1])
combined_image = np.zeros((max_x, max_y, 3), dtype=np.uint8)
for image_file in image_files:
    image_path = os.path.join(input_folder, image_file)
    image = cv2.imread(image_path)
    gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    _, binary_image = cv2.threshold(gray_image, 200, 255, cv2.THRESH_BINARY)
    white_pixel_coordinates = np.column_stack(np.where(binary_image == 255))
    for coordinate in white_pixel_coordinates:
        x, y = coordinate
        combined_image[x, y, :] = [255, 255, 255]  # 设置为白色
cv2.imwrite(output_image, combined_image)
cv2.imshow('Combined Image', combined_image)
cv2.waitKey(0)
cv2.destroyAllWindows()
```

得到flag：SYC{we1c0m4\_T0\_De@tH\_W0r1d}

最后压缩一下像素点，是图片更清楚

​![KzQufGPXsp7LZWx](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-KzQufGPXsp7LZWx-20240826134819-ujzh09l.png)​

### 窃听风云

**考点：NTLM协议破解**

就是对捕捉的Ntlm协议进行解析

详细解析如下

[渗透技巧——利用netsh抓取连接文件服务器的NTLMv2 Hash (3gstudent.github.io)](https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%88%A9%E7%94%A8netsh%E6%8A%93%E5%8F%96%E8%BF%9E%E6%8E%A5%E6%96%87%E4%BB%B6%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%9A%84NTLMv2-Hash)

基本格式

NTLMv2的格式为：

```plain
username::domain:challenge:HMAC-MD5:blob
```

然后使用john和rockyou.txt破解

```plain
NETNTLMv2: jack::WIDGETLLC:2af71b5ca7246268:2d1d24572b15fe544043431c59965d30:0101000000000000040d962b02edd901e6994147d6a34af200000000020012005700490044004700450054004c004c004300010008004400430030003100040024005700690064006700650074004c004c0043002e0049006e007400650072006e0061006c0003002e0044004300300031002e005700690064006700650074004c004c0043002e0049006e007400650072006e0061006c00050024005700690064006700650074004c004c0043002e0049006e007400650072006e0061006c0007000800040d962b02edd90106000400020000000800300030000000000000000000000000300000078cdc520910762267e40488b60032835c6a37604d1e9be3ecee58802fb5f9150a001000000000000000000000000000000000000900200048005400540050002f003100390032002e003100360038002e0030002e0031000000000000000000
```

​![yKxAprDETQG3HiV](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-yKxAprDETQG3HiV-20240826134820-5lgults.png)​

​![HM8U4bSsF6fjE1k](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-HM8U4bSsF6fjE1k-20240826134821-4qpgvkn.png)​

### 窃听风云-v2

**考点：NTLM协议破解**

这是仅有的没有做出来的一道题，qwq，其实不难的

基本原理同上，但是由于是使用的smtp协议，所以不能自动解析

```plain
jack::WidgetLLC.Internal:3e3966c8cacd29f7:ddd46fd8f78c262eae16918f66185497:010100000000000050fd26d235edd9011219408ccb8a364800000000020012005700490044004700450054004c004c0043000100100043004c00490045004e00540030003300040024005700690064006700650074004c004c0043002e0049006e007400650072006e0061006c000300360043004c00490045004e005400300033002e005700690064006700650074004c004c0043002e0049006e007400650072006e0061006c00050024005700690064006700650074004c004c0043002e0049006e007400650072006e0061006c000700080050fd26d235edd90106000400020000000800300030000000000000000000000000300000c78e803920758ec5672c36696ee163f6a4e61c8b5463c247daef8571677995a40a001000000000000000000000000000000000000900200053004d00540050002f0075006e007300700065006300690066006900650064000000000000000000
```

​![1sX2j3rEeZNofSw](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-1sX2j3rEeZNofSw-20240826134821-tncf75p.png)​
