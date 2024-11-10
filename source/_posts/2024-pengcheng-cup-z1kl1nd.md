---
title: 2024鹏程杯
date: '2024-11-09 18:23:21'
updated: '2024-11-10 15:09:32'
permalink: /post/2024-pengcheng-cup-z1kl1nd.html
comments: true
toc: true
---

# 2024鹏程杯

备注：图片图床使用为Github，打不开需要挂梯子！

---

# Simple_steganography-pcb2024

‍

首先我们使用7z打开压缩包，发现存在一个奇怪的图片，直接解压无法打开

​![QQ_1731147865970](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1731147865970-20241109182427-hukfnuv.png)​

这里转折了一下，用了神奇的qq浏览器

​![QQ_1731148032700](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1731148032700-20241109182713-8ahekyw.png)​

然后分离出来一个jpg图片

​![QQ_1731148134965](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1731148134965-20241109182858-hn9hqpx.png)​

直接一眼看出来是猫脸变换，联想到a=7,b=35

​![00000000](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/00000000-20241109182907-i94qxy8.jpg)​

```python
# -*- coding: UTF-8 -*-

import cv2
import numpy as np
import os

def arnold_decode(image, shuffle_times, a, b, output_file='decoded_image.png'):
    """
    Decodes an RGB image that was encoded by the Arnold transformation.

    Args:
        image (np.array): The RGB image encoded by Arnold transformation.
        shuffle_times (int): Number of iterations for shuffling.
        a (int): Arnold transformation parameter.
        b (int): Arnold transformation parameter.
        output_file (str): Filename for saving the decoded image.

    Returns:
        np.array: The decoded image.
    """
    if image is None:
        raise ValueError("Image not loaded. Check file path or file integrity.")
  
    # Create a new image with the same shape as the input
    decode_image = np.zeros_like(image)
  

    h, w = image.shape[:2]
    N = h  


    for _ in range(shuffle_times):
        for ori_x in range(h):
            for ori_y in range(w):

                new_x = ((a * b + 1) * ori_x - b * ori_y) % N
                new_y = (-a * ori_x + ori_y) % N
                decode_image[new_x, new_y, :] = image[ori_x, ori_y, :]

    cv2.imwrite(output_file, decode_image, [int(cv2.IMWRITE_PNG_COMPRESSION), 0])
    return decode_image


image_path = '/home/Work/pcb/00000000.jpg'
img = cv2.imread(image_path)


if img is None:
    raise FileNotFoundError(f"Image at path '{image_path}' not found. Please check the file path.")


for i in range(1000):
    output_filename = f'./decoded_image_{i}.png'
    arnold_decode(img, shuffle_times=7, a=35, b=i, output_file=output_filename)

```

最终是在变换次数是7的时候得到应该是原始图片

​![QQ_1731148193153](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1731148193153-20241109182955-krrmely.png)​

得到后一半的flag

```python
3_h4ck1ng}
```

还有一个secret.zip压缩包

所以呢，我们刚刚一直没有找到相关的任何线索，发现一个png图片和一个svg文件，所以我们就思考是不是能够直接通过png的头进行爆破

将`89504E470D0A1A0A0000000D49484452`​放入

开始爆破

```python
bkcrack.exe -C secret.zip -c flag.png -p pngheader -o 0
```

​![QQ_1731148698674](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1731148698674-20241109183820-r00vql5.png)​

修改压缩包密码

```python
bkcrack.exe -C secret.zip -k f45dd89f e3e929fb 3202ba17 -U flag.zip easy
```

​![QQ_1731148799110](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1731148799110-20241109184011-zt2pld3.png)​

爆破图片宽高得到前半部分

​![QQ_1731148890263](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1731148890263-20241109184139-7lbufwk.png)​

```python
flag{We_11k
```

合并起来flag

```python
flag{We_11k3_h4ck1ng}
```
