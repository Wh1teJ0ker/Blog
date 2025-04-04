---
title: 2024巅峰极客-Misc
slug: 2024-peak-geekmisc-1xtnfv
url: /post/2024-peak-geekmisc-1xtnfv.html
date: '2024-08-18 15:26:41+08:00'
lastmod: '2025-04-04 17:34:56+08:00'
toc: true
categories:
  - CTF-Writeup
isCJKLanguage: true
---

easy-病毒分析，但是脑洞（
<!--more-->

# 2024巅峰极客-Misc

方案1：

部分说直接运行样本就会存在释放文件的操作，我这边尝试未果

方案2：

upx脱壳

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818154139.png)​

然后foremost分离出来得到一张图片

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818154141.png)​

LSB隐写

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818205032.png)​

http://47.104.129.38/79407f2309b5763fbd0e33dc583c4262/default.a

下载样本

注意观察原始样本中存在大量yyttddd，这个就是密钥

异或出来即得样本

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818205006.png)​

然后利用下面脚本进行提取的

https://github.com/CaledoniaProject/pupyrat-config-decoder

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818154142.png)​

但是在安装好相对应的库后，发现如上报错

再询问以及查询源码后得知，其中存在一个反编译行为

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818154143.png)​

但是实际上在tmp这个变量的时候就已经得到相关的结果了

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818154144.png)​

注释后打印结果即可

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/network-asset-20240818154146-20241001025744-380andk.png)​

```JavaScript
{'launcher_args': ['--host', '60.177.118.44:3432', '-t', 'ssl']
```

最终flag为

```python
flag{b57758d5acc923137eef453239ba685b}
```

‍
