---
title: 2024巅峰极客-Misc
date: '2024-08-18 15:26:41'
updated: '2024-08-18 15:41:56'
permalink: /post/2024-peak-geekmisc-1o9v4u.html
comments: true
toc: true
---

# 2024巅峰极客-Misc

方案1：

部分说直接运行样本就会存在释放文件的操作，我这边尝试未果

方案2：

upx脱壳

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818154139.png)​

然后foremost分离出来得到一张图片

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818154141.png)​

LSB隐写

​![](https://birkenwald.feishu.cn/space/api/box/stream/download/asynccode/?code=MGJlMDEwOTk1ZGE4MDUzODc3ZjYyMGIzZmM2MzU3MjRfR2xKZTVhV0sxUW96b3B6YXNOYWZnbjUyeHlPMmZ2Z3BfVG9rZW46QWRBZGJOd2Vkb3dyWDB4MEg1QWNLbTFJbjRiXzE3MjM5NjYyODg6MTcyMzk2OTg4OF9WNA)​

http://47.104.129.38/79407f2309b5763fbd0e33dc583c4262/default.a

下载样本

注意观察原始样本中存在大量yyttddd，这个就是密钥

异或出来即得样本

​![](https://birkenwald.feishu.cn/space/api/box/stream/download/asynccode/?code=ODQxNzQ3ZTRlOWU2YjExNWZhZWI1MzQyMzQ0NmJkNjZfNm1ncjQ2NDk1Wm1mYjVXN2VpN1FMU1ZpQm9hSUdEVjlfVG9rZW46RHdrYmJEcER4b3NBdEt4UzF1T2NxUURCbnkzXzE3MjM5NjYyODg6MTcyMzk2OTg4OF9WNA)​

然后利用下面脚本进行提取的

https://github.com/CaledoniaProject/pupyrat-config-decoder

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818154142.png)​

但是在安装好相对应的库后，发现如上报错

再询问以及查询源码后得知，其中存在一个反编译行为

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818154143.png)​

但是实际上在tmp这个变量的时候就已经得到相关的结果了

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818154144.png)​

注释后打印结果即可

​![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/20240818154146.png)​

```JavaScript
{'launcher_args': ['--host', '60.177.118.44:3432', '-t', 'ssl']
```

最终flag为

```python
flag{b57758d5acc923137eef453239ba685b}
```

‍
