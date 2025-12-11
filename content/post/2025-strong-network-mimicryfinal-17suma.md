---
title: 2025强网拟态-Final
slug: 2025-strong-network-mimicryfinal-17suma
url: /post/2025-strong-network-mimicryfinal-17suma.html
date: '2025-11-27 11:16:36+08:00'
lastmod: '2025-12-10 15:36:31+08:00'
categories:
  - CTF-Writeup
description: 好难，无力了
toc: true
isCJKLanguage: true
---



# 2025强网拟态-Final

# Misc

@脉冲星，友好合作

## 标准的绝密压缩

首先分析流量，发现关键的PNG图片相关的流量，全部在tcp流的data部分，先使用tshark导出

```bash
tshark -r input.pcap -Y "tcp.payload" -T fields -e tcp.payload
```

然后根据之前发现的长度重建恢复压缩包

```python
#!/usr/bin/env python3
import sys, os
from binascii import unhexlify

SIG_PNG = '89504e470d0a1a0a'
IEND = '49454e44'

def read_from_data_txt(path):
    parts = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if len(s) == 20 and all(c in '0123456789abcdefABCDEF' for c in s):
                b = bytes.fromhex(s)
                try:
                    parts.append(b.decode('ascii'))
                except:
                    parts.append(''.join(chr(x) for x in b))
    return ''.join(parts)

def read_from_decoded_txt(path):
    parts = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if len(s) >= 2 and all(c in '0123456789abcdefABCDEF' for c in s):
                parts.append(s)
    return ''.join(parts)

def recover_pngs(hex_str, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    pos = 0
    n = 0
    L = len(hex_str)
    while True:
        idx = hex_str.find(SIG_PNG, pos)
        if idx == -1:
            break
        i = idx + len(SIG_PNG)
        while True:
            if i + 16 > L:
                break
            length = int(hex_str[i:i+8], 16)
            i += 8
            type_hex = hex_str[i:i+8]
            i += 8
            data_hex_len = length * 2
            if i + data_hex_len + 8 > L:
                break
            i += data_hex_len
            crc_hex = hex_str[i:i+8]
            i += 8
            if type_hex.lower() == IEND:
                break
        seg_hex = hex_str[idx:i]
        if seg_hex.startswith(SIG_PNG) and IEND in seg_hex:
            n += 1
            p = os.path.join(out_dir, f'png_{n:03d}.png')
            with open(p, 'wb') as f:
                f.write(unhexlify(seg_hex))
            paths.append(p)
        pos = i
    return paths

def main():
    args = sys.argv[1:]
    if not args:
        inp = './decoded.txt'
        out_dir = './recovered'
        mode = 'decoded'
    else:
        inp = args[0]
        out_dir = args[1] if len(args) > 1 else 'recovered'
        mode = args[2] if len(args) > 2 else 'decoded'
    if mode == 'data':
        hex_str = read_from_data_txt(inp)
    else:
        hex_str = read_from_decoded_txt(inp)
    paths = recover_pngs(hex_str, out_dir)
    print(len(paths))

if __name__ == '__main__':
    main()
```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251127112219-5uuiq74.png)

恢复后发现在IDAT块内有问题

```python
#!/usr/bin/env python3
import os, re
from binascii import unhexlify

SRC = '/Users/joker/Code/2025QWNT_final/data_from_hex.txt'
OUT_DIR = '/Users/joker/Code/2025QWNT_final/data_from_hex/recovered'
SIG_PNG = '89504e470d0a1a0a'
IEND = '49454e44'

hex_tokens = []
pat = re.compile(r'[0-9a-fA-F]+')
with open(SRC, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        for m in pat.finditer(line):
            s = m.group(0)
            if len(s) % 2 == 0:
                hex_tokens.append(s)

hex_str = ''.join(hex_tokens).lower()

os.makedirs(OUT_DIR, exist_ok=True)
paths = []
pos = 0
n = 0
L = len(hex_str)
while True:
    idx = hex_str.find(SIG_PNG, pos)
    if idx == -1:
        break
    i = idx + len(SIG_PNG)
    while True:
        if i + 16 > L:
            break
        length = int(hex_str[i:i+8], 16)
        i += 8
        type_hex = hex_str[i:i+8]
        i += 8
        data_hex_len = length * 2
        if i + data_hex_len + 8 > L:
            break
        i += data_hex_len
        crc_hex = hex_str[i:i+8]
        i += 8
        if type_hex.lower() == IEND:
            break
    seg_hex = hex_str[idx:i]
    if seg_hex.startswith(SIG_PNG) and IEND in seg_hex:
        n += 1
        p = os.path.join(OUT_DIR, f'png_{n:03d}.png')
        with open(p, 'wb') as f2:
            f2.write(unhexlify(seg_hex))
        paths.append(p)
    pos = i

print(len(paths))
```

```python
png_001.png: Connection established. Hey, you online? It s been a while since we last talked.
png_002.png: Yeah, I m here. Busy as always. Feels like the days are getting shorter.
png_003.png: Tell me about it. I barely have time to sleep lately. Between maintenance logs and incident reports, I m drowning.
png_004.png: Sounds rough. I ve been buried in audits myself. Every time I finish one, another pops up.
png_005.png: Classic. Sometimes I wonder if the machines are easier to deal with than the people.
png_006.png: No kidding. At least machines don t ask pointless questions.
png_007.png: True. Anyway, before I forget how s that side project you were working on? The one you wouldn t shut up about months ago.
png_008.png: Still alive barely. Progress is slow, but steady. You know me I don t give up easily.
png_009.png: Good. I hope it pays off one day.
png_010.png: Thanks. Alright I m guessing you didn t ping me just to chat?
png_011.png: Well, half of it was. It s been a while. But yes I do have something for you today. Before sending the core cipher, I ll transmit an encrypted archive first. It contains a sample text and the decryption rules.
png_012.png: Okay. What s special about this sample text?
png_013.png: And inside the sample text, I used my favorite Herobrine legend you know the one I always bring up.
png_014.png: Of course I know. The hidden original text from that weird old site, right?
png_015.png: What can I say old habits die hard. Anyway, the important part: the sample packet and the core cipher are encrypted with the same password.
png_016.png: Got it. So if I can decrypt the sample, the real one should be straightforward.
png_017.png: Exactly. Send the sample when ready.
png_018.png: I m ready. Go ahead.
png_019.png: UEsDBBQAAQAIABtFeFu1Ii0dcwAAAHwAAAAJAAAAcnVsZXMudHh07XuRBFDbojGKhAz59VaKEpwD6/rKaZnqUxf+NMH0rybWrAMPewZ/yGyLrMKQjNIcEbPAxjmP5oTh8fP77Vi1wnFwzN37BmrQ9SCkC27FC/xeqbgw/HWcDpgzsEoiNpqT9ZThrbAScyg5syfJmNactjelNVBLAwQUAAEACACGOXhbpdvG1ysBAAAVAgAACgAAAHNhbXBsZS50eHTA1fy4cMLZwZkTI1mEk88yOXy9rmbTbCNBQOo9hqKQPK6vjZVo9aCtTVflmkKYGV99+51qXbinmG7WGik5UvLJk9MKRosThBCDMHrmjibOCzjzNELwEgEyX8DjqJkSc8pIFwj+oRM3bb4i0GtRxbwqgsxCtgwiKdCVoXVdetN7RKLIQ7DD+Huv/ZptNdd0yRNHis9LEA3loB+IHZ+dK7IknqPh4lYF8JwAjx5/wwp0YAM6Bcec7uAvk6B5t1pEztm1rLl8TjniVz5/bBUTo1LjUXnar/pnm1NvE9EAuxz/s6b+O8/ew7/A4ItdNJGzDudh6YULfiV3pCTXFIbR4GCe4LwkohWZIlAjysA+zLRrgkTDoB10vWdNGdfoBAlLRoUdZ95mS7X5/bXV41BLAQI/ABQAAQAIABtFeFu1Ii0dcwAAAHwAAAAJACQAAAAAAAAAIAAAAAAAAABydWxlcy50eHQKACAAAAAAAAEAGABIv3f82lzcAQAAAAAAAAAAAAAAAAAAAABQSwECPwAUAAEACACGOXhbpdvG1ysBAAAVAgAACgAkAAAAAAAAACAAAACaAAAAc2FtcGxlLnR4dAoAIAAAAAAAAQAYAFP0sZjOXNwBAAAAAAAAAAAAAAAAAAAAAFBLBQYAAAAAAgACALcAAADtAQAAAAA=
png_020.png: got it. Decrypting yeah, it works.
png_021.png: Good. That means the channel is stable.
png_022.png: Alright. Whenever you re ready, send the real thing.
png_023.png: The core cipher will be transmitted through our secret channel. You remember how to decrypt it, right?
png_024.png: Of course. I ve got the procedure ready. Start when you re ready.
png_025.png: Done. Core cipher fully received. Integrity verified no corruption.
png_026.png: Same to you. And hey nice talking again.
png_027.png: Agreed. Take care.
png_028.png: Good. Keep things quiet for the next few days.
png_029.png: Yeah. Let s not wait so long next time.
png_030.png: You too.
```

下面是去查找原文在哪里

```bash
It has been reported that some victims of torture, during the act, would retreat into a fantasy world from which they could not WAKE UP. In this catatonic state, the victim lived in a world just like their normal one, except they weren't being tortured. The only way that they realized they needed to WAKE UP was a note they found in their fantasy world. It would tell them about their condition, and tell them to WAKE UP. Even then, it would often take months until they were ready to discard their fantasy world and PLEASE WAKE UP.
```

开始明文攻击

```bash
bkcrack.exe -C download.zip -c sample.txt -P sample.zip -p sample.txt
```

爆破出来了

```bash
C:\Users\admin\Desktop\2025强网拟态\bkcrack-1.8.1-win64\bkcrack-1.8.1-win64>bkcrack.exe -C download.zip -c sample.txt -P sample.zip -p sample.txt
bkcrack 1.8.1 - 2025-10-25
[21:43:00] Z reduction using 280 bytes of known plaintext
100.0 % (280 / 280)
[21:43:00] Attack on 28505 Z values at index 6
Keys: b47e923c 5aeb49a7 a3cd7af0
65.2 % (18580 / 28505)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 18580
[21:43:09] Keys
b47e923c 5aeb49a7 a3cd7af0
```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251127214331-wpjk8bm.png)

先将压缩包内的文本拿出来

```bash
bkcrack.exe -C download.zip -k b47e923c 5aeb49a7 a3cd7af0 -U unlocked.zip 123
```

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251127215237-6m1bghg.png)

得到rules.txt

```python
1.you need to calc the md5 of port to decrypt the core data.
2.The cipher I put in the zip, in segments, has been deflated.
```

然后发现需要重建，因为未知端口，所以尝试爆破

```python
from scapy.all import rdpcap, TCP, IP
import pandas as pd
from typing import Dict, List, Tuple
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os

def calculate_md5(num: int) -> bytes:
    """计算整数的MD5，返回字节格式作为AES密钥"""
    num_str = str(num)
    md5_hash = hashlib.md5(num_str.encode('utf-8')).hexdigest()
    # 对于AES-256，我们需要32字节密钥，所以用MD5重复填充到32字节
    key = (md5_hash * 2)[:32].encode('utf-8')  # 重复MD5并取前32字符
    return key

def aes_ecb_decrypt(ciphertext_hex: str, key: bytes) -> bytes:
    """使用AES-256-ECB解密数据"""
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
##        if ciphertext.startswith(b"8950"):
##            return f"[AES解密错误: {str(e)}]".encode()
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        # 尝试去除PKCS7填充
        try:
            decrypted = unpad(decrypted, AES.block_size)
        except ValueError:
            # 如果没有填充或者填充不正确，保持原样
            pass
        return decrypted
    except Exception as e:
        return f"[AES解密错误: {str(e)}]".encode()

def extract_tcp_communication(pcap_file: str, ip1: str, ip2: str) -> List[Tuple[str, str, bytes]]:
    """
    从PCAP文件中提取两个IP的TCP通讯数据，按通讯方向和端口号分组
    
    参数:
        pcap_file: PCAP/PCAPNG文件路径
        ip1: 第一个目标IP
        ip2: 第二个目标IP
    返回:
        包含(方向端口、十六进制数据、解密数据)的元组列表
    """
    # 读取PCAP文件
    print(f"正在读取文件: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"共读取到 {len(packets)} 个数据包")

    # 存储筛选后的TCP数据
    tcp_data: List[Dict] = []

    # 遍历所有数据包，筛选目标IP的TCP通讯
    for pkt in packets:
        # 只保留IP+TCP层的数据包
        if IP in pkt and TCP in pkt:
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            
            # 筛选条件：通讯双方必须是 ip1 和 ip2（双向都包含）
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            if not ((src_ip == ip1 and dst_ip == ip2) or (src_ip == ip2 and dst_ip == ip1)):
                continue

            # 提取TCP关键信息
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
            
            # 只处理有负载的数据包
            if len(payload) > 0:
                data = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "timestamp": pkt.time,
                    "seq_num": tcp_layer.seq,
                    "payload": payload,
                    "payload_len": len(payload)
                }
                tcp_data.append(data)

    if not tcp_data:
        print("未找到目标IP之间的TCP通讯数据")
        return []

    # 转换为DataFrame，方便分组处理
    df = pd.DataFrame(tcp_data)
    print(f"筛选出 {len(df)} 个目标TCP数据包")

    # 定义通讯方向和端口分组
    df["方向端口"] = df.apply(
        lambda x: f"{x['src_ip']}:{x['src_port']}→{x['dst_ip']}:{x['dst_port']}", 
        axis=1
    )

    # 按通讯方向和端口分组，合并同组的TCP数据
    def merge_tcp_direction(group: pd.DataFrame) -> Tuple[str, str, bytes, int]:
        """合并同一通讯方向和端口的TCP数据包"""
        direction = group["方向端口"].iloc[0]
        src_port = group["src_port"].iloc[0]
        
        # 按序列号排序，确保数据顺序正确
        sorted_group = group.sort_values("seq_num")
        # 合并所有负载数据
        merged_payload = b"".join(sorted_group["payload"].tolist())
        
        # 转换为十六进制字符串
        hex_data = merged_payload.hex()
        # 使用源端口的MD5作为AES密钥进行解密
        aes_key = calculate_md5(src_port)
        
        if bytes.fromhex(hex_data).startswith(b"8950"):
            decrypted_data = ""
        else:
            decrypted_data = aes_ecb_decrypt(hex_data, aes_key)
        
        # 获取数据包数量
        packet_count = len(group)
        
        return direction, hex_data, decrypted_data, packet_count, src_port

    # 按方向和端口分组合并
    results = []
    successful_decrypts = 0
    failed_decrypts = 0
    
    for direction_port, group in df.groupby("方向端口"):
        result = merge_tcp_direction(group)
        direction, hex_data, decrypted_data, packet_count, src_port = result
        
        # 统计解密结果
        if isinstance(decrypted_data, bytes) and decrypted_data:
            successful_decrypts += 1
            status = "成功"
        else:
            failed_decrypts += 1
            status = "失败"
        
        print(f"方向: {direction_port}, 数据包: {packet_count}个, 解密: {status}")
        
        results.append((direction_port, hex_data, decrypted_data, src_port))

    print(f"\n解密统计: 成功 {successful_decrypts} 个, 失败 {failed_decrypts} 个")
    
    return results

def save_all_decrypted_data(results: List[Tuple[str, str, bytes, int]], output_dir: str = "output"):
    """将每个流量的解密数据单独保存为ZIP文件"""
    
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    saved_files = []
    
    for i, (direction_port, hex_data, decrypted_data, src_port) in enumerate(results, 1):
        if isinstance(decrypted_data, bytes) and decrypted_data:
            # 简洁的文件名：只使用索引
            filename = f"flow_{i:03d}.zip"
            filepath = os.path.join(output_dir, filename)
            
            # 保存为ZIP文件
            with open(filepath, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"保存文件: {filename}, 源端口: {src_port}, 长度: {len(decrypted_data)} 字节")
            saved_files.append((filename, len(decrypted_data), src_port, direction_port))
    
    print(f"\n所有解密数据已保存到目录: {output_dir}")
    print(f"总共保存了 {len(saved_files)} 个ZIP文件")
    
    # 显示保存的文件统计
    if saved_files:
        print("\n=== 保存的文件列表 ===")
        total_size = 0
        for filename, size, src_port, direction in saved_files:
            print(f"  {filename} - 端口: {src_port} - {size} 字节")
            print(f"    方向: {direction}")
            total_size += size
        print(f"总数据大小: {total_size} 字节")
    
    return saved_files


if __name__ == "__main__":
    # 配置参数
    PCAP_FILE = "capture.pcapng"  # 你的PCAPNG文件路径
    TARGET_IP1 = "192.168.0.234"  # 目标IP1
    TARGET_IP2 = "120.232.61.180"  # 目标IP2
    OUTPUT_FILE = "all_decrypted_data.bin"  # 输出文件路径

    # 检查依赖
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("错误: 需要安装pycryptodome库")
        print("请运行: pip install pycryptodome")
        exit(1)

    # 执行提取和AES解密
    print("开始提取TCP通讯并进行AES-256-ECB解密...")
    results = extract_tcp_communication(PCAP_FILE, TARGET_IP1, TARGET_IP2)

    if results:
        # 分析解密数据
##        analyze_decrypted_data(results)
        
        # 保存所有解密数据到文件
##        os.makedirs("output_zip_files", exist_ok=True)
        saved_files = save_all_decrypted_data(results, "output_zip_files")
        
        print(f"\n=== 完成 ===")
        print(f"总共处理了 {len(results)} 个通讯流")
        print(f"最终输出文件: {OUTPUT_FILE}")
    else:
        print("未找到任何TCP通讯数据")

```

爆破完后得到恢复的压缩包

批量做CRC

```bash
解密完成！总共解密了 319 字节
解密数据十六进制: 53290000cbae0200cb2c000053310400d3320400d3320200d3320000d332060033d5020033b20400d332010033340600334d0400334f0300d3320000d332020033d3020033d0020033360500d33200003331040033d602004bb6000033360500b34806004bb504004b350300b3300500b348030033340300333307003335060033330600334f01004b350400333105004b3100004bb60000333104004b4e05004bb504004b4d03004b3107004b4e03003332000033b000004b310400334e050033350500334c01004b310500b33001004b320300b34c06004b4c050033b50000b33405004b3607004b490300333105004b330600334a03004b4903004b320500334c010033480600334801003332070033b600003332000033320600b3b40000b33403004b3106004b350300d3520100d32f0000cbae0200cb2c0000530100
```

这一串数据得到

```bash
$pkzip$1*1*2*0*35*29*4135a7f*0*26*0*35*0413*c8358ce9e6858f166753637de145d0c841cee9efd7cf2008d13e551dd584b69cae5895c7df45f32fdfb51d0c0d273820239896d3e6*$/pkzip$
```

使用之前明文攻击得到的密钥恢复

```python
import binascii

cipher_hex = "c8358ce9e6858f166753637de145d0c841cee9efd7cf2008d13e551dd584b69cae5895c7df45f32fdfb51d0c0d273820239896d3e6"
data = bytearray.fromhex(cipher_hex)

key0 = 0xb47e923c
key1 = 0x5aeb49a7
key2 = 0xa3cd7af0

crctab = []
for i in range(256):
    r = i
    for _ in range(8):
        if r & 1:
            r = (r >> 1) ^ 0xEDB88320
        else:
            r >>= 1
    crctab.append(r)

def update_keys(ch):
    global key0, key1, key2
    key0 = crctab[(key0 ^ ch) & 0xff] ^ (key0 >> 8)
    key1 = (key1 + (key0 & 0xff)) & 0xffffffff
    key1 = (key1 * 134775813 + 1) & 0xffffffff
    key2 = crctab[(key2 ^ (key1 >> 24)) & 0xff] ^ (key2 >> 8)

def decrypt_byte():
    temp = (key2 | 3) & 0xffff
    return ((temp * (temp ^ 1)) >> 8) & 0xff

plain = bytearray()
for c in data:
    k = decrypt_byte()
    p = c ^ k
    plain.append(p)
    update_keys(p)

print("解密明文（hex）:")
print(plain.hex())

print("\n解密明文:")
print(''.join(chr(b) if 32 <= b <= 126 else '.' for b in plain))

```
