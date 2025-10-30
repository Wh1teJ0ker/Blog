---
title: 2025羊城杯
slug: 2025yang-cheng-bei-14spwm
url: /post/2025yang-cheng-bei-14spwm.html
date: '2025-10-11 13:20:43+08:00'
lastmod: '2025-10-30 13:53:18+08:00'
description: 原题+AI一把嗦
toc: true
isCJKLanguage: true
---



# 2025羊城杯

# Misc

## 别笑，你试你也过不了第二关

第一关要求

```json
编写代码使字符串 hilogo 的内容为以下图案：

#####  #####   ###   #      #      ##### ##### ##### #####   ###   #      #      #####
#        #    #   #  #      #      #   # #     #       #    #   #  #      #      #   #
#        #    #####  #      #      #   # #     #       #    #####  #      #      #   #
#        #    #   #  #      #      #   # #     #       #    #   #  #      #      #   #
#####  #####  #   #  #####  #####  ##### ##### ##### #####  #   #  #####  #####  #####
```

使用替换的方法，比较容易

```python
s='ebecccafafeaeaeaecccafafe|ahadacabafafacaaaeagadacabafafaca|ahadebafafacaaaeagadebafafaca|ahadacabafafacaaaeagadacabafafaca|ebebacabebebeaeaeaebacabebebe';r='';i=j=0;t='# '
while j<len(s):
 c=s[j];r=r+('\n'if c=='|'else t[i%2]*(ord(c)&15));i=0 if c=='|'else i+1;j=j+1
hilogo=r
```

第二关要求

```python
请编写 code 以输出前0x114514个数的序数词后缀:
def get_ordinal(n):
	if 10 <= n % 100 <= 20:
		suffix = 'th'
	else:
		suffix = ['st', 'nd', 'rd', 'th', 'th', 'th', 'th', 'th', 'th', 'th'][n % 10 - 1]
		return suffix
		
            test_passed = True
            user_function = eval(f"lambda n: {code}", {}, {})
    
for i in range(1, 0x114514):
    if user_function(i) != get_ordinal(i):
        test_passed = False
```

这里开始使用基础的切片方法，始终过不去

最后在cofegolf上找到了结果

```python
'tsnrhtdd'[n%5*(n%100^15>4>n%10)::4]
```

## 帅的被人砍

只补全解密后部分，如何得到第二行密钥还需要补充

图片文件名 `hide.jpg` 提示可能有隐写，稍作尝试后使用 steghide 提取出 `key.txt`：

```bash
PZNCKSLLLNWUMILYTNQSXCIDUNBHBDFV
```

怀疑其是加密使用的密钥，尝试代入解密器源码中编译运行：

```c
int main() {
    unsigned char key[32] = {
        'P', 'Z', 'N', 'C', 'K', 'S', 'L', 'L', 'L', 'N', 'W', 'U', 'M', 'I', 'L', 'Y', 'T', 'N', 'Q', 'S', 'X', 'C', 'I', 'D', 'U', 'N', 'B', 'H', 'B', 'D', 'F', 'V'
    };
//需要将其换成获得的key 
    decrypt_file("动态KEY生成器.lock", "动态KEY生成器.re", key);
    system("chmod +x 动态KEY生成器.re");
    return 0;
}
```

运行后输出 `.re` 文件，经验证是合法的 Linux ELF 程序。对其进行逆向分析，是取运行时的系统时间，处理后与硬编码数据逐位异或输出。主函数反编译代码：

```cpp
  v15 = __readfsqword(0x28u);
  v10 = time(0LL);
  snprintf(s, 0x40uLL, "%lld", v10 * (__int64)v10);
  v11 = strlen(s);
  if ( v11 > 15 )
  {
    v3 = &s[v11 - 16];
    v4 = *((_QWORD *)v3 + 1);
    v12 = *(_QWORD *)v3;
    v13 = v4;
  }
  else
  {
    memset(&v12, 48, 16 - v11);
    memcpy((char *)&v12 + 16 - v11, s, v11);
  }
  for ( i = 0; i <= 3; ++i )
  {
    v5 = &s[16 * i + 64];
    v6 = v13;
    *(_QWORD *)v5 = v12;
    *((_QWORD *)v5 + 1) = v6;
  }
  printf("KEY>>  ");
  for ( j = 0; j <= 63; ++j )
    putchar(s[j + 64] ^ byte_B60[j]);
  puts(&::s);
  return 0LL;
```

​`byte_B60` 是已知的，但时间我们不知道。考虑到前面从 flag 生成器中得到的未知字符串，可能是加密后数据，于是结合 key 生成逻辑，用脚本进行反推：

```python
from binascii import unhexlify

mask_hex="5E5544425C07040D0751010B42010E000558004B4641454C464A52545F5B5D01767660756D7D4A575C495309070704555E404146405953480201090E0250054B00"

M=bytearray(unhexlify(mask_hex)); M=M[:64]
cipher=b"oeqqh2550i12v3964h5xrtttqrbmkij7"
cands=[]

for start in (0,16,32):

    ms=M[start:start+32]
    Q=bytes([c ^ m for c,m in zip(cipher, ms)])
    a, b = Q[:16], Q[16:]

    ok_digits = all(48 <= x <= 57 for x in a)
    if len(ms)==32 and a==b and ok_digits:
        cands.append((start, a.decode()))

print("candidates:", cands)
# candidates: [(0, '1053451878094276')]
```

得到 `1053451878094276` 这一个数字，为异或过程用到的 key，解密：

```python
from binascii import unhexlify

S=b'1053451878094276'
P=S*4

mask_hex='5E5544425C07040D0751010B42010E000558004B4641454C464A52545F5B5D01767660756D7D4A575C495309070704555E404146405953480201090E0250054B00'

M=bytearray(unhexlify(mask_hex))[:64]
O=bytes([p^m for p,m in zip(P,M)])

print('full64:',O.decode('latin1'))
print('first32:',O[:32].decode('latin1'))
print('last32:',O[32:].decode('latin1'))
# full64: oeqqh2550i12v3964h5xrtttqrbmkij7GFUFYH{okqc0353coptutlbp59976b2}
# first32: oeqqh2550i12v3964h5xrtttqrbmkij7
# last32: GFUFYH{okqc0353coptutlbp59976b2}
```

得到的 `full64` 即为经 flag 生成器处理前的原内容，输入后得到 Flag：

![471e20b58165a03fab4259cfbe4338ca](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic471e20b58165a03fab4259cfbe4338ca-20251012005758-3rur1sm.png)

## polar

‍

```python
def construction(N, K, eps):
    infoIndex = np.array([4, 5, 6, 7], dtype=int)
    frozenIndex = np.array([0, 1, 2, 3], dtype=int)
    return infoIndex, frozenIndex, np.arange(N, dtype=int)

]
def encode(u, N):
    x = np.zeros(N, dtype=int)
    x[0] = u[4]; x[1] = u[4]
    x[2] = u[5]; x[3] = u[5]
    x[4] = u[6]; x[5] = u[6]
    x[6] = u[7]; x[7] = u[7]
    return x

def decode(y, frozenIndex):
    N = len(y)
    uh = np.zeros(N, dtype=int)

    def decide(p, q):
        a = y[p]; b = y[q]
        if a is None and b is None:
            return np.random.randint(0, 2)  
        if a is None:
            return b
        if b is None:
            return a
        return 1 if (a + b) >= 1 else 0

    uh[4] = decide(0, 1)
    uh[5] = decide(2, 3)
    uh[6] = decide(4, 5)
    uh[7] = decide(6, 7)

    for i in frozenIndex:
        uh[i] = 0
    return uh
```

# DS&AI

# Mini-modelscope

发现使用tensflow，合理猜想思路应该是通过写入，让模型在导入的时候实现命令执行

根据题目描述，推理时，模型的签名 serve 会返回指定文件（这里是 /flag）的内容

```python
import tensorflow as tf
import os
import shutil
import zipfile

EXPORT_DIR = "mdoel"
ZIP_NAME = "model.zip"
FLAG_PATH = "/flag"

if os.path.exists(EXPORT_DIR):
    shutil.rmtree(EXPORT_DIR)
if os.path.exists(ZIP_NAME):
    os.remove(ZIP_NAME)

@tf.function(input_signature=[tf.TensorSpec(shape=[None, 1], dtype=tf.float32)])
def serve_fn(x):
    data = tf.io.read_file(FLAG_PATH)
    batch_dim = tf.shape(x)[0]
    data_vec = tf.repeat(tf.expand_dims(data, 0), repeats=batch_dim)
    return {"prediction": data_vec}

class ModelWrapper(tf.Module):
    @tf.function(input_signature=[tf.TensorSpec(shape=[None, 1], dtype=tf.float32)])
    def __call__(self, inputs):
        return serve_fn(inputs)

model_instance = ModelWrapper()
tf.saved_model.save(model_instance, EXPORT_DIR, signatures={"serve": serve_fn})

with zipfile.ZipFile(ZIP_NAME, "w", zipfile.ZIP_DEFLATED) as zf:
    for root, _, files in os.walk(EXPORT_DIR):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, EXPORT_DIR)
            zf.write(full_path, rel_path)

```

## dataIdSort

```python
import re, csv
from pathlib import Path
from datetime import datetime
from collections import Counter

# ---------------- 工具函数 ----------------
def is_valid_date_yyyymmdd(s: str) -> bool:
    try:
        datetime.strptime(s, "%Y%m%d")
        return True
    except Exception:
        return False


def id_checksum_char(id17: str) -> str:
    w = [7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2]
    tab = ['1','0','X','9','8','7','6','5','4','3','2']
    return tab[sum(int(a)*b for a,b in zip(id17, w)) % 11]


def valid_id(raw: str) -> bool:
    core = re.sub(r'[-\s]', '', raw).upper()
    if not re.fullmatch(r'\d{17}[0-9X]', core):
        return False
    if core[:6] == '000000':
        return False
    try:
        prov = int(core[:2])
        if not (11 <= prov <= 65):
            return False
    except:
        return False
    if core[14:17] == '000':
        return False
    b = core[6:14]
    try:
        bd = datetime.strptime(b, "%Y%m%d")
        if bd.year < 1900 or bd > datetime.now():
            return False
    except:
        return False
    return core[-1] == id_checksum_char(core[:17])


def luhn_ok(num: str) -> bool:
    num = re.sub(r'[\s-]', '', num)
    if not (16 <= len(num) <= 19 and num.isdigit()):
        return False
    ds = [int(x) for x in num[::-1]]
    s = 0
    for i, d in enumerate(ds):
        if i % 2:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        s += d
    return s % 10 == 0


def valid_ip(ip: str) -> bool:
    ip = ip.replace("．", ".").replace("。", ".")
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        for p in parts:
            if not (0 <= int(p) <= 255):
                return False
            if len(p) > 1 and p.startswith('0'):
                return False
        return True
    except Exception:
        return False


# ---------------- 常量集合 ----------------
PHONE_PREFIX3 = {
    '130','131','132','133','134','135','136','137','138','139',
    '140','145','146','149','150','151','152','153','155','156',
    '166','167','171','172','173','174','175','176','177','178',
    '180','181','182','183','184','185','186','187','188','189',
    '190','191','193','195','196','198','199','147','148'
}
prefix_alt = "(?:" + "|".join(sorted(PHONE_PREFIX3)) + ")"


# ---------------- 正则模式 ----------------
PATTERNS = {
    "idcard": re.compile(r'(?<!\d)(?:\d{17}[0-9Xx]|\d{6}[-\s]+\d{8}[-\s]+\d{3}[0-9Xx])(?!\d)'),
    "phone":  re.compile(rf'''
        (?<!\d)
        (?:\+86\s*|\(\+86\)\s*)?
        ({prefix_alt})
        (?:
            \d{{8}}                           # 连续 11 位（已含前三位）
          | [-\s]\d{{4}}[-\s]\d{{4}}          # 严格 3-4-4：恰好两处分隔
        )
        (?!\d)
    ''', re.VERBOSE),
    "bankcard": re.compile(
        r'(?<!\d)(?:'
        r'(?:[1-9]\d{15,18})'
        r')(?!\d)'
        ),
    "ip": re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)'),
    "mac": re.compile(r'[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}')
}


# ---------------- 核心识别函数 ----------------
def detect_sensitive_data(text: str):
    out, seen = [], set()

    def push(cat, val, pos):
        if (cat, val) not in seen:
            seen.add((cat, val))
            out.append((pos, cat, val.strip()))

    for m in PATTERNS["idcard"].finditer(text):
        s = m.group(0)
        if valid_id(s): push("idcard", s, m.start())

    for m in PATTERNS["phone"].finditer(text):
        s = m.group(0)
        digits = re.sub(r"\D", "", s)
        if digits.startswith("86") and len(digits) > 11:
            digits = digits[2:]
        if len(digits) == 11 and digits[:3] in PHONE_PREFIX3:
            mid = digits[3:7]
            if not re.match(r"(19|20)\d{2}", mid):
                push("phone", s.strip(), m.start())

    for m in PATTERNS["bankcard"].finditer(text):
        s = m.group(0)
        if luhn_ok(s):
            if not re.match(r'\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])', s):
                push("bankcard", s, m.start())

    for m in PATTERNS["ip"].finditer(text):
        s = m.group(0)
        if valid_ip(s): push("ip", s, m.start())

    for m in PATTERNS["mac"].finditer(text):
        s = m.group(0).lower()
        if all(re.fullmatch(r"[0-9A-Fa-f]{2}", seg) for seg in s.split(":")):
            push("mac", s.lower(), m.start())

    # ✳️ 改动关键处：分类排序（不按出现顺序，而按类别块排序）
    category_order = ["idcard", "phone", "bankcard", "ip", "mac"]
    out.sort(key=lambda x: (category_order.index(x[1]), x[0]))

    return out


# ---------------- 输出 ----------------
def write_to_csv(out_data, output_path: Path):
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "value"])
        for _, cat, val in out_data:
            writer.writerow([cat, val])


# ---------------- 主程序 ----------------
def main():
    DATA_PATH = Path("data.txt")
    OUT_PATH  = Path("result_plus_grouped.csv")

    text = DATA_PATH.read_text(encoding="utf-8", errors="ignore")
    results = detect_sensitive_data(text)
    write_to_csv(results, OUT_PATH)

    cnt = Counter(c for _, c, _ in results)
    print(f"✅ 输出文件: {OUT_PATH}")
    print("📊 统计:", dict(cnt))


if __name__ == "__main__":
    main()

```
