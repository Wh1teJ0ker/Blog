---
title: 2025HITCTF
slug: 2025hitctf-zrsb8p
url: /post/2025hitctf-zrsb8p.html
date: '2025-12-06 14:06:53+08:00'
lastmod: '2025-12-09 22:48:20+08:00'
categories:
  - CTF-Writeup
description: 24H的鏖战，🥹最后被超了
toc: true
isCJKLanguage: true
---



# 2025HITCTF

# Misc

## 5-Layer-Fog

1. 打开 `flag_cert.pem`，这是一个 X.509 证书，subject/issuer 里写着：  
    ​`algorithms: Xor+Base64, Rot13, BasE64, CaEsAr(3), SwApCaSe`​
2. 用库（如 `cryptography`）解析证书，发现有一个自定义扩展 OID `1.2.3.4.5.6.7.8.1`，内容是一串 Base64：  
    ​`uMkIvhvNuWSdaWu5tXW0qNAotWoeaXyCvMT5egIvqjqbSqEEy3ylSW4wUhgASqo3unywvrEmUhcYSNu4tnv5rrAlvZEhwqALtjAIUg==`​
3. 对这串密文按提示做“逆操作”：

    - 先 `swapcase`（大小写互换）
    - 再 Caesar -3（还原 CaEsAr(3)）
    - 再 `rot13`​
    - 然后 Base64 解码
    - 得到一段二进制数据，对它做单字节 XOR 爆破，key \= `0x40`（即字符 `'@'`）时得到新的 Base64 串：  
      ​`SElUQ1RGMjAyNXtCYXNFNjRfWG9yKEApK0Jhc2U2NF9Td0FwQ2FTZV9Sb3QxM19DYUVzQXIoMyl9`​
    - 最后再 Base64 解码，即为上面的 flag。

gpt秒了

```bash
https://chatgpt.com/share/6933cf1b-d090-800f-969a-6d83684b747d
```

## Regex Beast

‍

```python

import re
import sys

# Increase recursion limit just in case
sys.setrecursionlimit(2000000)

def solve():
    print("Reading file...")
    try:
        with open('/Users/joker/Code/2025HITCTF/enc.txt', 'r') as f:
            content = f.read().strip()
    except FileNotFoundError:
        print("File not found.")
        return

    if content.startswith('/'):
        content = content[1:]
    
    # Simple check for trailing characters
    # The file ends with ...)) so we might want to trim until the last )
    # But usually strip() is enough if there are no flags
    
    print("Extracting blocks...")
    block_map = {}
    reverse_map = {}
    next_id = 0
    
    def replace_callback(match):
        nonlocal next_id
        b = match.group(0)
        if b not in block_map:
            block_map[b] = next_id
            reverse_map[next_id] = b
            next_id += 1
        return f'B{block_map[b]} ' 
        
    content_sub = re.sub(r'(?:\\x[0-9a-f]{2})+', replace_callback, content)
    
    print(f"Unique blocks: {len(block_map)}")
    
    # Tokenize
    # Add spaces around special chars to split easily
    tokens_str = content_sub.replace('(?:', ' ( ').replace('(?=', ' [ ').replace(')', ' ) ').replace('|', ' | ')
    tokens = tokens_str.split()
    
    print(f"Total tokens: {len(tokens)}")
    
    stack = []
    # Root frame
    # A frame represents the current Group or Lookahead being parsed.
    # alts: list of Alternatives.
    # Alternative: list of Terms.
    # Term: (SetOfPaths, is_lookahead)
    stack.append({ 'type': 'ROOT', 'alts': [ [] ] })
    
    def make_block_set(bid):
        return { (bid,) }
        
    def union_sets(sets):
        res = set()
        for s in sets:
            res.update(s)
        return res
        
    def concat_sets(list_of_sets):
        if not list_of_sets:
            return {()} 
        
        # If any set is empty, result is empty (invalid path)
        for s in list_of_sets:
            if not s:
                return set()
                
        res = list_of_sets[0]
        for i in range(1, len(list_of_sets)):
            next_s = list_of_sets[i]
            new_res = set()
            # If sets are large, this cross product is expensive.
            # But we expect singletons.
            if len(res) > 100 or len(next_s) > 100:
                 print(f"Warning: Large sets in concat: {len(res)} * {len(next_s)}")
                 
            for p1 in res:
                for p2 in next_s:
                    new_res.add(p1 + p2)
            res = new_res
            if not res: break
        return res

    def intersect_sets(s1, s2):
        return s1.intersection(s2)

    for i, tok in enumerate(tokens):
        if i % 50000 == 0:
            print(f"Processing token {i}/{len(tokens)} stack depth {len(stack)}")
            
        if tok == '(':
            stack.append({ 'type': 'GROUP', 'alts': [ [] ] })
        elif tok == '[': # Lookahead
            stack.append({ 'type': 'LOOKAHEAD', 'alts': [ [] ] })
        elif tok == '|':
            stack[-1]['alts'].append([])
        elif tok == ')':
            frame = stack.pop()
            
            # Evaluate alternatives
            alt_results = []
            for alt in frame['alts']:
                # alt is list of (Set, is_lookahead)
                # Concatenate them
                # If we have [ (A, True), (B, False) ] -> A \cap B
                # If we have [ (A, False), (B, True) ] -> A + B (and B is asserted)
                
                # Wait, my logic in the loop below handles the merge of (Lookahead, Next).
                # So `alt` here already contains merged terms?
                # No, `alt` contains the terms accumulated in this frame.
                # But inside the loop (elif tok == 'B' or tok == ')') we merge into parent.
                # Here we are processing the CLOSED frame.
                # We need to evaluate the content OF THE FRAME.
                
                # Inside the frame, we also had terms.
                # The terms inside the frame were already merged?
                # No. `stack[-1]` refers to the frame we are building.
                # When we are IN the frame, we append terms to IT.
                # So `frame['alts']` contains the terms.
                
                # We need to process the terms in the alternative.
                # The logic `if current_alt and current_alt[-1][1]: merge` 
                # was applied when ADDING to the frame.
                # So `alt` list is already "Lookaheads merged into following consumers".
                # EXCEPT for trailing lookaheads.
                
                sets_to_concat = [x[0] for x in alt]
                val = concat_sets(sets_to_concat)
                alt_results.append(val)
            
            frame_res = union_sets(alt_results)
            
            is_lookahead = (frame['type'] == 'LOOKAHEAD')
            
            if not stack:
                # Should not happen if balanced
                break
                
            parent = stack[-1]
            current_alt = parent['alts'][-1]
            
            # Merge into parent
            if is_lookahead:
                current_alt.append( (frame_res, True) )
            else:
                if current_alt and current_alt[-1][1]:
                    prev_set, _ = current_alt.pop()
                    inter = intersect_sets(prev_set, frame_res)
                    current_alt.append( (inter, False) )
                else:
                    current_alt.append( (frame_res, False) )
                    
        elif tok.startswith('B'):
            bid = int(tok[1:])
            s = make_block_set(bid)
            
            parent = stack[-1]
            current_alt = parent['alts'][-1]
            
            if current_alt and current_alt[-1][1]:
                 prev_set, _ = current_alt.pop()
                 inter = intersect_sets(prev_set, s)
                 current_alt.append( (inter, False) )
            else:
                 current_alt.append( (s, False) )
                 
    # Final result
    root_frame = stack[0]
    final_sets = []
    for alt in root_frame['alts']:
        sets_to_concat = [x[0] for x in alt]
        final_sets.append(concat_sets(sets_to_concat))
        
    final_res = union_sets(final_sets)
    
    print(f"Found {len(final_res)} valid paths.")
    
    if len(final_res) > 0:
        path = list(final_res)[0]
        decoded = b''
        for bid in path:
            hex_str = reverse_map[bid]
            parts = hex_str.split(r'\x')
            for p in parts:
                if p:
                    decoded += bytes.fromhex(p)
                    
        with open('decoded_flag.txt', 'wb') as f:
            f.write(decoded)
        print("Decoded flag written to decoded_flag.txt")
        # Check if it's a zip or text
        # print head
        print("First 100 bytes:", decoded[:100])

if __name__ == '__main__':
    solve()

```

```python
import re

def analyze():
    with open('/Users/joker/Code/2025HITCTF/enc.txt', 'r') as f:
        content = f.read()

    # Find all hex blocks
    # A block seems to be a sequence of \xNN
    # Let's assume they are reasonably long to avoid matching short things if any
    # The snippet shows long blocks.
    
    # We'll regex replace them.
    block_pattern = re.compile(r'(?:\\x[0-9a-f]{2})+')
    
    unique_blocks = {}
    next_id = 0
    
    def replace_func(match):
        nonlocal next_id
        block = match.group(0)
        if block not in unique_blocks:
            unique_blocks[block] = next_id
            next_id += 1
        return f'BLOCK_{unique_blocks[block]}'

    simplified = block_pattern.sub(replace_func, content)
    
    print(f"Found {len(unique_blocks)} unique blocks.")
    print("Simplified structure (first 500 chars):")
    print(simplified[:500])
    
    # Let's also print the simplified structure around the middle to see if it changes
    print("Simplified structure (middle):")
    mid = len(simplified) // 2
    print(simplified[mid:mid+500])

if __name__ == '__main__':
    analyze()

```

然后扫码即可

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251206150727-vm7zyp5.png)

trae秒了

## Berkeley

使用elf freebsd的文件头，进行明文攻击

```bash
echo -n "7f454c4602010109000000000000000004003e00010000000000000000000000" | xxd -r -ps > freebsd_header1
```

这里的文件头是查询了Berkeley联想到freebsd系统，因此部分字节需要一致

```bash
bkcrack.exe -C strong_encrypted.zip -c veracrypt.core -p freebsd_header1 -o 0
```

![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnetwork-asset-asynccode-20251209221116-z3c5b95.png)

提取出来了1和core文件

```bash
bkcrack -C strong_encrypted.zip -c veracrypt.core -k 25b0091d 6687a00d 791e474d -d veracrypt.core
bkcrack -C strong_encrypted.zip -c veracrypt.core -k 25b0091d 6687a00d 791e474d -d 1
```

在core文件内查找到密码

```bash
strings veracrypt.core | grep -i "password"
```

![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnetwork-asset-asynccode-20251209221117-ulfdiyo.png)

然后看到这个SecurePassword12

然后挂载

![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnetwork-asset-asynccode-20251209221117-3bmttxl.png)

使用rstudio就可以扫描恢复文件，在.snap下找到2，点进去就是flag

![](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picnetwork-asset-asynccode-20251209221117-0m53ddg.png)

```bash
flag{Fr33BSD_part1t10n_taB1e_Is_StraNg3}
```

## VanYouSee

🤡修了一个晚上

```bash
https://pan.baidu.com/s/1Tzad98GtbeuLs5RS0V_wuw?pwd=avev
```

# Crypto

## Scan4fLaG

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251209221319-c54z0c2.png)

扫码得

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251209221519-rcj9twr.png)

PS：被密码手猜出来的，郁郁了🤡

分离压缩包，用上面的密码解密

![image](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Picimage-20251209221616-ss3ggts.png)

# Reverse

## EasyVm

七道re，我们一个re手不堪重任，帮忙做了一题easy的，AI太好用了

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
逆向自 Calendar.dll 中的自定义 VM，恢复 FLAG 的脚本。

思路简述：
1. 把 .rdata 里的字节码抄出来（0x14001DA90 那一段）。
2. 按照 sub_140001270 的逻辑写一个 Python 版 VM 解释器。
3. 根据逆向分析得到的等式（全是 + / - / ^ / == 这种），在 Python 里
   把各个字符算出来，组装出 flag，并用 VM 真实跑一遍校验。
"""

# ----------------------------
# 1. 还原出来的 VM 字节码
# ----------------------------
CODE = bytes([
    0x0D,0x3C,0x01,0x06,0x0A,0x01,0x02,0x6F,0x01,0x00,0x57,0x01,0x05,0x21,0x01,0x03,
    0x6E,0x01,0x01,0x72,0x01,0x04,0x67,0x01,0x07,0x00,0x11,0x00,0x01,0x04,0x65,0x01,
    0x05,0x63,0x01,0x09,0x00,0x01,0x01,0x6F,0x01,0x03,0x72,0x01,0x07,0x21,0x01,0x02,
    0x72,0x01,0x08,0x0A,0x01,0x00,0x43,0x01,0x06,0x74,0x11,0x00,0x10,0x02,0x00,0x00,
    0x0C,0x00,0x66,0x0E,0x02,0x02,0x00,0x01,0x03,0x01,0x00,0x06,0x01,0x01,0x0C,0x01,
    0x6D,0x0E,0x02,0x02,0x01,0x02,0x02,0x02,0x03,0x02,0x03,0x04,0x03,0x00,0x01,0x09,
    0x00,0x02,0x0C,0x00,0x06,0x0E,0x02,0x03,0x00,0x02,0x09,0x00,0x03,0x0C,0x00,0x1C,
    0x0E,0x02,0x03,0x00,0x01,0x09,0x00,0x03,0x0C,0x00,0x1A,0x0E,0x02,0x02,0x01,0x05,
    0x02,0x02,0x06,0x02,0x03,0x07,0x0C,0x02,0x69,0x0E,0x02,0x03,0x00,0x01,0x09,0x00,
    0x02,0x0C,0x00,0x21,0x0E,0x02,0x03,0x00,0x03,0x09,0x00,0x02,0x0C,0x00,0x3D,0x0E,
    0x02,0x02,0x04,0x08,0x02,0x05,0x09,0x02,0x06,0x0A,0x0B,0x05,0x03,0x0E,0x02,0x03,
    0x00,0x04,0x09,0x00,0x05,0x0C,0x00,0x17,0x0E,0x02,0x03,0x00,0x06,0x09,0x00,0x05,
    0x0C,0x00,0x12,0x0E,0x02,0x02,0x01,0x0B,0x02,0x02,0x0C,0x02,0x03,0x0D,0x02,0x04,
    0x0E,0x02,0x05,0x0F,0x02,0x06,0x10,0x02,0x07,0x11,0x0B,0x02,0x04,0x0E,0x02,0x03,
    0x00,0x01,0x05,0x00,0x00,0x0C,0x00,0xBE,0x0E,0x02,0x09,0x00,0x00,0x0B,0x00,0x07,
    0x0E,0x02,0x05,0x00,0x02,0x0C,0x00,0x32,0x0E,0x02,0x08,0x00,0x02,0x0C,0x00,0x30,
    0x0E,0x02,0x06,0x00,0x05,0x0B,0x00,0x05,0x0E,0x02,0x02,0x00,0x04,0x07,0x06,0x00,
    0x0C,0x06,0x02,0x0E,0x02,0x0D,0x1C,0x00
])

# 操作码到名字，仅用于调试（脚本真正执行不依赖这个）
OPMAP = {
    0: "HALT",
    1: "STORE",
    2: "LDMEM",
    3: "MOV",
    4: "LDI",
    5: "ADD",
    6: "ADD_I",
    7: "SUB",
    8: "SUB_I",
    9: "XOR",
    10: "XOR_I",
    11: "CMP",
    12: "CMP_I",
    13: "JMP",
    14: "JNZ",
    16: "IN",
    17: "OUT",
}

# -------------------------------------------------
# 2. Python 版 VM 解释器：仿 sub_140001270 的核心逻辑
# -------------------------------------------------
def vm_run(flag_bytes: bytes, debug: bool = False) -> bool:
    """
    用 Python 跑一遍 VM 逻辑，判断给定输入是否走到“正确”分支。

    flag_bytes：我们要传给 VM 的“输入字符串”（不含 \n），
                VM 读不到的位置按 0 处理。
    返回值：True 表示通过所有校验，走到了成功分支；False 表示走错分支。
    """
    code = CODE
    regs = [0] * 8           # 8 个通用寄存器 r0..r7，每个 32 bit
    zf = 0                   # 只模拟 Zero Flag（ZF），对应 a1+1064 的最低位
    ip = 0                   # instruction pointer，从 0 开始
    steps = 0

    # 实际 VM 里：输入从 a1+1084 开始，我们这里直接用 flag_bytes 数组代替
    def read_input(idx: int) -> int:
        return flag_bytes[idx] if idx < len(flag_bytes) else 0

    while ip < len(code):
        steps += 1
        if steps > 20000:
            # 理论上不会死循环，这里加个保险
            raise RuntimeError("VM 可能陷入死循环，终止调试")

        op = code[ip]

        if debug:
            print(f"IP={ip:03d} OP={op:02X} {OPMAP.get(op, '?'):<5} regs={regs} ZF={zf}")

        # ------- 无参数指令 -------
        if op == 0:  # HALT
            # 题目里有两个 HALT：
            #  - 错误分支是前面构造 "Wrong..." 后的 HALT（在 ip=27）
            #  - 正确分支在最后构造 "Correct!" 后 HALT（在 ip=279）
            return ip != 27

        elif op == 16:  # IN：真实程序里 fgets 读入，我们在脚本中直接忽略
            ip += 1
            continue

        elif op == 17:  # OUT：真实程序把 a1+1134 的字符串输出，这里也直接跳过
            ip += 1
            continue

        # ------- 单字节参数（跳转） -------
        elif op == 13:  # JMP imm8
            target = code[ip + 1]
            ip = target
            continue

        elif op == 14:  # JNZ imm8 ：如果 ZF == 0 就跳转
            target = code[ip + 1]
            if zf == 0:
                ip = target
            else:
                ip += 2
            continue

        # ------- 双字节参数的算术 / 访存 / mov / cmp -------
        # 下面所有分支都会读两个紧跟的字节作为参数
        # 形式统一： [op, a, b]
        # --------------------------------------------
        if ip + 2 >= len(code):
            # 防御性检查
            raise RuntimeError("字节码非法，读取越界")

        a = code[ip + 1]
        b = code[ip + 2]

        # 说明：原 VM 对寄存器编号 >=8 会返回错误，这个字节码里都在 0..7 范围
        if op == 1:  # STORE；只影响 VM 内部的输出缓冲，对逻辑无影响，这里忽略
            ip += 3
            continue

        elif op == 2:  # LDMEM r, idx   -> 从输入缓冲 flag[idx] 读入寄存器
            r, idx = a, b
            regs[r] = read_input(idx)
            ip += 3
            continue

        elif op == 3:  # MOV rd, rs
            rd, rs = a, b
            regs[rd] = regs[rs]
            ip += 3
            continue

        elif op == 4:  # LDI r, imm8
            r, imm = a, b
            regs[r] = imm
            ip += 3
            continue

        elif op == 5:  # ADD rd, rs
            rd, rs = a, b
            regs[rd] = (regs[rd] + regs[rs]) & 0xFFFFFFFF
            zf = 1 if regs[rd] == 0 else 0
            ip += 3
            continue

        elif op == 6:  # ADD_I r, imm8
            r, imm = a, b
            regs[r] = (regs[r] + imm) & 0xFFFFFFFF
            zf = 1 if regs[r] == 0 else 0
            ip += 3
            continue

        elif op == 7:  # SUB rd, rs
            rd, rs = a, b
            regs[rd] = (regs[rd] - regs[rs]) & 0xFFFFFFFF
            zf = 1 if regs[rd] == 0 else 0
            ip += 3
            continue

        elif op == 8:  # SUB_I r, imm8
            r, imm = a, b
            regs[r] = (regs[r] - imm) & 0xFFFFFFFF
            zf = 1 if regs[r] == 0 else 0
            ip += 3
            continue

        elif op == 9:  # XOR rd, rs
            rd, rs = a, b
            regs[rd] = regs[rd] ^ regs[rs]
            zf = 1 if regs[rd] == 0 else 0
            ip += 3
            continue

        elif op == 10:  # XOR_I r, imm8
            r, imm = a, b
            regs[r] = regs[r] ^ imm
            zf = 1 if regs[r] == 0 else 0
            ip += 3
            continue

        elif op == 11:  # CMP r1, r2  -> 设置 ZF = (r1 - r2 == 0)
            r1, r2 = a, b
            res = (regs[r1] - regs[r2]) & 0xFFFFFFFF
            zf = 1 if res == 0 else 0
            ip += 3
            continue

        elif op == 12:  # CMP_I r, imm8 -> 设置 ZF = (r - imm == 0)
            r, imm = a, b
            res = (regs[r] - imm) & 0xFFFFFFFF
            zf = 1 if res == 0 else 0
            ip += 3
            continue

        else:
            raise RuntimeError(f"未知指令 op={op} @ ip={ip}")

    # 正常不会跑到这里
    return False

# -------------------------------------------------
# 3. 利用逆向出来的方程，在 Python 里还原 FLAG
# -------------------------------------------------
def solve_flag() -> str:
    """
    根据 VM 中的比较与跳转逻辑，恢复所有字符。
    这里只做“数学解方程”，而不是瞎枚举。
    """

    # flag[i] 代表第 i 个字符（0-based）
    flag = [0] * 17  # 实际用到索引 0..16，其中 17 位置在内存中是 0 终止符

    # ---- 0,1: 直接比较 ----
    # LDMEM r0, [0] ; CMP_I r0, 102 ('f')
    flag[0] = ord('f')
    # LDMEM r0, [1] ; MOV r1, r0 ; ADD_I r1, 1 ; CMP_I r1, 109
    # => flag[1] + 1 = 109 -> flag[1] = 108 ('l')
    flag[1] = ord('l')

    # ---- 2,3,4: 三个异或方程 ----
    #  r1 = flag[2]
    #  r2 = flag[3]
    #  r3 = flag[4]
    #  CMP_I (r1 ^ r2), 6
    #  CMP_I (r2 ^ r3), 28
    #  CMP_I (r1 ^ r3), 26
    #
    # 这组方程有很多数值解，但我们知道一般 CTF flag 会是 "flag{...}"
    # 代入 'a','g','{' 可以验证：
    #   ord('a') ^ ord('g') == 6
    #   ord('g') ^ ord('{') == 28
    #   ord('a') ^ ord('{') == 26
    flag[2] = ord('a')
    flag[3] = ord('g')
    flag[4] = ord('{')

    # ---- 5,6,7: 与 'H','i','T' 相关 ----
    # LDMEM r1,[5]; LDMEM r2,[6]; LDMEM r3,[7]
    # CMP_I r2, 105          -> flag[6] == 'i'
    flag[6] = ord('i')
    # MOV r0,r1; XOR r0,r2; CMP_I r0,33  -> flag[5] ^ flag[6] = 33
    #     ord('H') ^ ord('i') == 72 ^ 105 == 33
    flag[5] = ord('H')
    # MOV r0,r3; XOR r0,r2; CMP_I r0,61  -> flag[7] ^ flag[6] = 61 -> flag[7] = 84 'T'
    flag[7] = ord('T')

    # ---- 8,9,10: 与前面的 'T' 组合出来 "CTF" ----
    # LDMEM r4,[8]; LDMEM r5,[9]; LDMEM r6,[10]
    # CMP r5,r3     -> flag[9] == flag[7] == 'T'
    flag[9] = flag[7]                # 'T'
    # MOV r0,r4; XOR r0,r5; CMP_I r0,23 -> flag[8] ^ flag[9] = 23
    # MOV r0,r6; XOR r0,r5; CMP_I r0,18 -> flag[10] ^ flag[9] = 18
    flag[8] = flag[9] ^ 23           # 'C'
    flag[10] = flag[9] ^ 18          # 'F'
    # 验证一下：chr(flag[8]) == 'C', chr(flag[9]) == 'T', chr(flag[10]) == 'F'

    # ---- 11..16: 尾巴部分 ----
    # LDMEM r1,[11] ; r1 = flag[11]
    # CMP_I (r1+r1), 190          -> 2*flag[11] = 190 -> flag[11] = 95 -> '_'
    flag[11] = ord('_')

    # r7 = flag[17], 经过一系列操作后要求 0，说明第 18 个位置是 0 终止符，
    # 而不是我们输入的字符（也就是说输入长度不用到 18）。

    # CMP r2,r4 -> flag[12] == flag[14]
    # 后面：
    #   r0 = flag[12]; CMP_I r0,50 -> flag[12] == '2'
    #   然后 r0 -= 2 == 48 再加 5 == 53 与 flag[15] 比较 -> flag[15] == '5'
    flag[12] = ord('2')
    flag[14] = ord('2')
    flag[15] = ord('5')

    # 最后：
    #   LDMEM r0,[4] -> r0=flag[4]='{'
    #   SUB r6,r0   -> r6 = flag[16] - flag[4]
    #   CMP_I r6,2  -> flag[16] - flag[4] = 2  -> flag[16] = '{' + 2 = '}'
    flag[16] = ord('}')  # 123 + 2 = 125 -> '}'

    # flag[13] 在字节码中仅被 LDMEM 读入，从未参与比较，因此是自由变量。
    # 结合 CTF 年份，“_2 0 2 5” 比较自然，我们就填 '0'。
    flag[13] = ord('0')

    return "".join(chr(c) for c in flag)


def main():
    flag = solve_flag()
    print("Recovered flag:", flag)

    # 用 VM 真机跑一遍校验
    ok = vm_run(flag.encode())
    print("VM check:", "PASS" if ok else "FAIL")

    if not ok:
        raise SystemExit("求出来的 flag 没通过 VM 校验，请检查脚本逻辑。")


if __name__ == "__main__":
    main()

```
