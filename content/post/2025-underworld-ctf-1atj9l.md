---
title: 2025阴间CTF
slug: 2025-underworld-ctf-1atj9l
url: /post/2025-underworld-ctf-1atj9l.html
date: '2025-04-05 00:16:03+08:00'
lastmod: '2025-04-06 17:30:32+08:00'
toc: true
categories:
  - CTF-Writeup
isCJKLanguage: true
---

# 2025阴间CTF

# Misc

## 阴曹地府税务总局

大概思路就是基于做连接请求的时间戳前后大段时间进行爆破，验证成功率在一定比例以上就按照此时间戳去预测后续的股票波动率，获得flag

```shell
from pwn import *
from random import Random
import time

context.log_level = 'info'
logfile = open("record.log", "w", encoding="utf-8")

# ------------------- 基础功能 -------------------
def recv_and_record(io, delimiter, timeout=5):
    """接收服务器数据并同步记录到本地日志文件"""
    data = io.recvuntil(delimiter, timeout=timeout)  # 注意这里要调用 io.recvuntil，而不是自己！
    try:
        decoded = data.decode("utf-8", errors="ignore")
    except:
        decoded = str(data)
    logfile.write(decoded)
    logfile.flush()
    return decoded



def connect_to_server():
    """连接服务器"""
    return remote("nc1.ctfplus.cn", 29850)

def extract_tax_rates(raw_data):
    """提取历史税率"""
    lines = raw_data.splitlines()
    rates = []
    for line in lines:
        if "交易税率" in line and ":" in line:
            rate = int(line.split(":")[1].strip().replace("%", ""))
            rates.append(rate)
    return rates

def predict_seed_and_rates(history_rates, timestamp, time_window=120, skip_min=1, skip_max=20, tolerance=20):
    """爆破种子并预测未来税率"""
    best_score = 0
    best_result = None

    for ts in range(timestamp - time_window, timestamp + time_window + 1):
        for skip in range(skip_min, skip_max + 1):
            r = Random()
            r.seed(ts)
            for _ in range(skip):
                r.randint(0, 100)

            predicted = [r.randint(0, 100) for _ in range(10)]
            score = sum(abs(real - pred) <= tolerance for real, pred in zip(history_rates, predicted))

            if score > best_score:
                best_score = score
                best_result = (ts, skip, predicted)

    return best_result if best_result and best_score >= 6 else None

def should_burn(predicted_rate):
    """判断是否烧纸"""
    return predicted_rate <= 50  # 小于等于50才烧纸

def read_balance(io):
    """
    从服务器响应提取当前冥币余额，兼容各种情况。
    """
    try:
        resp = recv_and_record(io, ['要进行烧纸交易吗？(y/n):', '当前冥币:', '当前冥币余额:'], timeout=5)

    except EOFError:
        log.error("连接断开了，无法读取冥币余额！")
        return 0.0

    log.debug(f"收到服务器回应：{resp}")

    lines = resp.splitlines()
    balance = None

    # 遍历所有行，找可能的冥币余额
    for line in lines:
        if "当前冥币余额" in line or "当前冥币" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                num_part = parts[1].strip()
                # 确保后面跟着数字
                if num_part:
                    try:
                        balance = float(num_part.split()[0])
                        break
                    except ValueError:
                        log.warning(f"冥币余额提取异常，内容：{num_part}")
  
    if balance is None:
        log.warning(f"找到了冥币字段但未提取到数字，默认返回0，原始内容：{resp}")
        return 0.0
    else:
        return balance




def burn_paper(io, predicted_rate, round_num):
    """执行烧纸操作，并返回真实税率"""
    io.sendline('y')
    recv_and_record(io, '当前税率是(0-99%):')
    io.sendline(str(predicted_rate))

    resp = io.recvline().decode(errors='ignore')
    if "当前税率为" in resp:
        real_rate = int(resp.split(":")[1].strip().replace("%", ""))
        diff = abs(real_rate - predicted_rate)
        log.success(f"[第{round_num}轮] 烧纸！预测 {predicted_rate}% / 真实 {real_rate}% / 误差 {diff}%")
        return real_rate, diff
    else:
        log.warning(f"[第{round_num}轮] 未拿到真实税率！")
        return None, None

# ------------------- 主逻辑 -------------------

def attack():
    """执行完整攻击流程"""
    now = int(time.time())
    io = connect_to_server()

    # 第一次选n拿历史税率
    io.sendlineafter('(y/n):', 'n')
    data = recv_and_record(io,"税率参考数据已经给您了。")
    rates = extract_tax_rates(data)
    log.info(f"提取到历史税率：{rates}")

    # 预测种子
    result = predict_seed_and_rates(rates, now)
    if not result:
        log.error("种子爆破失败，退出")
        io.close()
        return

    seed, skip, predicted_list = result
    log.success(f"预测成功：种子={seed}，跳过轮数={skip}")
    log.info(f"预测未来税率（前10轮）：{predicted_list}")

    # 初始化新的伪随机器
    r = Random()
    r.seed(seed)
    for _ in range(skip + 10):
        r.randint(0, 100)

    coins = 0
    round_num = 1

    while coins < 10000:
        try:
            recv_and_record(io, '要进行烧纸交易吗？(y/n):')
        except EOFError:
            io.interactive()
            log.warning("服务器关闭了连接，正常退出！")
            break
        predicted_rate = r.randint(0, 100)

        if should_burn(predicted_rate):
            real_rate, diff = burn_paper(io, predicted_rate, round_num)

            if real_rate is not None and diff > 20:
                log.warning(f"[第{round_num}轮] 预测偏差过大 (预测 {predicted_rate}%，真实 {real_rate}%)，但继续执行！")
        else:
            io.sendline('n')
            log.info(f"[第{round_num}轮] 预测税率 {predicted_rate}% ，跳过。")

        # 更新冥币余额
        coins = read_balance(io)
        if coins is None:
            log.error("余额读取失败。")
            break
        else:
            log.info(f"当前冥币余额：{coins}")

        round_num += 1
        if round_num > 100:
            log.warning("回合过多，自动退出保护。")
            break

    if coins and coins >= 10000:
        log.success(f"冥币余额达到 {coins}，准备拿 FLAG！")
        io.interactive()

    io.close()
    logfile.close()


if __name__ == "__main__":
    attack()

```

​![QQ_1743783416158](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/QQ_1743783416158-20250405001657-9okbvy4.png)​

拼尽全力没有对的上web的脑洞，唉，太阴了
