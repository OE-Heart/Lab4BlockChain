import numpy as np
import platform
import time

def preprocess(message):
    msg_list = list(message)
    msgLen = len(msg_list)*8
    
    result = bytes(message, "ascii")
    result += b"\x80"

    if len(msg_list)%64 < 56:
        suffix = b"\x00" * (55-len(msg_list)%64)
    else:
        suffix = b"\x00" * (64+55-len(msg_list)%64)
    result += suffix
    
    result += msgLen.to_bytes(8, "big")
    return result

# 32个字节右移n位
def R(x, n):
    return (x >> n)

# 32个字节循环右移n位
def S(x, n):
    return ((x >> n) | (x << (32-n))) & (2**32-1)

# 逻辑函数的定义
def Ch(x, y ,z):
    return ((x & y) ^ (~x & z))

def Maj(x, y ,z):
    return ((x & y) ^ (x & z) ^ (y & z))

def Sigma0(x):
    return (S(x, 2) ^ S(x, 13) ^ S(x, 22))

def Sigma1(x):
    return (S(x, 6) ^ S(x, 11) ^ S(x, 25))

def sigma0(x):
    return (S(x, 7) ^ S(x, 18) ^ R(x, 3))

def sigma1(x):
    return (S(x, 17) ^ S(x, 19) ^ R(x, 10))

def compress(Kj, Wj, a, b, c, d, e, f, g, h):
    
    T1 = h + Sigma1(e) + Ch(e, f ,g) + Kj + Wj
    T2 = Sigma0(a) + Maj(a, b , c)
    h = g
    g = f
    f = e
    e = (d + T1) & (2**32-1)
    d = c
    c = b
    b = a
    a = (T1 + T2 ) & (2**32-1)
    return a, b, c, d, e, f, g, h

def SHA256(message):
    # 初始哈希值
    H = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
    # 计算过程当中用到的常数
    K = np.array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
                  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
                  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
                  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
                  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
                  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
                  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
                  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
                  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2])

    message = preprocess(message)

    for i in range(0, len(message), 64):
        S = message[i: i + 64]
        W = [int.from_bytes(S[e: e + 4], "big") for e in range(0, 64, 4)] + ([0] * 48)

        for j in range(16, 64):
            W[j] = (sigma1(W[j-2]) + W[j-7] + sigma0(W[j-15]) + W[j-16]) & ((2**32)-1)
        
        a, b, c, d, e, f, g, h = H

        for j in range(64):
            a, b, c, d, e, f, g, h = compress(K[j], W[j], a, b, c, d, e, f, g, h)

    H = [d.to_bytes(4, "big") for d in [int((x + y) & (2**32-1)) for x, y in zip(H, (a, b, c, d, e, f, g, h))]]

    return "".join(format(h, "02x") for h in b"".join(H))

if __name__ == '__main__':
    s = ""
    zero_cnt = 30
    zero_vec = [0]*zero_cnt
    zero_str = "".join([str(zero_vec[i]) for i in range(zero_cnt)])

    i = 8500000000
    time_start = time.perf_counter()
    while (True):
        result = SHA256(s+str(i))
        bin_str = "".join(['{:04b}'.format(int(result[i], 16)).replace("0b", "") for i in range(len(result))])
        if (i % 10000 == 0):
            time_now = time.perf_counter()

            print("i = "+str(i)+ " :", time_now-time_start, 's')
        if (bin_str[0:zero_cnt] == zero_str):
            time_now = time.perf_counter()
            print(s+str(i))
            print(result)
            print("Time used: ", time_now-time_start, 's')
            break
        else:
            i += 1