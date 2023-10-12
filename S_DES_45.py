from S_DES_123 import S_DES
import time
import random

a = "11010101"


def hack(P, C):
    time_start = time.time()
    print(f"P={P} | C={C}")
    print(f"\t开始暴力破解,时间为{time_start}")
    key_group = coder.hack(P, C)
    time_end = time.time()
    print(f"\t结束暴力破解,时间为{time_end}")
    print(f"\t共发现{len(key_group)}个密钥 : {key_group}")
    print(f"\t共用时: {(time_end - time_start):.4f}s")
    return key_group


# 生成随机明文字符串
def get_rand_P(seed):
    P = ""
    for i in range(8):
        random.seed(seed+i)
        c = random.randint(0, 1)
        P = "".join((P, str(c)))
    return P


# 生成随机密钥字符串
def get_rand_K(seed):
    K = ""
    for i in range(10):
        random.seed(seed+i)
        c = random.randint(0, 1)
        K = "".join((K, str(c)))
    return K


if __name__ == '__main__':
    coder = S_DES()
    seed = 2023

    # 求解第四关
    print("------------------Level 4------------------")
    P = get_rand_P(seed)
    K = get_rand_K(seed)
    coder.set_K(K)
    coder.set_P(P)
    C = coder.encode(P, K)
    print(f"输入的明文P: {P}")
    print(f"输入的密钥K: {K}")
    print(f"加密后的密文C: {C}")
    print(f"解密后的明文P: {coder.decode(C, K)}")
    hack_K = hack(P, C)

    # 求解第五关
    print("------------------Level 5------------------")
    print(f"明文P: {P} | 密文C: {C}")
    for key in hack_K:
        print(f"使用密钥K= {key} 进行加密后得到得密文C: {coder.encode(P, K)}")
