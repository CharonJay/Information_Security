import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter.messagebox as messagebox
import re


class S_DES:
    def __init__(self):
        # 初始化明文P与密钥K
        self.P = "10101010"
        self.K = "0101010101"

        # 标准设定
        self.group_length = 8
        self.key_length = 10

        # 转换装置设定
        # 密钥扩展装置
        self.p_10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        self.p_8 = [6, 3, 7, 4, 8, 5, 10, 9]
        self.left_shift_1 = [2, 3, 4, 5, 1]
        self.left_shift_2 = [3, 4, 5, 1, 2]
        # 初始置换盒
        self.IP = [2, 6, 3, 1, 4, 8, 5, 7]
        # 最终置换盒
        self.inv_IP = [4, 1, 3, 5, 7, 2, 8, 6]
        # 轮函数
        self.EP_Box = [4, 1, 2, 3, 2, 3, 4, 1]
        self.S_Box = [[[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]],
                      [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]]
        self.SP_Box = [2, 4, 3, 1]

    # 设置明文P与密钥K
    def set_P(self, P):
        self.P = P

    def set_K(self, K):
        self.K = K

    # 转换机制
    # 置换
    def permute(self, text, P_box):
        cipher_text = ''.join(text[i - 1] for i in P_box)
        return cipher_text

    # 替换
    def replace(self, text, S_Box):
        row_1 = int(text[0] + text[3], 2)
        col_1 = int(text[1] + text[2], 2)
        row_2 = int(text[4] + text[7], 2)
        col_2 = int(text[5] + text[6], 2)
        cipher_text = bin(S_Box[0][row_1][col_1])[2:].zfill(2) + bin(S_Box[1][row_2][col_2])[2:].zfill(2)
        return cipher_text

    # 异或
    def xor(self, text_1, text_2):
        cipher_text = ''.join(str(int(i) ^ int(j)) for i, j in zip(text_1, text_2))
        return cipher_text

    # 移位
    def shift(self, text, Left_shift_i):
        cipher_text = ''.join(text[i - 1] for i in Left_shift_i)
        return cipher_text

    # 拓展置换
    def expand_permute(self, text, EP_Box):
        cipher_text = ''.join(text[i - 1] for i in EP_Box)
        return cipher_text

    # 生成子密钥
    def get_sub_key(self, K, P_box_10, P_box_8):
        temp_key = self.permute(K, P_box_10)
        k = []
        temp_key = self.shift(temp_key[:5], self.left_shift_1) + self.shift(temp_key[5:], self.left_shift_1)
        k.append(self.permute(temp_key, P_box_8))
        temp_key = self.shift(temp_key[:5], self.left_shift_2) + self.shift(temp_key[5:], self.left_shift_2)
        k.append(self.permute(temp_key, P_box_8))
        k1, k2 = k[0], k[1]
        return k1, k2

    # 加密
    def encode(self, P, K):
        P = self.permute(P, self.IP)  # 初始置换
        k1, k2 = self.get_sub_key(K, self.p_10, self.p_8)  # 密钥生成
        # 第一轮
        left_text, right_text = P[:4], P[4:]  # 分割
        expanded_right = self.expand_permute(right_text, self.EP_Box)  # 扩展置换
        temp = self.xor(expanded_right, k1)  # 加轮密钥
        temp = self.replace(temp, self.S_Box)  # 替换盒替换
        temp = self.permute(temp, self.SP_Box)  # 直接替换
        # SW
        new_right = self.xor(left_text, temp)  # 异或
        new_left = right_text
        # 第二轮
        expanded_right = self.expand_permute(new_right, self.EP_Box)
        temp = self.xor(expanded_right, k2)
        temp = self.replace(temp, self.S_Box)
        temp = self.permute(temp, self.SP_Box)
        # 输出
        final_left = self.xor(new_left, temp)
        final_right = new_right
        ciper_text = final_left + final_right
        ciper_text = self.permute(ciper_text, self.inv_IP)
        return ciper_text

    # 解密
    def decode(self, ciper_text, K):
        C = self.permute(ciper_text, self.IP)  # 初始置换
        k1, k2 = self.get_sub_key(K, self.p_10, self.p_8)  # 密钥生成
        # 第一轮
        left_text, right_text = C[:4], C[4:]
        expanded_right = self.expand_permute(right_text, self.EP_Box)
        temp = self.xor(expanded_right, k2)
        temp = self.replace(temp, self.S_Box)
        temp = self.permute(temp, self.SP_Box)
        # SW
        new_right = self.xor(left_text, temp)
        new_left = right_text
        # 第二轮
        expanded_right = self.expand_permute(new_right, self.EP_Box)
        temp = self.xor(expanded_right, k1)
        temp = self.replace(temp, self.S_Box)
        temp = self.permute(temp, self.SP_Box)
        final_left = self.xor(new_left, temp)
        final_right = new_right
        P = final_left + final_right
        P = self.permute(P, self.inv_IP)
        return P

    # 暴力破解
    def hack(self, plaintext, ciphertext):
        # 重置密钥
        self.set_K("0000000000")
        # 密钥空间
        fre = 2 ** len(self.K)
        key_group = []
        for i in range(fre):
            C = self.encode(plaintext, self.K)
            P = self.decode(ciphertext, self.K)
            # 判断
            if P == plaintext and C == ciphertext:
                key_group.append(self.K)
            # 将二进制字符串转换为整数
            K_int = int(self.K, 2)
            K_int += 1
            # 将结果转换回二进制字符串并保持固定长度
            self.set_K(format(K_int, '010b'))
        return key_group


# 将ASCII字符转换成二进制
def ASCII_trans_binary(A_str):
    binary = ''
    for c in A_str:
        c_int = ord(c)
        c_binary = format(c_int, '08b')
        binary = ' '.join([binary, c_binary])
    return binary


# 将二进制转换成ASCII字符
def binary_trans_ASCII(binary):
    binary_bytes = binary.split()
    A_characters = [chr(int(x, 2)) for x in binary_bytes]
    A_str = ''.join(A_characters)
    return A_str


class S_DES_window(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=(20, 10))
        self.pack(fill=BOTH, expand=YES)
        # 输入框
        self.plain_text = ttk.StringVar(value="")
        self.cipher_text = ttk.StringVar(value="")
        self.key = ttk.StringVar(value="")
        # 文本信息
        hdr_txt = "请输入明文与密钥获取密文，或输入密文与密钥获取明文"
        hdr = ttk.Label(master=self, text=hdr_txt, width=100)
        hdr.pack(fill=X, pady=10)
        # 组合文本
        self.create_form_entry("明文", self.plain_text)
        self.create_form_entry("密文", self.cipher_text)
        self.create_form_entry("密钥", self.key)
        result_txt = " "
        self.result_label = ttk.Label(master=self, text=result_txt, width=100)
        self.result_label.pack(fill=X, pady=10)
        self.create_buttonbox()

    # 创建组合容器
    def create_form_entry(self, label, variable):
        container = ttk.Frame(self)
        container.pack(fill=X, expand=YES, pady=5)
        lbl = ttk.Label(master=container, text=label.title(), width=10)
        lbl.pack(side=LEFT, padx=5)
        ent = ttk.Entry(master=container, textvariable=variable)
        ent.pack(side=LEFT, padx=5, fill=X, expand=YES)

    # 创建按钮
    def create_buttonbox(self):
        """Create the application buttonbox"""
        container = ttk.Frame(self)
        container.pack(fill=X, expand=YES, pady=(15, 10))
        sub_btn = ttk.Button(master=container, text="加密", command=self.act_encode, bootstyle=SUCCESS, width=6)
        sub_btn.pack(side=RIGHT, padx=5)
        sub_btn.focus_set()
        cnl_btn = ttk.Button(master=container, text="解密", command=self.act_decode, bootstyle=DANGER, width=6)
        cnl_btn.pack(side=RIGHT, padx=5)

    def act_encode(self):
        try:
            plain_str = self.plain_text.get()
            key_str = self.key.get()
            if plain_str == "" and key_str == "":  # 当明文或密钥未输入时扔出异常
                raise Exception('明文或密钥未输入')
            if bool(re.match('^[01]*$', plain_str)) and len(plain_str) == 8:  # 如果输入是八位二进制字符串, 则直接进行加密操作
                ciper_text_str = coder.encode(plain_str, key_str)
                self.result_label['text'] = f"加密结果: {ciper_text_str},已复制在密文框中"  # 将结果显示在GUI界面上
                self.cipher_text.set(ciper_text_str)  # 将结果复制在密文框中
            else:  # 如果输入不是，则先进行Unicode转码
                P_binary = ASCII_trans_binary(plain_str)
                P_binary_list = P_binary.split()
                ciper_text_binary = ""
                for P in P_binary_list:
                    ciper_text_binary = ' '.join([ciper_text_binary, coder.encode(P, key_str)])
                ciper_text_str = binary_trans_ASCII(ciper_text_binary)
                self.result_label['text'] = f"加密结果: {ciper_text_str},已复制在密文框中"  # 将结果显示在GUI界面上
                self.cipher_text.set(ciper_text_str)  # 将结果复制在密文框中
        except:
            messagebox.showerror(title="错误", message="请检查明密文和密钥是否正确输入!")

    def act_decode(self):
        try:
            cipher_str = self.cipher_text.get()
            key_str = self.key.get()
            if cipher_str == "" and key_str == "":  # 当密文或密钥未输入时扔出异常
                raise Exception('密文或密钥未输入')
            if bool(re.match('^[01]*$', cipher_str)) and len(cipher_str) == 8:  # 如果输入是八位二进制字符串, 则直接进行解密操作
                plain_text_str = coder.decode(cipher_str, key_str)
                self.result_label['text'] = f"解密结果: {plain_text_str},已复制在明文框中"  # 将结果显示在GUI界面上
                self.plain_text.set(plain_text_str)  # 将结果复制在明文框中
            else:  # 如果输入不是，则先进行Unicode转码
                C_binary = ASCII_trans_binary(cipher_str)
                C_binary_list = C_binary.split()
                plain_text_binary = ""
                for C in C_binary_list:
                    plain_text_binary = ' '.join([plain_text_binary, coder.decode(C, key_str)])
                plain_text_str = binary_trans_ASCII(plain_text_binary)
                self.result_label['text'] = f"解密结果: {plain_text_str},已复制在明文框中"  # 将结果显示在GUI界面上
                self.plain_text.set(plain_text_str)  # 将结果复制在明文框中
        except:
            messagebox.showerror(title="错误", message="请检查明密文和密钥是否正确输入!")


if __name__ == "__main__":
    coder = S_DES()
    app = ttk.Window("S-DES加解密器", "superhero", resizable=(False, False))
    S_DES_window(app)
    app.mainloop()
