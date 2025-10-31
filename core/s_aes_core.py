"""
S-AES核心算法实现（优化版）
基于配置文件的模块化实现
"""

from config.algorithm_config import AlgorithmConfig
from config.constants import Constants


class S_AES_Core:
    """S-AES核心算法类"""
    
    def __init__(self):
        """初始化算法核心"""
        self.validate_algorithm_config()
    
    def validate_algorithm_config(self):
        """验证算法配置"""
        AlgorithmConfig.validate_config()
    
    @staticmethod
    def gf_mult(a: int, b: int) -> int:
        """GF(2^4)域上的乘法运算（基于预定义乘法表）"""
        if a < 0 or a > 0xF or b < 0 or b > 0xF:
            raise ValueError("GF乘法输入必须是4位半字节（0-F）")
        
        # 使用预定义的GF乘法表
        GF_MULT_TABLE = [
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [0, 2, 4, 6, 8, 10, 12, 14, 3, 1, 7, 5, 11, 9, 15, 13],
            [0, 3, 6, 5, 12, 15, 10, 9, 11, 8, 13, 14, 7, 4, 1, 2],
            [0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9],
            [0, 5, 10, 15, 7, 2, 13, 8, 14, 11, 4, 1, 9, 12, 3, 6],
            [0, 6, 12, 10, 11, 13, 7, 1, 5, 3, 9, 15, 14, 8, 2, 4],
            [0, 7, 14, 9, 15, 8, 1, 6, 13, 10, 3, 4, 2, 5, 11, 12],
            [0, 8, 3, 11, 6, 14, 5, 13, 12, 4, 15, 7, 10, 2, 9, 1],
            [0, 9, 1, 8, 2, 11, 3, 10, 4, 13, 5, 12, 6, 15, 7, 14],
            [0, 10, 7, 13, 14, 4, 9, 3, 15, 5, 8, 2, 1, 11, 6, 12],
            [0, 11, 5, 14, 10, 1, 15, 4, 7, 12, 2, 9, 13, 6, 8, 3],
            [0, 12, 11, 7, 5, 9, 14, 2, 10, 6, 1, 13, 15, 3, 4, 8],
            [0, 13, 9, 4, 1, 12, 8, 5, 2, 15, 11, 6, 3, 14, 10, 7],
            [0, 14, 15, 1, 13, 3, 2, 11, 9, 7, 6, 8, 4, 10, 12, 5],
            [0, 15, 13, 2, 9, 6, 4, 12, 1, 14, 12, 3, 8, 7, 5, 10]
        ]
        
        return GF_MULT_TABLE[a][b]
    
    @staticmethod
    def rot_nibble(word: int) -> int:
        """8位字的半字节旋转（高4位与低4位交换）"""
        high_nib = (word >> 4) & 0xF  # 高4位
        low_nib = word & 0xF          # 低4位
        return (low_nib << 4) | high_nib
    
    @staticmethod
    def sub_nibble(nibble: int) -> int:
        """单个半字节的S盒替换"""
        return AlgorithmConfig.S_BOX[nibble]
    
    @staticmethod
    def inv_sub_nibble(nibble: int) -> int:
        """单个半字节的逆S盒替换"""
        return AlgorithmConfig.INV_S_BOX[nibble]
    
    def key_expansion(self, key: int) -> list[int]:
        """S-AES密钥扩展：16位密钥→48位（6个8位字）"""
        # 步骤1：拆分初始密钥为w0和w1（各8位）
        w0 = (key >> 8) & 0xFF
        w1 = key & 0xFF
        w = [w0, w1]
        
        # 步骤2：计算w2-w5
        for i in range(2, AlgorithmConfig.KEY_WORDS):
            if i % 2 == 0:  # w2、w4需经过g函数
                # g函数：rot_nibble → sub_nibble → 异或RCON
                prev_word = w[i-1]
                # 1. 半字节旋转
                rotated = self.rot_nibble(prev_word)
                # 2. 半字节替换（高4位和低4位分别替换）
                sub_high = self.sub_nibble((rotated >> 4) & 0xF)
                sub_low = self.sub_nibble(rotated & 0xF)
                subbed = (sub_high << 4) | sub_low
                # 3. 异或RCON（RCON索引为i//2，如w2对应RCON[1]）
                rcon_val = AlgorithmConfig.RCON[i // 2]
                g_val = subbed ^ rcon_val
                # 计算当前w：w[i] = w[i-2] ^ g_val
                current_w = w[i-2] ^ g_val
            else:  # w3、w5直接异或前两个字
                current_w = w[i-2] ^ w[i-1]
            w.append(current_w)
        
        return w
    
    def add_round_key(self, state: list[list[int]], round_key: int) -> list[list[int]]:
        """轮密钥加：状态矩阵与16位轮密钥逐位异或"""
        # 拆分轮密钥为4个半字节（按列排列：k00 k10 k01 k11）
        k00 = (round_key >> 12) & 0xF  # 第0列高4位
        k10 = (round_key >> 8) & 0xF   # 第0列低4位
        k01 = (round_key >> 4) & 0xF   # 第1列高4位
        k11 = round_key & 0xF          # 第1列低4位
        
        # 逐半字节异或
        state[0][0] ^= k00
        state[1][0] ^= k10
        state[0][1] ^= k01
        state[1][1] ^= k11
        
        return state
    
    def sub_bytes(self, state: list[list[int]]) -> list[list[int]]:
        """半字节代替：对状态矩阵中每个半字节应用S盒"""
        for i in range(AlgorithmConfig.STATE_MATRIX_ROWS):
            for j in range(AlgorithmConfig.STATE_MATRIX_COLS):
                state[i][j] = self.sub_nibble(state[i][j])
        return state
    
    def inv_sub_bytes(self, state: list[list[int]]) -> list[list[int]]:
        """逆半字节代替：对状态矩阵中每个半字节应用逆S盒"""
        for i in range(AlgorithmConfig.STATE_MATRIX_ROWS):
            for j in range(AlgorithmConfig.STATE_MATRIX_COLS):
                state[i][j] = self.inv_sub_nibble(state[i][j])
        return state
    
    @staticmethod
    def shift_rows(state: list[list[int]]) -> list[list[int]]:
        """行移位：第二行半字节循环左移1位（第一行不变）"""
        # 第二行交换s10和s11
        state[1][0], state[1][1] = state[1][1], state[1][0]
        return state
    
    # 逆行移位与行移位相同（循环左移1位的逆操作仍是自身）
    inv_shift_rows = shift_rows
    
    def mix_columns(self, state: list[list[int]]) -> list[list[int]]:
        """列混淆：对每列应用矩阵乘法 [[1,4],[4,1]]（GF(2⁴)域）"""
        for col in range(AlgorithmConfig.STATE_MATRIX_COLS):
            # 保存当前列的原始值（避免覆盖）
            s0 = state[0][col]
            s1 = state[1][col]
            
            # 应用混淆公式：
            # s0' = 1*s0 ⊕ 4*s1
            # s1' = 4*s0 ⊕ 1*s1
            state[0][col] = self.gf_mult(1, s0) ^ self.gf_mult(4, s1)
            state[1][col] = self.gf_mult(4, s0) ^ self.gf_mult(1, s1)
        
        return state
    
    def inv_mix_columns(self, state: list[list[int]]) -> list[list[int]]:
        """逆列混淆：对每列应用矩阵乘法 [[9,2],[2,9]]（GF(2⁴)域）"""
        for col in range(AlgorithmConfig.STATE_MATRIX_COLS):
            # 保存当前列的原始值
            s0 = state[0][col]
            s1 = state[1][col]
            
            # 应用逆混淆公式：
            # s0' = 9*s0 ⊕ 2*s1
            # s1' = 2*s0 ⊕ 9*s1
            state[0][col] = self.gf_mult(9, s0) ^ self.gf_mult(2, s1)
            state[1][col] = self.gf_mult(2, s0) ^ self.gf_mult(9, s1)
        
        return state
    
    def encrypt_block(self, plaintext: int, key: int) -> int:
        """S-AES加密：16位明文块→16位密文块"""
        # 步骤1：密钥扩展（得到w0-w5）
        w = self.key_expansion(key)
        # 生成轮密钥：K0=w0w1，K1=w2w3，K2=w4w5（各16位）
        k0 = (w[0] << 8) | w[1]
        k1 = (w[2] << 8) | w[3]
        k2 = (w[4] << 8) | w[5]
        
        # 步骤2：初始化状态矩阵（16位明文按列拆分）
        # 明文拆分：plaintext → [s00, s10, s01, s11]（按列排列）
        s00 = (plaintext >> 12) & 0xF
        s10 = (plaintext >> 8) & 0xF
        s01 = (plaintext >> 4) & 0xF
        s11 = plaintext & 0xF
        state = [[s00, s01], [s10, s11]]
        
        # 步骤3：第0轮（仅轮密钥加）
        state = self.add_round_key(state, k0)
        
        # 步骤4：第1轮（完整轮：NS → SR → MC → A_K1）
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.mix_columns(state)
        state = self.add_round_key(state, k1)
        
        # 步骤5：第2轮（无列混淆：NS → SR → A_K2）
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, k2)
        
        # 步骤6：状态矩阵→16位密文
        ciphertext = (state[0][0] << 12) | (state[1][0] << 8) | (state[0][1] << 4) | state[1][1]
        
        return ciphertext
    
    def decrypt_block(self, ciphertext: int, key: int) -> int:
        """S-AES解密：16位密文块→16位明文块"""
        # 步骤1：密钥扩展（与加密相同）
        w = self.key_expansion(key)
        k0 = (w[0] << 8) | w[1]
        k1 = (w[2] << 8) | w[3]
        k2 = (w[4] << 8) | w[5]
        
        # 步骤2：初始化状态矩阵（16位密文按列拆分）
        s00 = (ciphertext >> 12) & 0xF
        s10 = (ciphertext >> 8) & 0xF
        s01 = (ciphertext >> 4) & 0xF
        s11 = ciphertext & 0xF
        state = [[s00, s01], [s10, s11]]
        
        # 步骤3：第0轮解密（对应加密第2轮：A_K2）
        state = self.add_round_key(state, k2)
        
        # 步骤4：第1轮解密（对应加密第1轮：ISR → INS → A_K1 → IMC）
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, k1)
        state = self.inv_mix_columns(state)
        
        # 步骤5：第2轮解密（对应加密第0轮：ISR → INS → A_K0）
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, k0)
        
        # 步骤6：状态矩阵→16位明文
        plaintext = (state[0][0] << 12) | (state[1][0] << 8) | (state[0][1] << 4) | state[1][1]
        
        return plaintext


# 创建全局算法核心实例
_aes_core = S_AES_Core()

# 提供便捷的函数接口
def encrypt_block(plaintext: int, key: int) -> int:
    """加密块便捷函数"""
    return _aes_core.encrypt_block(plaintext, key)

def decrypt_block(ciphertext: int, key: int) -> int:
    """解密块便捷函数"""
    return _aes_core.decrypt_block(ciphertext, key)

def double_encrypt(plaintext: int, key1: int, key2: int) -> int:
    """双重加密：P → E(K1,P) → E(K2, M) → C"""
    middle = encrypt_block(plaintext, key1)
    return encrypt_block(middle, key2)

def double_decrypt(ciphertext: int, key1: int, key2: int) -> int:
    """双重解密：C → D(K2,C) → D(K1, M) → P"""
    middle = decrypt_block(ciphertext, key2)
    return decrypt_block(middle, key1)

def triple_encrypt(plaintext: int, key1: int, key2: int, key3: int) -> int:
    """三重加密（E-D-E模式，48位密钥K1+K2+K3）：P→E(K1)→D(K2)→E(K3)→C"""
    m1 = encrypt_block(plaintext, key1)
    m2 = decrypt_block(m1, key2)
    return encrypt_block(m2, key3)

def triple_decrypt(ciphertext: int, key1: int, key2: int, key3: int) -> int:
    """三重解密：C→D(K3)→E(K2)→D(K1)→P"""
    m1 = decrypt_block(ciphertext, key3)
    m2 = encrypt_block(m1, key2)
    return decrypt_block(m2, key1)

def meet_in_the_middle(plaintext: int, ciphertext: int) -> list[tuple[int, int]]:
    """中间相遇攻击：寻找双重加密的密钥对(K1, K2)"""
    # 步骤1：预计算所有K1→中间值M的映射（K1: 0-FFFF）
    m1_to_k1 = {}
    for k1 in range(0x10000):
        m1 = encrypt_block(plaintext, k1)
        # 允许多个密钥映射到同一个中间值
        if m1 not in m1_to_k1:
            m1_to_k1[m1] = []
        m1_to_k1[m1].append(k1)
    
    # 步骤2：遍历所有K2，寻找M2=M1的K2
    possible_keys = []
    for k2 in range(0x10000):
        m2 = decrypt_block(ciphertext, k2)
        if m2 in m1_to_k1:
            for k1 in m1_to_k1[m2]:
                possible_keys.append((k1, k2))
    
    return possible_keys