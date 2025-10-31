"""
S-AES算法配置类
包含所有算法相关的常量和配置参数
"""

class AlgorithmConfig:
    """S-AES算法配置"""
    
    # S盒配置
    S_BOX = [
        0x9, 0x4, 0xA, 0xB,  # 行0 (i=00)
        0xD, 0x1, 0x8, 0x5,  # 行1 (i=01)
        0x6, 0x2, 0x0, 0x3,  # 行2 (i=10)
        0xC, 0xE, 0xF, 0x7   # 行3 (i=11)
    ]
    
    # 逆S盒配置
    INV_S_BOX = [
        0xA, 0x5, 0x9, 0xB,  # 行0 (i=00)
        0x1, 0x7, 0x8, 0xF,  # 行1 (i=01)
        0x6, 0x0, 0x2, 0x3,  # 行2 (i=10)
        0xC, 0x4, 0xD, 0xE   # 行3 (i=11)
    ]
    
    # RCON常量配置
    RCON = [0x00, 0x80, 0x30]  # RCON[0]未使用，RCON[1]=0x80，RCON[2]=0x30
    
    # 列混淆矩阵配置
    MIX_COLUMNS_MATRIX = [[1, 4], [4, 1]]
    INV_MIX_COLUMNS_MATRIX = [[9, 2], [2, 9]]
    
    # 加密轮数配置
    ROUNDS = 3
    KEY_WORDS = 6  # 密钥扩展后的字数
    
    # 块大小配置（位）
    BLOCK_SIZE_BITS = 16
    BLOCK_SIZE_BYTES = 2
    BLOCK_SIZE_NIBBLES = 4
    
    # 密钥大小配置
    KEY_SIZE_SINGLE_BITS = 16
    KEY_SIZE_DOUBLE_BITS = 32
    KEY_SIZE_TRIPLE_BITS = 48
    
    # 状态矩阵尺寸
    STATE_MATRIX_ROWS = 2
    STATE_MATRIX_COLS = 2
    
    @classmethod
    def validate_config(cls):
        """验证算法配置的有效性"""
        assert len(cls.S_BOX) == 16, "S盒必须包含16个元素"
        assert len(cls.INV_S_BOX) == 16, "逆S盒必须包含16个元素"
        assert len(cls.RCON) >= 3, "RCON数组必须至少包含3个元素"
        return True