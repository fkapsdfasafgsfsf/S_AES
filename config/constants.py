"""
通用常量定义
"""

class Constants:
    """通用常量"""
    
    # 编码相关
    ENCODING = "ascii"
    
    # 填充相关
    PADDING_SCHEME = "PKCS7"
    DEFAULT_BLOCK_SIZE = 2
    
    # 数值范围
    MAX_16BIT = 0xFFFF
    MAX_32BIT = 0xFFFFFFFF
    MAX_48BIT = 0xFFFFFFFFFFFF
    
    # 字符串格式
    HEX_PREFIX = "0x"
    
    # 输入类型
    INPUT_TYPE_HEX = "hex"
    INPUT_TYPE_ASCII = "ascii"
    
    # 加密模式
    MODE_SINGLE = "single"
    MODE_DOUBLE = "double" 
    MODE_TRIPLE = "triple"
    
    # 攻击参数
    MAX_KEY_PAIRS_DISPLAY = 20
    
    # 文件路径
    CONFIG_DIR = "config"
    CORE_DIR = "core"
    UI_DIR = "ui"
    UTILS_DIR = "utils"