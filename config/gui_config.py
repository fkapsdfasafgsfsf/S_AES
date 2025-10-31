"""
GUI界面配置类
包含所有界面相关的配置参数
"""

class GUIConfig:
    """GUI配置参数"""
    
    # 窗口配置
    WINDOW_TITLE = "S-AES"
    WINDOW_SIZE = "800x600"
    WINDOW_PADDING = {"padx": 10, "pady": 10}
    
    # 标签页配置
    TAB_NAMES = {
        "basic": "第1关：基本测试",
        "ascii": "第3关：ASCII扩展", 
        "multi": "第4关：多重加密",
        "cbc": "第5关：CBC模式",
        "attack": "中间相遇攻击"
    }
    
    # 输入框配置
    ENTRY_CONFIGS = {
        "normal": {"width": 20},
        "wide": {"width": 40},
        "readonly": {"width": 20, "state": "readonly"}
    }
    
    TEXT_CONFIGS = {
        "small": {"width": 50, "height": 4},
        "large": {"width": 50, "height": 10}
    }
    
    # 标签配置
    LABEL_TEXTS = {
        # 基本测试标签页
        "basic_plaintext": "16位明文（十六进制，如0000）：",
        "basic_key": "16位密钥（十六进制，如0000）：", 
        "basic_result": "输出结果（十六进制）：",
        
        # ASCII扩展标签页
        "ascii_input": "ASCII字符串（如hello）：",
        "ascii_key": "16位密钥（十六进制，如0000）：",
        "ascii_result": "输出结果：",
        
        # 多重加密标签页
        "multi_data": "16位明文/密文（十六进制）：",
        "multi_key": "密钥（十六进制）：",
        "multi_result": "输出结果（十六进制）：",
        
        # CBC模式标签页
        "cbc_input": "输入数据：",
        "cbc_key": "16位密钥（十六进制）：",
        "cbc_iv": "初始向量IV（十六进制）：", 
        "cbc_result": "输出结果：",
        
        # 攻击标签页
        "attack_plaintext": "已知明文（十六进制）：",
        "attack_ciphertext": "已知密文（十六进制）：",
        "attack_result": "可能的密钥对："
    }
    
    # 按钮配置
    BUTTON_TEXTS = {
        "basic_encrypt": "加密",
        "basic_decrypt": "解密",
        "ascii_encrypt": "字符串加密→十六进制密文", 
        "ascii_decrypt": "十六进制密文解密→字符串",
        "multi_encrypt": "加密",
        "multi_decrypt": "解密",
        "cbc_encrypt": "CBC加密",
        "cbc_decrypt": "CBC解密", 
        "attack_run": "开始攻击"
    }
    
    # 默认值配置
    DEFAULT_VALUES = {
        "basic_plaintext": "0000",
        "basic_key": "0000",
        "ascii_input": "hello", 
        "ascii_key": "0000",
        "multi_data": "0000",
        "multi_key": "00000000",
        "cbc_key": "0000",
        "cbc_iv": "0000",
        "attack_plaintext": "0000",
        "attack_ciphertext": "0000"
    }
    
    # 布局配置
    GRID_CONFIG = {
        "padx": 5,
        "pady": 5,
        "sticky": "W"
    }
    
    # 错误消息配置
    ERROR_MESSAGES = {
        "invalid_hex": "无效的十六进制字符串：{}",
        "hex_length_16": "必须是4个十六进制字符（16位）",
        "hex_length_32": "必须是8个十六进制字符（32位）", 
        "hex_length_48": "必须是12个十六进制字符（48位）",
        "hex_multiple_4": "必须是4的整数倍个十六进制字符",
        "encryption_failed": "加密失败：{}",
        "decryption_failed": "解密失败：{}",
        "cbc_encryption_failed": "CBC加密失败：{}",
        "cbc_decryption_failed": "CBC解密失败：{}"
    }
    
    @classmethod
    def get_tab_name(cls, tab_key):
        """获取标签页名称"""
        return cls.TAB_NAMES.get(tab_key, tab_key)
    
    @classmethod
    def get_label_text(cls, label_key):
        """获取标签文本"""
        return cls.LABEL_TEXTS.get(label_key, label_key)
    
    @classmethod
    def get_button_text(cls, button_key):
        """获取按钮文本"""
        return cls.BUTTON_TEXTS.get(button_key, button_key)
    
    @classmethod
    def get_default_value(cls, value_key):
        """获取默认值"""
        return cls.DEFAULT_VALUES.get(value_key, "")
    
    @classmethod
    def get_error_message(cls, error_key, *args):
        """获取错误消息"""
        message = cls.ERROR_MESSAGES.get(error_key, error_key)
        return message.format(*args) if args else message