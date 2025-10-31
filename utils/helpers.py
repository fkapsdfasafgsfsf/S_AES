"""
通用工具函数
"""

import tkinter.messagebox as messagebox
from config.constants import Constants
from config.gui_config import GUIConfig


def hex_to_int(hex_str: str) -> int:
    """十六进制字符串→整数（处理16位/32位/48位）"""
    try:
        return int(hex_str.strip(), 16)
    except ValueError:
        messagebox.showerror("错误", GUIConfig.get_error_message("invalid_hex", hex_str))
        return -1


def int_to_hex(num: int, bits: int) -> str:
    """整数→固定位数的十六进制字符串（如16位→4个字符）"""
    hex_str = hex(num)[2:].upper()  # 去掉0x前缀，转大写
    return hex_str.zfill(bits // 4)  # 补零到指定位数（1位十六进制=4位二进制）


def pkcs7_pad(data: bytes, block_size: int = Constants.DEFAULT_BLOCK_SIZE) -> bytes:
    """PKCS#7填充：补足到block_size的整数倍（默认2字节）"""
    if not data:
        return data
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    """PKCS#7去填充"""
    if not data:
        return data
    pad_len = data[-1]
    # 验证填充有效性
    if pad_len > len(data) or not all(b == pad_len for b in data[-pad_len:]):
        raise ValueError("无效的PKCS#7填充")
    return data[:-pad_len]


def validate_hex_length(hex_str: str, expected_bits: int) -> bool:
    """验证十六进制字符串长度"""
    expected_chars = expected_bits // 4
    actual_length = len(hex_str)
    
    if actual_length != expected_chars:
        error_messages = {
            16: GUIConfig.get_error_message("hex_length_16"),
            32: GUIConfig.get_error_message("hex_length_32"),
            48: GUIConfig.get_error_message("hex_length_48")
        }
        messagebox.showerror("错误", error_messages.get(expected_bits, f"必须是{expected_chars}个十六进制字符"))
        return False
    return True


def validate_hex_multiple(hex_str: str, multiple: int = 4) -> bool:
    """验证十六进制字符串长度是否为指定倍数"""
    if len(hex_str) % multiple != 0:
        messagebox.showerror("错误", GUIConfig.get_error_message("hex_multiple_4"))
        return False
    return True


def bytes_to_int_be(data: bytes) -> int:
    """字节数组→整数（大端序）"""
    result = 0
    for byte in data:
        result = (result << 8) | byte
    return result


def int_to_bytes_be(num: int, num_bytes: int) -> bytes:
    """整数→字节数组（大端序）"""
    return bytes([(num >> (8 * (num_bytes - 1 - i))) & 0xFF for i in range(num_bytes)])