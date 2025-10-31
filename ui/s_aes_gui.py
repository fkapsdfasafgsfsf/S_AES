"""
S-AES图形用户界面实现（优化版）
基于配置文件的模块化GUI实现
"""

import tkinter as tk
from tkinter import ttk, messagebox
from core.s_aes_core import (
    encrypt_block, decrypt_block, 
    double_encrypt, double_decrypt,
    triple_encrypt, triple_decrypt,
    meet_in_the_middle
)
from utils.helpers import (
    hex_to_int, int_to_hex, 
    pkcs7_pad, pkcs7_unpad,
    validate_hex_length, validate_hex_multiple,
    bytes_to_int_be, int_to_bytes_be
)
from config.gui_config import GUIConfig
from config.constants import Constants
from config.algorithm_config import AlgorithmConfig


class S_AES_GUI:
    """S-AES算法图形用户界面主类"""
    
    def __init__(self, root):
        """初始化GUI界面"""
        self.root = root
        self.root.title(GUIConfig.WINDOW_TITLE)
        self.root.geometry(GUIConfig.WINDOW_SIZE)
        
        # 标签页控件
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, **GUIConfig.WINDOW_PADDING)
        
        # 初始化各标签页
        self.init_basic_tab()      # 第1关：基本测试
        self.init_ascii_tab()      # 第3关：ASCII扩展
        self.init_multi_tab()      # 第4关：多重加密
        self.init_cbc_tab()        # 第5关：CBC模式
        self.init_attack_tab()     # 第4关：中间相遇攻击
        
    def create_label(self, parent, text_key, row, column):
        """创建标签"""
        text = GUIConfig.get_label_text(text_key)
        label = ttk.Label(parent, text=text)
        label.grid(row=row, column=column, **GUIConfig.GRID_CONFIG)
        return label
    
    def create_entry(self, parent, config_key, row, column, default_key=None):
        """创建输入框"""
        config = GUIConfig.ENTRY_CONFIGS.get(config_key, {})
        entry = ttk.Entry(parent, **config)
        entry.grid(row=row, column=column, **GUIConfig.GRID_CONFIG)
        
        if default_key:
            default_value = GUIConfig.get_default_value(default_key)
            entry.insert(0, default_value)
            
        return entry
    
    def create_button(self, parent, text_key, command, row, column, colspan=1):
        """创建按钮"""
        text = GUIConfig.get_button_text(text_key)
        button = ttk.Button(parent, text=text, command=command)
        button.grid(row=row, column=column, columnspan=colspan, **GUIConfig.GRID_CONFIG)
        return button

    def init_basic_tab(self):
        """基本测试标签页：16位明文/密钥→16位密文"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=GUIConfig.get_tab_name("basic"))
        
        # 1. 明文输入
        self.create_label(tab, "basic_plaintext", 0, 0)
        self.basic_plaintext = self.create_entry(tab, "normal", 0, 1, "basic_plaintext")
        
        # 2. 密钥输入
        self.create_label(tab, "basic_key", 1, 0)
        self.basic_key = self.create_entry(tab, "normal", 1, 1, "basic_key")
        
        # 3. 结果显示
        self.create_label(tab, "basic_result", 2, 0)
        self.basic_result = self.create_entry(tab, "readonly", 2, 1)
        
        # 4. 按钮
        self.create_button(tab, "basic_encrypt", self.basic_encrypt, 3, 0)
        self.create_button(tab, "basic_decrypt", self.basic_decrypt, 3, 1)
    
    def basic_encrypt(self):
        """基本测试-加密"""
        plaintext_hex = self.basic_plaintext.get()
        key_hex = self.basic_key.get()
        
        # 验证输入长度
        if not validate_hex_length(plaintext_hex, AlgorithmConfig.KEY_SIZE_SINGLE_BITS):
            return
        if not validate_hex_length(key_hex, AlgorithmConfig.KEY_SIZE_SINGLE_BITS):
            return
        
        # 转换为整数
        plaintext = hex_to_int(plaintext_hex)
        key = hex_to_int(key_hex)
        if plaintext == -1 or key == -1:
            return
        
        # 加密
        ciphertext = encrypt_block(plaintext, key)
        
        # 显示结果
        self.basic_result.config(state="normal")
        self.basic_result.delete(0, tk.END)
        self.basic_result.insert(0, int_to_hex(ciphertext, AlgorithmConfig.BLOCK_SIZE_BITS))
        self.basic_result.config(state="readonly")
    
    def basic_decrypt(self):
        """基本测试-解密"""
        ciphertext_hex = self.basic_plaintext.get()
        key_hex = self.basic_key.get()
        
        if not validate_hex_length(ciphertext_hex, AlgorithmConfig.BLOCK_SIZE_BITS):
            return
        if not validate_hex_length(key_hex, AlgorithmConfig.KEY_SIZE_SINGLE_BITS):
            return
        
        ciphertext = hex_to_int(ciphertext_hex)
        key = hex_to_int(key_hex)
        if ciphertext == -1 or key == -1:
            return
        
        # 解密
        plaintext = decrypt_block(ciphertext, key)
        
        self.basic_result.config(state="normal")
        self.basic_result.delete(0, tk.END)
        self.basic_result.insert(0, int_to_hex(plaintext, AlgorithmConfig.BLOCK_SIZE_BITS))
        self.basic_result.config(state="readonly")

    def init_ascii_tab(self):
        """ASCII扩展标签页：字符串→十六进制密文"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=GUIConfig.get_tab_name("ascii"))
        
        # 1. 字符串输入
        self.create_label(tab, "ascii_input", 0, 0)
        self.ascii_input = self.create_entry(tab, "wide", 0, 1, "ascii_input")
        
        # 2. 16位密钥输入
        self.create_label(tab, "ascii_key", 1, 0)
        self.ascii_key = self.create_entry(tab, "normal", 1, 1, "ascii_key")
        
        # 3. 结果显示
        self.create_label(tab, "ascii_result", 2, 0)
        self.ascii_result = self.create_entry(tab, "wide", 2, 1)
        
        # 4. 按钮
        self.create_button(tab, "ascii_encrypt", self.ascii_encrypt, 3, 0, 2)
        self.create_button(tab, "ascii_decrypt", self.ascii_decrypt, 4, 0, 2)
    
    def ascii_encrypt(self):
        """ASCII字符串加密：字符串→填充→分块加密→十六进制密文"""
        input_str = self.ascii_input.get()
        key_hex = self.ascii_key.get()
        
        if not validate_hex_length(key_hex, AlgorithmConfig.KEY_SIZE_SINGLE_BITS):
            return
        
        key = hex_to_int(key_hex)
        if key == -1:
            return
        
        try:
            # 1. 字符串→字节流→PKCS#7填充
            data = input_str.encode(Constants.ENCODING)
            padded_data = pkcs7_pad(data)
            
            # 2. 按2字节（16位）分块加密
            ciphertext_blocks = []
            for i in range(0, len(padded_data), AlgorithmConfig.BLOCK_SIZE_BYTES):
                block = padded_data[i:i+AlgorithmConfig.BLOCK_SIZE_BYTES]
                # 字节块→16位整数（大端序）
                block_int = bytes_to_int_be(block)
                # 加密
                cipher_int = encrypt_block(block_int, key)
                ciphertext_blocks.append(cipher_int)
            
            # 3. 所有块→十六进制字符串
            ciphertext_hex = "".join([
                int_to_hex(block, AlgorithmConfig.BLOCK_SIZE_BITS) 
                for block in ciphertext_blocks
            ])
            
            # 显示结果
            self.ascii_result.config(state="normal")
            self.ascii_result.delete(0, tk.END)
            self.ascii_result.insert(0, ciphertext_hex)
            self.ascii_result.config(state="readonly")
            
        except Exception as e:
            messagebox.showerror("错误", GUIConfig.get_error_message("encryption_failed", str(e)))
    
    def ascii_decrypt(self):
        """ASCII字符串解密：十六进制密文→分块解密→去填充→字符串"""
        ciphertext_hex = self.ascii_input.get()
        key_hex = self.ascii_key.get()
        
        # 验证密文长度
        if not validate_hex_multiple(ciphertext_hex):
            return
        
        if not validate_hex_length(key_hex, AlgorithmConfig.KEY_SIZE_SINGLE_BITS):
            return
        
        key = hex_to_int(key_hex)
        if key == -1:
            return
        
        try:
            # 1. 十六进制密文→分块
            plaintext_blocks = []
            for i in range(0, len(ciphertext_hex), AlgorithmConfig.BLOCK_SIZE_NIBBLES):
                block_hex = ciphertext_hex[i:i+AlgorithmConfig.BLOCK_SIZE_NIBBLES]
                cipher_int = hex_to_int(block_hex)
                if cipher_int == -1:
                    return
                # 解密
                plain_int = decrypt_block(cipher_int, key)
                # 16位整数→2字节块
                block_bytes = int_to_bytes_be(plain_int, AlgorithmConfig.BLOCK_SIZE_BYTES)
                plaintext_blocks.append(block_bytes)
            
            # 2. 合并块→去填充→字符串
            plaintext_bytes = b"".join(plaintext_blocks)
            unpadded_bytes = pkcs7_unpad(plaintext_bytes)
            plaintext_str = unpadded_bytes.decode(Constants.ENCODING)
            
            # 显示结果
            self.ascii_result.config(state="normal")
            self.ascii_result.delete(0, tk.END)
            self.ascii_result.insert(0, plaintext_str)
            self.ascii_result.config(state="readonly")
            
        except Exception as e:
            messagebox.showerror("错误", GUIConfig.get_error_message("decryption_failed", str(e)))

    def init_multi_tab(self):
        """多重加密标签页：双重（32位密钥）/三重（48位密钥）"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=GUIConfig.get_tab_name("multi"))
        
        # 1. 加密模式选择
        self.multi_mode = tk.StringVar(value=Constants.MODE_DOUBLE)
        ttk.Radiobutton(tab, text="双重加密（32位密钥）", 
                       variable=self.multi_mode, value=Constants.MODE_DOUBLE).grid(
            row=0, column=0, **GUIConfig.GRID_CONFIG)
        ttk.Radiobutton(tab, text="三重加密（48位密钥）", 
                       variable=self.multi_mode, value=Constants.MODE_TRIPLE).grid(
            row=0, column=1, **GUIConfig.GRID_CONFIG)
        
        # 2. 16位明文/密文输入
        self.create_label(tab, "multi_data", 1, 0)
        self.multi_data = self.create_entry(tab, "normal", 1, 1, "multi_data")
        
        # 3. 密钥输入
        self.create_label(tab, "multi_key", 2, 0)
        self.multi_key = self.create_entry(tab, "wide", 2, 1, "multi_key")
        
        # 4. 结果显示
        self.create_label(tab, "multi_result", 3, 0)
        self.multi_result = self.create_entry(tab, "readonly", 3, 1)
        
        # 5. 按钮
        self.create_button(tab, "multi_encrypt", self.multi_encrypt, 4, 0)
        self.create_button(tab, "multi_decrypt", self.multi_decrypt, 4, 1)
    
    def multi_encrypt(self):
        """多重加密"""
        data_hex = self.multi_data.get()
        key_hex = self.multi_key.get()
        mode = self.multi_mode.get()
        
        # 验证输入
        if not validate_hex_length(data_hex, AlgorithmConfig.BLOCK_SIZE_BITS):
            return
        
        key_size_map = {
            Constants.MODE_DOUBLE: AlgorithmConfig.KEY_SIZE_DOUBLE_BITS,
            Constants.MODE_TRIPLE: AlgorithmConfig.KEY_SIZE_TRIPLE_BITS
        }
        
        expected_bits = key_size_map.get(mode)
        if expected_bits and not validate_hex_length(key_hex, expected_bits):
            return
        
        # 转换为整数
        plaintext = hex_to_int(data_hex)
        key = hex_to_int(key_hex)
        if plaintext == -1 or key == -1:
            return
        
        # 拆分密钥并加密
        if mode == Constants.MODE_DOUBLE:
            key1 = (key >> 16) & Constants.MAX_16BIT
            key2 = key & Constants.MAX_16BIT
            ciphertext = double_encrypt(plaintext, key1, key2)
        else:  # triple
            key1 = (key >> 32) & Constants.MAX_16BIT
            key2 = (key >> 16) & Constants.MAX_16BIT
            key3 = key & Constants.MAX_16BIT
            ciphertext = triple_encrypt(plaintext, key1, key2, key3)
        
        # 显示结果
        self.multi_result.config(state="normal")
        self.multi_result.delete(0, tk.END)
        self.multi_result.insert(0, int_to_hex(ciphertext, AlgorithmConfig.BLOCK_SIZE_BITS))
        self.multi_result.config(state="readonly")
    
    def multi_decrypt(self):
        """多重解密"""
        data_hex = self.multi_data.get()
        key_hex = self.multi_key.get()
        mode = self.multi_mode.get()
        
        if not validate_hex_length(data_hex, AlgorithmConfig.BLOCK_SIZE_BITS):
            return
        
        key_size_map = {
            Constants.MODE_DOUBLE: AlgorithmConfig.KEY_SIZE_DOUBLE_BITS,
            Constants.MODE_TRIPLE: AlgorithmConfig.KEY_SIZE_TRIPLE_BITS
        }
        
        expected_bits = key_size_map.get(mode)
        if expected_bits and not validate_hex_length(key_hex, expected_bits):
            return
        
        ciphertext = hex_to_int(data_hex)
        key = hex_to_int(key_hex)
        if ciphertext == -1 or key == -1:
            return
        
        # 拆分密钥并解密
        if mode == Constants.MODE_DOUBLE:
            key1 = (key >> 16) & Constants.MAX_16BIT
            key2 = key & Constants.MAX_16BIT
            plaintext = double_decrypt(ciphertext, key1, key2)
        else:  # triple
            key1 = (key >> 32) & Constants.MAX_16BIT
            key2 = (key >> 16) & Constants.MAX_16BIT
            key3 = key & Constants.MAX_16BIT
            plaintext = triple_decrypt(ciphertext, key1, key2, key3)
        
        self.multi_result.config(state="normal")
        self.multi_result.delete(0, tk.END)
        self.multi_result.insert(0, int_to_hex(plaintext, AlgorithmConfig.BLOCK_SIZE_BITS))
        self.multi_result.config(state="readonly")

    def init_cbc_tab(self):
        """CBC模式标签页"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=GUIConfig.get_tab_name("cbc"))
        
        # 1. 输入类型选择
        ttk.Label(tab, text="输入类型：").grid(
            row=0, column=0, **GUIConfig.GRID_CONFIG)
        self.cbc_input_type = tk.StringVar(value=Constants.INPUT_TYPE_HEX)
        ttk.Radiobutton(tab, text="十六进制", 
                       variable=self.cbc_input_type, value=Constants.INPUT_TYPE_HEX).grid(
            row=0, column=1, **GUIConfig.GRID_CONFIG)
        ttk.Radiobutton(tab, text="ASCII字符串", 
                       variable=self.cbc_input_type, value=Constants.INPUT_TYPE_ASCII).grid(
            row=0, column=2, **GUIConfig.GRID_CONFIG)
        
        # 2. 明文/密文输入
        self.create_label(tab, "cbc_input", 1, 0)
        self.cbc_input = tk.Text(tab, **GUIConfig.TEXT_CONFIGS["small"])
        self.cbc_input.grid(row=1, column=1, columnspan=2, **GUIConfig.GRID_CONFIG)
        
        # 3. 密钥和IV输入
        self.create_label(tab, "cbc_key", 2, 0)
        self.cbc_key = self.create_entry(tab, "normal", 2, 1, "cbc_key")
        
        self.create_label(tab, "cbc_iv", 3, 0)
        self.cbc_iv = self.create_entry(tab, "normal", 3, 1, "cbc_iv")
        
        # 4. 结果显示
        self.create_label(tab, "cbc_result", 4, 0)
        self.cbc_result = tk.Text(tab, **GUIConfig.TEXT_CONFIGS["small"])
        self.cbc_result.grid(row=4, column=1, columnspan=2, **GUIConfig.GRID_CONFIG)
        
        # 5. 按钮
        self.create_button(tab, "cbc_encrypt", self.cbc_encrypt, 5, 1)
        self.create_button(tab, "cbc_decrypt", self.cbc_decrypt, 5, 2)
    
    def cbc_encrypt(self):
        """CBC模式加密"""
        try:
            input_data = self.cbc_input.get("1.0", tk.END).strip()
            key_hex = self.cbc_key.get()
            iv_hex = self.cbc_iv.get()
            
            if not validate_hex_length(key_hex, AlgorithmConfig.KEY_SIZE_SINGLE_BITS):
                return
            if not validate_hex_length(iv_hex, AlgorithmConfig.BLOCK_SIZE_BITS):
                return
            
            key = hex_to_int(key_hex)
            iv = hex_to_int(iv_hex)
            if key == -1 or iv == -1:
                return
            
            # 处理输入数据
            if self.cbc_input_type.get() == Constants.INPUT_TYPE_ASCII:
                # ASCII字符串处理
                data = input_data.encode(Constants.ENCODING)
                padded_data = pkcs7_pad(data)
                blocks = []
                for i in range(0, len(padded_data), AlgorithmConfig.BLOCK_SIZE_BYTES):
                    block_bytes = padded_data[i:i+AlgorithmConfig.BLOCK_SIZE_BYTES]
                    block = bytes_to_int_be(block_bytes)
                    blocks.append(block)
            else:
                # 十六进制数据处理
                if not validate_hex_multiple(input_data):
                    return
                blocks = []
                for i in range(0, len(input_data), AlgorithmConfig.BLOCK_SIZE_NIBBLES):
                    block_hex = input_data[i:i+AlgorithmConfig.BLOCK_SIZE_NIBBLES]
                    block = hex_to_int(block_hex)
                    if block == -1:
                        return
                    blocks.append(block)
            
            # CBC加密
            cipher_blocks = []
            previous = iv
            for block in blocks:
                # 异或前一个密文块（或IV）
                xored = block ^ previous
                # 加密
                encrypted = encrypt_block(xored, key)
                cipher_blocks.append(encrypted)
                previous = encrypted
            
            # 输出结果
            result_hex = "".join([
                int_to_hex(block, AlgorithmConfig.BLOCK_SIZE_BITS) 
                for block in cipher_blocks
            ])
            self.cbc_result.delete("1.0", tk.END)
            self.cbc_result.insert("1.0", result_hex)
            
        except Exception as e:
            messagebox.showerror("错误", GUIConfig.get_error_message("cbc_encryption_failed", str(e)))
    
    def cbc_decrypt(self):
        """CBC模式解密"""
        try:
            input_data = self.cbc_input.get("1.0", tk.END).strip()
            key_hex = self.cbc_key.get()
            iv_hex = self.cbc_iv.get()
            
            if not validate_hex_length(key_hex, AlgorithmConfig.KEY_SIZE_SINGLE_BITS):
                return
            if not validate_hex_length(iv_hex, AlgorithmConfig.BLOCK_SIZE_BITS):
                return
            
            key = hex_to_int(key_hex)
            iv = hex_to_int(iv_hex)
            if key == -1 or iv == -1:
                return
            
            # 解析输入块（必须是十六进制）
            if not validate_hex_multiple(input_data):
                return
            
            cipher_blocks = []
            for i in range(0, len(input_data), AlgorithmConfig.BLOCK_SIZE_NIBBLES):
                block_hex = input_data[i:i+AlgorithmConfig.BLOCK_SIZE_NIBBLES]
                block = hex_to_int(block_hex)
                if block == -1:
                    return
                cipher_blocks.append(block)
            
            # CBC解密
            plain_blocks = []
            previous = iv
            for block in cipher_blocks:
                # 解密
                decrypted = decrypt_block(block, key)
                # 异或前一个密文块（或IV）
                xored = decrypted ^ previous
                plain_blocks.append(xored)
                previous = block
            
            # 处理输出
            if self.cbc_input_type.get() == Constants.INPUT_TYPE_ASCII:
                # 转换为ASCII字符串
                bytes_data = b""
                for block in plain_blocks:
                    bytes_data += int_to_bytes_be(block, AlgorithmConfig.BLOCK_SIZE_BYTES)
                unpadded_data = pkcs7_unpad(bytes_data)
                result = unpadded_data.decode(Constants.ENCODING)
            else:
                # 输出十六进制
                result = "".join([
                    int_to_hex(block, AlgorithmConfig.BLOCK_SIZE_BITS) 
                    for block in plain_blocks
                ])
            
            self.cbc_result.delete("1.0", tk.END)
            self.cbc_result.insert("1.0", result)
            
        except Exception as e:
            messagebox.showerror("错误", GUIConfig.get_error_message("cbc_decryption_failed", str(e)))

    def init_attack_tab(self):
        """中间相遇攻击标签页"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=GUIConfig.get_tab_name("attack"))
        
        # 1. 已知明密文对
        self.create_label(tab, "attack_plaintext", 0, 0)
        self.attack_plaintext = self.create_entry(tab, "normal", 0, 1, "attack_plaintext")
        
        self.create_label(tab, "attack_ciphertext", 1, 0)
        self.attack_ciphertext = self.create_entry(tab, "normal", 1, 1, "attack_ciphertext")
        
        # 2. 结果显示
        self.create_label(tab, "attack_result", 2, 0)
        self.attack_result = tk.Text(tab, **GUIConfig.TEXT_CONFIGS["large"])
        self.attack_result.grid(row=3, column=0, columnspan=2, **GUIConfig.GRID_CONFIG)
        
        # 3. 按钮
        self.create_button(tab, "attack_run", self.run_attack, 4, 0, 2)
    
    def run_attack(self):
        """执行中间相遇攻击"""
        plaintext_hex = self.attack_plaintext.get()
        ciphertext_hex = self.attack_ciphertext.get()
        
        if not validate_hex_length(plaintext_hex, AlgorithmConfig.BLOCK_SIZE_BITS):
            return
        if not validate_hex_length(ciphertext_hex, AlgorithmConfig.BLOCK_SIZE_BITS):
            return
        
        plaintext = hex_to_int(plaintext_hex)
        ciphertext = hex_to_int(ciphertext_hex)
        if plaintext == -1 or ciphertext == -1:
            return
        
        # 执行中间相遇攻击
        self.attack_result.delete("1.0", tk.END)
        self.attack_result.insert("1.0", "正在计算，请稍候...")
        self.root.update()
        
        possible_keys = meet_in_the_middle(plaintext, ciphertext)
        
        # 显示结果
        self.attack_result.delete("1.0", tk.END)
        if not possible_keys:
            self.attack_result.insert("1.0", "未找到可能的密钥对")
        else:
            result_text = f"找到 {len(possible_keys)} 个可能的密钥对：\n\n"
            max_display = Constants.MAX_KEY_PAIRS_DISPLAY
            for i, (k1, k2) in enumerate(possible_keys[:max_display]):
                result_text += f"密钥对 {i+1}: K1={int_to_hex(k1, 16)}, K2={int_to_hex(k2, 16)}\n"
            
            if len(possible_keys) > max_display:
                result_text += f"\n... 还有 {len(possible_keys) - max_display} 个密钥对未显示"
            
            self.attack_result.insert("1.0", result_text)