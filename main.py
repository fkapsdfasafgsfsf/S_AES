"""
S-AES算法实现主程序入口
"""

import tkinter as tk
from ui.s_aes_gui import S_AES_GUI


def main():
    """主函数：启动GUI应用程序"""
    try:
        root = tk.Tk()
        app = S_AES_GUI(root)
        root.mainloop()
    except Exception as e:
        print(f"程序启动失败: {e}")
        input("按Enter键退出...")


if __name__ == "__main__":
    main()