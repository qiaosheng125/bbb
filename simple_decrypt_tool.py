#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
简易文件解密工具 (自动版 v4.2)

这个工具可以自动查找同文件夹内的加密文件，解密后直接将内容复制到剪贴板。
设计重点：
1. 无界面操作：双击运行后自动识别同目录下的txt文件并进行解密
2. 增强单实例机制：启动新实例时自动关闭旧实例，接管监控任务
3. 自动识别标识符：从文件名中提取中文标识符
4. 解密结果自动复制到剪贴板并传入打印助手
5. 持续后台运行：完成解密后继续在后台监控打印助手窗口
6. 智能退出：成功终止打印助手进程后自动退出程序
"""

import os
import sys
import json
import base64
import hashlib
import datetime
import socket
import platform
import getpass
import uuid
import re
import glob
import random
import pyperclip
import tkinter as tk
from tkinter import messagebox, ttk
import subprocess
import time
import threading
import ctypes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Windows API相关导入，用于窗口操作和键盘钩子
try:
    import win32gui
    import win32process
    import win32con
    import win32api
    import win32clipboard
    import keyboard
except ImportError:
    # 在非Windows系统上可能会导入失败
    pass

# 定义全局常量
SALT = b'sportsbet_file_encryption_salt'

# 全局变量
lb_printer_hwnd = None  # 赢彩投注单打印助手窗口句柄
is_monitoring = False  # 是否已启动窗口监控
DEVICE_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".sportsbet")
DEVICE_CONFIG_FILE = os.path.join(DEVICE_CONFIG_DIR, "device_config.json")
DECRYPT_HISTORY_FILE = os.path.join(DEVICE_CONFIG_DIR, "decrypt_history.json")
VERSION = "4.2"  # 2025-04-07 更新，成功终止打印助手进程后自动退出程序

# 外部程序设置
LBPRINTER_PROCESS_NAME = "LBPrinter.exe"
LBPRINTER_WINDOW_TITLE = "赢彩投注单打印助手"

# 保存按钮区域配置（统一配置，便于一处修改）
SAVE_BUTTON = {
    'offset_left': 300,  # 按钮区域距离窗口左边距离（从窗口最左侧开始）
    'offset_top': 50,  # 按钮区域距离窗口顶部距离（从窗口顶部开始）
    'width': 90,  # 按钮区域宽度（极限宽度确保覆盖整个窗口顶部区域）
    'height': 65  # 按钮区域高度（极限高度确保覆盖所有可能的按钮位置）
}

# 全局变量
is_monitoring = False
lb_printer_hwnd = None
is_first_activation = True


class SimpleDecryptTool:

    def __init__(self, root):
        self.root = root
        self.root.title("简易解密工具")
        self.root.geometry("450x320")  # 增加窗口大小
        self.root.resizable(True, True)  # 允许调整窗口大小

        # 获取设备ID
        self.device_id = get_device_id()
        self.setup_ui()

        # 自动扫描同目录内的加密文件
        self.encrypted_files = self.scan_for_encrypted_files()
        self.update_file_list()

        # 启动时立即设置窗口监控
        setup_window_monitoring()

        # 启动时查找赢彩投注单打印助手窗口并标记保存按钮区域
        self.root.after(1000, self.mark_save_button_area)

        # 启动时就创建保存按钮阻挡窗口
        self.root.after(1000, self.create_protection_on_startup)

    def mark_save_button_area(self):
        """在启动时标记保存按钮区域并在界面上显示详细信息"""
        global lb_printer_hwnd

        try:
            # 创建位置信息标签（如果不存在）
            if not hasattr(self, 'button_info_label'):
                self.button_info_frame = ttk.LabelFrame(self.root,
                                                        text="保存按钮位置信息",
                                                        padding=10)
                self.button_info_frame.pack(fill=tk.X,
                                            expand=True,
                                            padx=20,
                                            pady=10)

                self.button_info_label = ttk.Label(self.button_info_frame,
                                                   text="等待检测...",
                                                   justify=tk.LEFT)
                self.button_info_label.pack(fill=tk.X)

            # 查找并激活赢彩投注单打印助手窗口
            hwnd = find_window_by_title(LBPRINTER_WINDOW_TITLE)
            if hwnd:
                lb_printer_hwnd = hwnd
                # 显示该窗口
                try:
                    if 'win32gui' in globals():
                        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)

                        # 获取窗口位置
                        left, top, right, bottom = win32gui.GetWindowRect(
                            lb_printer_hwnd)

                        # 计算保存按钮区域，使用全局配置
                        save_btn_left = left + SAVE_BUTTON[
                            'offset_left']  # 从窗口左边开始
                        save_btn_top = top + SAVE_BUTTON[
                            'offset_top']  # 从窗口顶部开始
                        save_btn_right = save_btn_left + SAVE_BUTTON[
                            'width']  # 按全局配置宽度
                        save_btn_bottom = save_btn_top + SAVE_BUTTON[
                            'height']  # 按全局配置高度

                        # 更新界面显示
                        button_info_text = f"窗口位置: 左={left}, 上={top}, 右={right}, 下={bottom}\n"
                        button_info_text += f"保存按钮区域:\n"
                        button_info_text += f"- 左上角: ({save_btn_left}, {save_btn_top})\n"
                        button_info_text += f"- 右上角: ({save_btn_right}, {save_btn_top})\n"
                        button_info_text += f"- 左下角: ({save_btn_left}, {save_btn_bottom})\n"
                        button_info_text += f"- 右下角: ({save_btn_right}, {save_btn_bottom})"

                        self.button_info_label.config(text=button_info_text)

                        # 调用is_save_button_region函数以在控制台显示信息
                        client_x = 50  # 假设的客户端x坐标
                        client_y = 50  # 假设的客户端y坐标
                        is_save_button_region(client_x, client_y)

                        self.status_var.set("已获取保存号码按钮位置信息")
                except Exception as e:
                    print(f"标记保存按钮区域出错: {str(e)}")
                    self.button_info_label.config(
                        text=f"获取保存按钮区域信息出错: {str(e)}")
            else:
                print("未找到赢彩投注单打印助手窗口，请先启动该程序")
                self.status_var.set("未找到赢彩投注单打印助手窗口，请先启动该程序")
                self.button_info_label.config(text="未找到赢彩投注单打印助手窗口，请先启动该程序")
                # 稍后再试
                self.root.after(1000, self.mark_save_button_area)
        except Exception as e:
            print(f"标记保存按钮区域过程中出错: {str(e)}")
            if hasattr(self, 'button_info_label'):
                self.button_info_label.config(text=f"标记保存按钮区域过程中出错: {str(e)}")
            # 稍后再试
            self.root.after(1000, self.mark_save_button_area)

    def setup_ui(self):
        """创建简洁的用户界面"""
        main_frame = ttk.Frame(self.root, padding="20 20 20 20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 标题
        title_label = ttk.Label(main_frame,
                                text="简易解密工具",
                                font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 10))

        # 设备ID信息
        device_frame = ttk.Frame(main_frame)
        device_frame.pack(fill=tk.X, pady=5)

        device_id_short = self.device_id[:8] + "..." + self.device_id[-8:]
        device_label = ttk.Label(device_frame, text=f"设备ID: {device_id_short}")
        device_label.pack(side=tk.LEFT)

        copy_btn = ttk.Button(device_frame,
                              text="复制设备ID",
                              command=self.copy_device_id)
        copy_btn.pack(side=tk.RIGHT)

        # 使用说明
        instruction_text = "使用说明:\n" + \
                            "1. 将需要解密的文件放在与本工具相同的文件夹中\n" + \
                            "2. 从下拉菜单选择要解密的文件\n" + \
                            "3. 点击'解密并复制内容'按钮\n" + \
                            "4. 解密成功后内容会自动复制到剪贴板"
        instruction_label = ttk.Label(main_frame,
                                      text=instruction_text,
                                      justify=tk.LEFT)
        instruction_label.pack(fill=tk.X, pady=10)

        # 文件选择下拉菜单
        file_frame = ttk.Frame(main_frame)
        file_frame.pack(fill=tk.X, pady=5)

        file_label = ttk.Label(file_frame, text="选择文件:")
        file_label.pack(side=tk.LEFT)

        self.file_var = tk.StringVar()
        self.file_combo = ttk.Combobox(file_frame,
                                       textvariable=self.file_var,
                                       state="readonly")
        self.file_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        refresh_btn = ttk.Button(file_frame,
                                 text="刷新",
                                 command=self.refresh_files)
        refresh_btn.pack(side=tk.RIGHT)

        # 解密按钮（使用专门的按钮框架以确保完全显示）
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)

        decrypt_btn = ttk.Button(button_frame,
                                 text="解密并复制内容",
                                 command=self.decrypt_to_clipboard)
        decrypt_btn.pack(pady=5, padx=20, ipadx=10, ipady=5)

        # 状态栏
        self.status_var = tk.StringVar(value="准备就绪")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.pack(fill=tk.X, pady=5)

        # 版权信息
        version_label = ttk.Label(main_frame,
                                  text=f"版本 {VERSION}",
                                  font=('Arial', 8))
        version_label.pack(side=tk.RIGHT)

    def scan_for_encrypted_files(self):
        """扫描同目录下的所有可能是加密文件的文件"""
        # 获取程序所在目录
        current_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

        # 查找所有可能是加密文件的文件
        # 1. 查找包含"加密"的文件
        encrypted_files_pattern1 = os.path.join(current_dir, "*加密*.*")
        # 2. 查找带有中文字符的txt文件
        encrypted_files_pattern2 = os.path.join(current_dir, "*.txt")

        # 使用集合去除重复文件
        files_set = set(glob.glob(encrypted_files_pattern1))
        # 添加txt文件，但不添加已经在集合中的文件
        for txt_file in glob.glob(encrypted_files_pattern2):
            files_set.add(txt_file)

        # 过滤掉可能是解密结果的文件和自身
        filtered_files = []
        for file in files_set:
            filename = os.path.basename(file)
            # 排除自身和解密结果文件
            if (filename != os.path.basename(sys.argv[0])
                    and not filename.startswith("解密结果_")):
                filtered_files.append(file)

        return filtered_files

    def update_file_list(self):
        """更新文件列表下拉菜单"""
        if not self.encrypted_files:
            self.file_var.set("没有找到加密文件")
            self.file_combo['values'] = []
            self.file_combo.configure(state="disabled")
            self.status_var.set("请将加密文件放在同一目录下")
        else:
            # 仅显示文件名，不显示完整路径
            filenames = [os.path.basename(f) for f in self.encrypted_files]

            # 按文件名排序，以便列表更加一致
            filenames.sort()

            # 确保没有重复项
            unique_filenames = list(dict.fromkeys(filenames))

            self.file_combo['values'] = unique_filenames
            self.file_combo.current(0)  # 选择第一个文件
            self.file_combo.configure(state="readonly")
            self.status_var.set(f"找到 {len(unique_filenames)} 个可能的加密文件")

    def refresh_files(self):
        """刷新文件列表"""
        self.encrypted_files = self.scan_for_encrypted_files()
        self.update_file_list()

    def create_protection_on_startup(self):
        """在启动时就创建保存按钮区域阻挡窗口，并持续监视窗口位置变化"""
        global lb_printer_hwnd

        try:
            # 先设置监控系统（优先），确保即使找不到窗口也能启动监控
            setup_window_monitoring()

            # 查找赢彩投注单打印助手窗口
            hwnd = find_window_by_title(LBPRINTER_WINDOW_TITLE)
            if hwnd:
                lb_printer_hwnd = hwnd

                # 获取窗口位置
                if 'win32gui' in globals():
                    left, top, right, bottom = win32gui.GetWindowRect(hwnd)

                    # 创建阻挡窗口（方案二 - Tkinter实现）
                    create_button_blocker_window(left, top)

                    # 创建透明覆盖窗口（方案一 - Win32实现）
                    if 'create_overlay_window' in globals():
                        create_overlay_window(left, top)

                    self.status_var.set("已创建保存按钮区域阻挡窗口")
                    print(f"已创建保存按钮区域阻挡窗口，时间: {time.strftime('%H:%M:%S')}")
            else:
                # 如果未找到窗口，稍后再试
                print(
                    f"未找到赢彩投注单打印助手窗口，将在2秒后重试，时间: {time.strftime('%H:%M:%S')}")
                self.root.after(1000, self.create_protection_on_startup)
                return

            # 窗口创建成功后，设置持续监控窗口位置变化的定时器
            # 即使已经有setup_window_monitoring在工作，这里也多一层保障
            def check_window_position():
                try:
                    # 重新获取最新窗口句柄和位置
                    current_hwnd = find_window_by_title(LBPRINTER_WINDOW_TITLE)
                    if current_hwnd and 'win32gui' in globals():
                        left, top, right, bottom = win32gui.GetWindowRect(
                            current_hwnd)

                        # 更新全局窗口句柄
                        global lb_printer_hwnd
                        if lb_printer_hwnd != current_hwnd:
                            print(
                                f"窗口句柄变化: {lb_printer_hwnd} -> {current_hwnd}")
                            lb_printer_hwnd = current_hwnd

                        # 检查LBPrinter窗口是否是当前活动窗口
                        if is_window_active(current_hwnd):
                            print("LBPrinter窗口处于活动状态，创建或更新覆盖窗口")
                            # 更新覆盖窗口位置
                            create_button_blocker_window(left, top)
                            if 'create_overlay_window' in globals():
                                create_overlay_window(left, top)
                        else:
                            # 窗口不活动，可以选择不更新覆盖窗口以节省资源
                            pass
                except Exception as e:
                    print(f"窗口位置监控出错: {str(e)}")

                # 继续监控，每500毫秒检查一次窗口位置
                self.root.after(500, check_window_position)

            # 启动窗口位置监控（作为备份监控机制）
            self.root.after(2000, check_window_position)

        except Exception as e:
            print(f"创建保存按钮区域阻挡窗口出错: {str(e)}")
            # 出错后稍后再试
            self.root.after(1000, self.create_protection_on_startup)

    def copy_device_id(self):
        """复制设备ID到剪贴板"""
        try:
            pyperclip.copy(self.device_id)
            self.status_var.set("设备ID已复制到剪贴板")
            messagebox.showinfo("成功", "设备ID已复制到剪贴板!\n请将此ID发送给管理员添加到授权列表。")
        except Exception as e:
            self.status_var.set(f"复制失败: {str(e)}")
            messagebox.showerror("错误", f"复制设备ID时出错: {str(e)}")

    def decrypt_to_clipboard(self):
        """解密文件并将内容直接复制到剪贴板，成功后删除源文件并与投注单打印助手交互"""
        if not self.encrypted_files:
            messagebox.showwarning("警告", "没有找到可解密的文件")
            return

        # 获取用户选择的文件名
        selected_filename = self.file_var.get()
        if not selected_filename:
            messagebox.showwarning("警告", "请选择要解密的文件")
            return

        # 获取完整路径
        full_path = None
        for file in self.encrypted_files:
            if os.path.basename(file) == selected_filename:
                full_path = file
                break

        if not full_path:
            messagebox.showerror("错误", "无法找到选定的文件")
            return

        # 从文件名提取标识符（仅用于显示，不影响解密）
        identifier = extract_identifier_from_file(full_path)

        try:
            # 显示解密中状态
            self.status_var.set(f"正在解密 {selected_filename}...")
            self.root.update()

            # 执行解密，成功后会自动删除源文件
            decrypted_content = decrypt_file_to_text(full_path, identifier)

            if decrypted_content:
                # 将解密内容复制到剪贴板
                pyperclip.copy(decrypted_content)
                self.status_var.set("解密成功，内容已复制到剪贴板!")

                # 刷新文件列表，以便从UI中移除已删除的文件
                self.refresh_files()

                # 与赢彩投注单打印助手交互
                interaction_thread = threading.Thread(
                    target=lambda: handle_decrypt_success(decrypted_content),
                    daemon=True)
                interaction_thread.start()

                messagebox.showinfo(
                    "成功", "文件解密成功!\n"
                    "内容已复制到剪贴板，正在将内容粘贴到赢彩投注单打印助手。\n"
                    "源文件已删除。\n\n"
                    "注意：\n"
                    "- 禁止使用Ctrl+S保存\n"
                    "- 禁止点击左上角带软盘图标的'保存号码'按钮\n"
                    "违反上述规则将导致打印助手程序被强制关闭!")
            else:
                self.status_var.set("解密失败")
                messagebox.showerror(
                    "错误", "解密失败!\n\n"
                    "可能原因:\n"
                    "1. 当前设备ID不正确\n"
                    "2. 文件格式不正确\n\n"
                    "解决方法:\n"
                    "请使用「复制设备ID」按钮，将您的设备ID发送给管理员，请求确认设备ID是否有效。")
        except Exception as e:
            self.status_var.set(f"解密过程中出错: {str(e)}")
            messagebox.showerror("错误", f"解密过程中出错:\n{str(e)}")


# 辅助函数部分


def get_device_id():
    """获取或生成设备唯一标识符"""
    # 如果配置目录不存在，创建它
    if not os.path.exists(DEVICE_CONFIG_DIR):
        os.makedirs(DEVICE_CONFIG_DIR)

    # 检查是否已有设备ID
    if os.path.exists(DEVICE_CONFIG_FILE):
        try:
            with open(DEVICE_CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return config.get('device_id')
        except:
            pass

    # 生成新的设备ID
    system_info = platform.system() + platform.version() + platform.machine()
    try:
        hostname = socket.gethostname()
        ip_addr = socket.gethostbyname(hostname)
    except:
        hostname = "unknown"
        ip_addr = "0.0.0.0"

    username = getpass.getuser()

    # 组合信息生成唯一ID
    device_info = f"{system_info}|{hostname}|{ip_addr}|{username}|{uuid.uuid4()}"
    device_id = hashlib.sha256(device_info.encode()).hexdigest()

    # 保存设备ID到配置文件
    try:
        with open(DEVICE_CONFIG_FILE, 'w') as f:
            json.dump({'device_id': device_id}, f)
    except Exception as e:
        print(f"保存设备ID失败: {str(e)}")

    return device_id


def extract_identifier_from_file(filepath):
    """
    从文件名提取标识符
    标识符是文件名第一个下划线前的中文字符
    例如: 红_W15_金额1600元_56张_加密.txt 中的 "红"
    """
    # 获取文件名
    filename = os.path.basename(filepath)
    print(f"从文件名中提取标识符: {filename}")

    try:
        # 专门匹配文件名第一个下划线前的内容作为标识符
        prefix_pattern = re.compile(r'^([^_]+)_')
        prefix_match = prefix_pattern.search(filename)

        if prefix_match:
            prefix = prefix_match.group(1)
            # 判断是否是中文字符
            if len(prefix) == 1 and '\u4e00' <= prefix <= '\u9fff':
                print(f"找到标识符: {prefix}")
                return prefix
            # 如果前缀包含中文，提取第一个中文字符
            chinese_pattern = re.compile(r'([\u4e00-\u9fff])')
            chinese_match = chinese_pattern.search(prefix)
            if chinese_match:
                chinese_char = chinese_match.group(1)
                print(f"从前缀中提取中文标识符: {chinese_char}")
                return chinese_char

        # 尝试直接匹配以中文字符开头的文件名
        first_char_pattern = re.compile(r'^([\u4e00-\u9fff])')
        first_char_match = first_char_pattern.search(filename)
        if first_char_match:
            chinese_char = first_char_match.group(1)
            print(f"从文件名开头提取中文标识符: {chinese_char}")
            return chinese_char

        # 尝试从文件名中提取任意中文字符作为标识符
        any_chinese_pattern = re.compile(r'([\u4e00-\u9fff])')
        any_chinese_match = any_chinese_pattern.search(filename)
        if any_chinese_match:
            chinese_char = any_chinese_match.group(1)
            print(f"从文件名中提取任意中文字符: {chinese_char}")
            return chinese_char

    except Exception as e:
        print(f"提取标识符时出错: {str(e)}")

    print(f"无法从文件名 '{filename}' 中提取标识符")
    return ""


def get_encryption_key(identifier=None, device_id=None):
    """
    根据提供的密钥源生成加密密钥

    参数:
        identifier: 标识符（旧版本兼容）
        device_id: 设备ID或其他密钥源字符串

    返回:
        加密密钥
    """
    # 确定使用哪个参数作为密钥源
    key_source = device_id if device_id is not None else identifier

    # 如果两个参数都为空，使用当前设备ID
    if key_source is None:
        key_source = get_device_id()

    # 将密钥源转换为字节
    key_bytes = key_source.encode()

    # 使用PBKDF2生成加密密钥
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
    return key


def get_file_hash(filepath):
    """计算文件哈希值以跟踪解密历史"""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def has_been_decrypted(file_hash):
    """检查文件是否已被解密过"""
    if not os.path.exists(DECRYPT_HISTORY_FILE):
        return False

    try:
        with open(DECRYPT_HISTORY_FILE, 'r') as f:
            history = json.load(f)
            return file_hash in history.get('decrypted_files', [])
    except:
        return False


def mark_as_decrypted(file_hash):
    """将文件标记为已解密"""
    history = {'decrypted_files': []}

    if os.path.exists(DECRYPT_HISTORY_FILE):
        try:
            with open(DECRYPT_HISTORY_FILE, 'r') as f:
                history = json.load(f)
        except:
            pass

    if 'decrypted_files' not in history:
        history['decrypted_files'] = []

    history['decrypted_files'].append(file_hash)

    try:
        with open(DECRYPT_HISTORY_FILE, 'w') as f:
            json.dump(history, f)
    except Exception as e:
        print(f"保存解密历史记录失败: {str(e)}")


def extract_metadata(encrypted_data):
    """从加密数据中提取元数据"""
    try:
        if encrypted_data.startswith(b'METADATA:'):
            parts = encrypted_data.split(b':DATA:', 1)
            if len(parts) == 2:
                metadata_part = parts[0][len(b'METADATA:'):]
                actual_data = parts[1]

                metadata_json = base64.b64decode(metadata_part).decode('utf-8')
                metadata = json.loads(metadata_json)
                return metadata, actual_data
    except Exception as e:
        print(f"提取元数据失败: {str(e)}")

    return None, encrypted_data


def decrypt_file_to_text(filepath, identifier, delete_source=True):
    """
    解密文件并返回文本内容，而不是写入文件
    如果解密失败返回None

    参数:
        filepath: 加密文件路径
        identifier: 标识符
        delete_source: 解密成功后是否删除源文件，默认为True

    返回:
        解密成功返回文本内容，失败返回None

    成功解密后还将：
    1. 查找并激活"赢彩投注单打印助手"窗口
    2. 粘贴解密内容
    3. 清空剪贴板
    4. 监控是否有按Ctrl+S或点击"保存号码"按钮的行为
    """
    try:
        # 获取当前设备ID
        current_device_id = get_device_id()
        print(f"当前设备ID: {current_device_id[:8]}...{current_device_id[-8:]}")

        # 标识符现在只用于日志显示，不用于加密
        if identifier:
            print(f"提取到标识符: '{identifier}'（仅用于显示）")

        # 读取加密文件内容
        with open(filepath, 'rb') as file:
            encrypted_data = file.read()

        # 提取元数据和加密数据
        metadata, actual_encrypted_data = extract_metadata(encrypted_data)

        # 检查当前设备ID是否在授权设备列表中
        if metadata and 'device_ids' in metadata:
            device_ids = metadata.get('device_ids', [])
            if device_ids and current_device_id not in device_ids:
                print(f"设备ID {current_device_id[:8]}... 不在授权列表中，无法解密")
                return None

        # 解密策略
        decryption_strategies = []

        # 策略1: 优先使用元数据中的共享密钥源（新版加密方式）
        if metadata and 'key_source' in metadata:
            key_source = metadata.get('key_source')
            if key_source:
                decryption_strategies.append(('共享密钥', key_source))

        # 策略2: 如果有设备列表且当前设备在列表中，尝试用第一个设备ID解密（旧版兼容）
        if metadata and 'device_ids' in metadata:
            device_ids = metadata.get('device_ids', [])
            if current_device_id in device_ids and device_ids:
                decryption_strategies.append(('第一个设备ID', device_ids[0]))

        # 策略3: 尝试使用当前设备ID直接解密（旧版兼容）
        decryption_strategies.append(('当前设备ID', current_device_id))

        # 策略4: 尝试使用标识符解密（最早版本兼容）
        if metadata and 'identifier' in metadata and not identifier:
            identifier = metadata.get('identifier')
        if identifier:
            decryption_strategies.append(('标识符', identifier[0]))

        # 尝试所有解密策略
        for strategy_name, key_source in decryption_strategies:
            try:
                print(f"尝试使用{strategy_name}解密...")
                key = get_encryption_key(device_id=key_source)
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(actual_encrypted_data)

                # 尝试将二进制数据转换为文本
                try:
                    decrypted_text = decrypted_data.decode('utf-8')
                except UnicodeDecodeError:
                    # 如果不是文本，尝试使用其他常见编码
                    for encoding in ['gbk', 'gb2312', 'gb18030', 'latin1']:
                        try:
                            decrypted_text = decrypted_data.decode(encoding)
                            break
                        except UnicodeDecodeError:
                            continue
                    else:
                        # 如果所有尝试都失败，继续下一个策略
                        print("解密的数据不是文本格式，尝试下一个策略")
                        continue

                print(f"使用{strategy_name}解密成功!")

                # 解密成功后删除源文件
                if delete_source:
                    try:
                        os.remove(filepath)
                        print(f"源文件 {filepath} 已删除")
                    except Exception as e:
                        print(f"删除源文件失败: {str(e)}")

                return decrypted_text

            except Exception as e:
                print(f"使用{strategy_name}解密失败: {type(e).__name__}")
                continue

        # 所有策略都失败
        print("所有解密策略都失败了")
        return None

    except Exception as e:
        print(f"解密过程出错: {str(e)}")
        return None


# Windows窗口管理和进程控制相关的功能函数
def find_window_by_title(title_part):
    """查找包含指定标题部分的窗口，返回窗口句柄"""
    result = []

    def enum_windows_callback(hwnd, results):
        if win32gui.IsWindowVisible(hwnd):
            window_title = win32gui.GetWindowText(hwnd)
            if title_part.lower() in window_title.lower():
                results.append(hwnd)
        return True

    try:
        win32gui.EnumWindows(enum_windows_callback, result)
    except Exception as e:
        print(f"查找窗口时出错: {str(e)}")

    return result[0] if result else None


def is_window_active(hwnd):
    """检查指定句柄的窗口是否为活动窗口（当前焦点窗口）"""
    if not hwnd:
        return False

    try:
        # 获取当前活动窗口句柄
        foreground_hwnd = win32gui.GetForegroundWindow()

        # 判断是否是同一个窗口
        return foreground_hwnd == hwnd
    except Exception as e:
        print(f"检查窗口活动状态出错: {str(e)}")
        return False


def find_lbprinter_process():
    """查找LBPrinter进程，返回进程ID列表"""
    process_ids = []
    try:
        # 使用subprocess调用tasklist来查找进程
        output = subprocess.check_output(
            ['tasklist', '/FI', f'IMAGENAME eq {LBPRINTER_PROCESS_NAME}'],
            shell=True,
            universal_newlines=True)

        # 解析输出查找进程ID
        for line in output.split('\n'):
            if LBPRINTER_PROCESS_NAME in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                        process_ids.append(pid)
                    except ValueError:
                        pass
    except Exception as e:
        print(f"查找进程时出错: {str(e)}")

    return process_ids


def activate_lbprinter_window():
    """查找并激活赢彩投注单打印助手窗口，返回窗口句柄"""
    global lb_printer_hwnd, is_first_activation

    try:
        # 尝试查找现有窗口
        hwnd = find_window_by_title(LBPRINTER_WINDOW_TITLE)

        if hwnd:
            # 将窗口置于前台
            try:
                # 尝试不同的方法确保窗口被激活
                if is_first_activation:
                    # 第一次激活时，使用鼠标左键单击窗口
                    left, top, right, bottom = win32gui.GetWindowRect(hwnd)
                    center_x = (left + right) // 2
                    center_y = (top + bottom) // 2
                    # 移动鼠标到窗口中心并点击
                    win32api.SetCursorPos((center_x, center_y))
                    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0,
                                         0, 0)
                    time.sleep(0.1)
                    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0,
                                         0)
                    is_first_activation = False

                    # 在第一次激活窗口后创建保存按钮区域的覆盖窗口
                    create_overlay_window(left, top)

                # 常规激活方式
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                win32gui.SetForegroundWindow(hwnd)
                time.sleep(0.2)  # 稍微等待激活完成

                print(f"成功激活{LBPRINTER_WINDOW_TITLE}窗口")
                lb_printer_hwnd = hwnd
                return hwnd
            except Exception as e:
                print(f"激活窗口时出错: {str(e)}")
        else:
            print(f"未找到{LBPRINTER_WINDOW_TITLE}窗口")
    except Exception as e:
        print(f"查找/激活窗口过程中出错: {str(e)}")

    return None


def paste_text_to_lbprinter():
    """粘贴文本到LBPrinter.exe窗口"""
    try:
        # 确保LBPrinter窗口在前台
        hwnd = activate_lbprinter_window()
        if hwnd:
            # 粘贴快捷键Ctrl+V
            win32api.keybd_event(win32con.VK_CONTROL, 0, 0, 0)  # Ctrl键按下
            win32api.keybd_event(ord('V'), 0, 0, 0)  # V键按下
            time.sleep(0.1)
            win32api.keybd_event(ord('V'), 0, win32con.KEYEVENTF_KEYUP,
                                 0)  # V键抬起
            win32api.keybd_event(win32con.VK_CONTROL, 0,
                                 win32con.KEYEVENTF_KEYUP, 0)  # Ctrl键抬起
            print("成功粘贴内容到LBPrinter窗口")
            return True
    except Exception as e:
        print(f"粘贴文本到LBPrinter时出错: {str(e)}")

    return False


def clear_clipboard():
    """清空剪贴板"""
    try:
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.CloseClipboard()
        print("成功清空剪贴板")
        return True
    except Exception as e:
        print(f"清空剪贴板时出错: {str(e)}")
        return False


def is_save_button_region(x, y):
    """检查坐标是否在保存按钮区域内"""
    if not lb_printer_hwnd:
        return False

    try:
        # 获取窗口位置
        left, top, right, bottom = win32gui.GetWindowRect(lb_printer_hwnd)

        # 使用全局配置的保存按钮区域
        save_btn_left = left + SAVE_BUTTON['offset_left']
        save_btn_top = top + SAVE_BUTTON['offset_top']
        save_btn_right = save_btn_left + SAVE_BUTTON['width']
        save_btn_bottom = save_btn_top + SAVE_BUTTON['height']

        # 打印按钮区域信息，用于用户调整
        print("\n" + "=" * 50)
        print("保存按钮区域位置:")
        print(f"左上角: ({save_btn_left}, {save_btn_top})")
        print(f"右上角: ({save_btn_right}, {save_btn_top})")
        print(f"左下角: ({save_btn_left}, {save_btn_bottom})")
        print(f"右下角: ({save_btn_right}, {save_btn_bottom})")
        print(f"窗口位置: 左={left}, 上={top}, 右={right}, 下={bottom}")
        print("=" * 50 + "\n")

        # 尝试使用其他方法在窗口中显示标记，使用更简单的方式替代SetPixel
        try:
            # 获取窗口句柄，尝试其他方式显示标记
            # 这里我们可以尝试在控制台或状态栏中显示信息，而不是直接在窗口上绘制
            # 在实际应用中，用户可以根据控制台输出的坐标来调整配置
            pass
        except Exception as e:
            print(f"标记保存按钮区域时出错: {str(e)}")

        # 判断点击位置是否在保存按钮区域内
        if (save_btn_left <= x <= save_btn_right
                and save_btn_top <= y <= save_btn_bottom):
            print(
                f"检测到点击保存按钮区域: ({x}, {y}) - 位于按钮边界: [{save_btn_left}, {save_btn_top}, {save_btn_right}, {save_btn_bottom}]"
            )
            return True
    except Exception as e:
        print(f"检查保存按钮区域时出错: {str(e)}")

    return False


# 保存所有创建的覆盖窗口句柄
overlay_windows = {}


def create_overlay_window(parent_left, parent_top):
    """创建或更新透明覆盖窗口，覆盖保存按钮区域"""
    global overlay_windows

    try:
        if 'win32gui' not in globals() or 'win32con' not in globals():
            print("无法创建覆盖窗口：缺少必要的win32gui或win32con模块")
            return None

        # 使用全局配置的保存按钮区域
        overlay_left = parent_left + SAVE_BUTTON['offset_left']
        overlay_top = parent_top + SAVE_BUTTON['offset_top']
        overlay_width = SAVE_BUTTON['width']
        overlay_height = SAVE_BUTTON['height']

        # 窗口标识（使用父窗口位置作为唯一标识符）
        position_id = f"{parent_left}_{parent_top}"

        # 检查已存在的窗口
        if position_id in overlay_windows and overlay_windows[position_id]:
            try:
                # 尝试更新现有窗口位置
                hwnd = overlay_windows[position_id]
                if win32gui.IsWindow(hwnd):
                    # 移动窗口到新位置
                    win32gui.MoveWindow(hwnd, overlay_left, overlay_top,
                                        overlay_width, overlay_height, True)
                    # 确保窗口仍然置顶
                    win32gui.SetWindowPos(
                        hwnd, win32con.HWND_TOPMOST, 0, 0, 0, 0,
                        win32con.SWP_NOMOVE | win32con.SWP_NOSIZE)
                    # 刷新窗口
                    win32gui.UpdateWindow(hwnd)

                    print(f"已更新透明覆盖窗口: 位置=({overlay_left}, {overlay_top})")
                    return hwnd
                else:
                    # 窗口已无效，需要创建新窗口
                    del overlay_windows[position_id]
            except Exception as update_error:
                print(f"更新透明覆盖窗口出错: {str(update_error)}")
                try:
                    del overlay_windows[position_id]
                except:
                    pass

        # 清理旧窗口（针对不同位置的窗口）
        for old_id, old_hwnd in list(overlay_windows.items()):
            try:
                if old_id != position_id and win32gui.IsWindow(old_hwnd):
                    win32gui.DestroyWindow(old_hwnd)
                    print(f"关闭旧的透明覆盖窗口: {old_id}")
                    del overlay_windows[old_id]
            except Exception:
                pass

        # 创建一个新的透明覆盖窗口
        overlay_hwnd = win32gui.CreateWindowEx(
            win32con.WS_EX_LAYERED | win32con.WS_EX_TRANSPARENT
            | win32con.WS_EX_TOPMOST,
            "Static",  # 使用静态控件类
            None,  # 无窗口标题
            win32con.WS_POPUP,  # 弹出式窗口，无边框
            overlay_left,
            overlay_top,
            overlay_width,
            overlay_height,
            None,
            None,
            None,
            None)

        # 设置窗口透明度（完全透明但可拦截鼠标）
        win32gui.SetLayeredWindowAttributes(
            overlay_hwnd,
            0,
            1,  # 几乎完全透明
            win32con.LWA_ALPHA)

        # 显示覆盖窗口
        win32gui.ShowWindow(overlay_hwnd, win32con.SW_SHOW)
        win32gui.UpdateWindow(overlay_hwnd)

        # 保存窗口句柄到字典
        overlay_windows[position_id] = overlay_hwnd

        print(
            f"已创建透明覆盖窗口: 位置=({overlay_left}, {overlay_top}, {overlay_left+overlay_width}, {overlay_top+overlay_height})"
        )
        return overlay_hwnd
    except Exception as e:
        print(f"创建透明覆盖窗口出错: {str(e)}")
        return None


def terminate_lbprinter():
    """终止LBPrinter.exe进程，成功终止后退出程序"""
    try:
        process_ids = find_lbprinter_process()
        if process_ids:
            for pid in process_ids:
                subprocess.call(['taskkill', '/F', '/PID',
                                 str(pid)],
                                shell=True)
            print(f"已终止 {LBPRINTER_PROCESS_NAME} 进程")
            print("检测到保存操作，已终止打印助手进程，程序将退出...")
            messagebox.showinfo("程序将退出", 
                               "检测到您尝试保存文件，已终止打印助手进程。\n解密工具将自动退出。")
            print("程序即将退出...")
            # 延迟1秒后退出程序，确保消息框有时间显示
            time.sleep(1)
            # 强制退出程序
            os._exit(0)  # 使用os._exit代替sys.exit以确保立即退出
        else:
            print(f"未找到 {LBPRINTER_PROCESS_NAME} 进程")
    except Exception as e:
        print(f"终止进程时出错: {str(e)}")

    return False


def on_key_event(event):
    """处理键盘事件"""
    global lb_printer_hwnd

    # 检查LBPrinter窗口是否存在并且是当前焦点窗口
    if lb_printer_hwnd and is_window_active(lb_printer_hwnd):
        # 监控Ctrl+S组合键
        if event.name == 's' and keyboard.is_pressed('ctrl'):
            print("检测到按下Ctrl+S，禁止保存操作")
            
            # 直接在此处终止LBPrinter进程并退出程序，而不调用terminate_lbprinter函数
            print("检测到按下Ctrl+S，正在终止打印助手进程并退出程序...")
            process_ids = find_lbprinter_process()
            if process_ids:
                for pid in process_ids:
                    subprocess.call(['taskkill', '/F', '/PID', str(pid)], shell=True)
                print(f"已终止 {LBPRINTER_PROCESS_NAME} 进程")
                print("程序即将退出...")
                messagebox.showinfo("程序将退出", 
                                   "检测到您尝试使用快捷键保存文件，已终止打印助手进程。\n解密工具将自动退出。")
                # 延迟1秒后退出程序，确保消息框有时间显示
                time.sleep(1)
                # 强制退出程序
                os._exit(0)
                
            # 阻止原有事件继续传播
            return False
    else:
        # 如果LBPrinter窗口不是当前焦点窗口，不做任何拦截
        pass


def on_mouse_click(event):
    """处理鼠标点击事件"""
    global lb_printer_hwnd

    try:
        # 获取当前鼠标点击所在的窗口句柄
        if 'win32gui' in globals():
            mouse_x, mouse_y = win32api.GetCursorPos()
            clicked_hwnd = win32gui.WindowFromPoint((mouse_x, mouse_y))

            # 检查是否点击的是赢彩投注单打印助手窗口
            window_text = win32gui.GetWindowText(clicked_hwnd)

            if LBPRINTER_WINDOW_TITLE in window_text or clicked_hwnd == lb_printer_hwnd:
                print(
                    f"检测到鼠标点击事件，坐标: ({mouse_x}, {mouse_y})，窗口标题: {window_text}"
                )

                # 更新打印助手窗口句柄（可能会变）
                lb_printer_hwnd = clicked_hwnd

                # 检查窗口是否是当前焦点窗口
                if is_window_active(clicked_hwnd):
                    print("LBPrinter窗口处于活动状态，检查点击区域")

                    # 转换为窗口内部坐标
                    left, top, right, bottom = win32gui.GetWindowRect(
                        lb_printer_hwnd)
                    client_x = mouse_x - left
                    client_y = mouse_y - top

                    # 如果点击了保存按钮区域
                    if is_save_button_region(client_x, client_y):
                        print(f"检测到点击保存按钮区域: 窗口内坐标 ({client_x}, {client_y})")
                        messagebox.showwarning(
                            "安全警告", "检测到点击保存按钮区域，为保护数据安全将关闭打印助手程序!")
                        
                        # 直接在此处终止LBPrinter进程并退出程序，而不调用terminate_lbprinter函数
                        print("检测到点击保存按钮，正在终止打印助手进程并退出程序...")
                        process_ids = find_lbprinter_process()
                        if process_ids:
                            for pid in process_ids:
                                subprocess.call(['taskkill', '/F', '/PID', str(pid)], shell=True)
                            print(f"已终止 {LBPRINTER_PROCESS_NAME} 进程")
                            print("程序即将退出...")
                            messagebox.showinfo("程序将退出", 
                                               "检测到您尝试保存文件，已终止打印助手进程。\n解密工具将自动退出。")
                            # 延迟1秒后退出程序，确保消息框有时间显示
                            time.sleep(1)
                            # 强制退出程序
                            os._exit(0)
                        # 阻止原有事件继续传播
                        return False
                else:
                    print("LBPrinter窗口不是当前活动窗口，不处理点击事件")
    except Exception as e:
        print(f"处理鼠标点击事件时出错: {str(e)}")

    return True


def setup_window_monitoring():
    """设置窗口监控"""
    global is_monitoring, lb_printer_hwnd

    if is_monitoring:
        return  # 如果已经在监控中，则不重复设置

    try:
        # 设置键盘钩子监听Ctrl+S
        if 'keyboard' in globals():
            keyboard.hook(on_key_event)

        # 保存窗口上一次的位置，用于检测窗口移动
        last_window_rect = None
        last_hwnd = None
        last_blocker_update_time = 0

        # 设置定时器检查鼠标点击事件和窗口位置变化
        def check_events():
            if not is_monitoring:
                return

            nonlocal last_window_rect, last_hwnd, last_blocker_update_time

            try:
                # 1. 每次都重新查找打印助手窗口，不依赖缓存的窗口句柄
                current_hwnd = find_window_by_title(LBPRINTER_WINDOW_TITLE)
                if current_hwnd:
                    # 如果找到了窗口，更新全局句柄变量
                    global lb_printer_hwnd
                    lb_printer_hwnd = current_hwnd

                    # 如果窗口句柄发生变化，记录日志
                    if last_hwnd != current_hwnd:
                        print(f"窗口句柄变化: {last_hwnd} -> {current_hwnd}")
                        last_hwnd = current_hwnd
                        # 窗口句柄变化时强制更新窗口位置
                        last_window_rect = None

                    # 2. 检查窗口位置是否变化
                    current_time = time.time()
                    try:
                        if 'win32gui' in globals():
                            current_rect = win32gui.GetWindowRect(current_hwnd)

                            # 如果窗口位置变化了，或者是第一次检测（last_window_rect为None）
                            if current_rect != last_window_rect:
                                print(
                                    f"检测到窗口位置变化: {last_window_rect} -> {current_rect}"
                                )
                                # 通过时间限制更新频率，至少1秒更新一次
                                if last_window_rect is None or current_time - last_blocker_update_time > 1:
                                    left, top, right, bottom = current_rect

                                    # 检查窗口是否处于活动状态
                                    if is_window_active(current_hwnd):
                                        # 窗口处于活动状态，调用全局函数更新阻挡窗口位置
                                        try:
                                            print(f"LBPrinter窗口处于活动状态，更新覆盖窗口")
                                            create_button_blocker_window(
                                                left, top)

                                            # 确保create_overlay_window存在
                                            if 'create_overlay_window' in globals(
                                            ):
                                                create_overlay_window(
                                                    left, top)

                                            print(
                                                f"已更新覆盖窗口位置：({left}, {top}) 时间: {time.strftime('%H:%M:%S')}"
                                            )
                                            last_blocker_update_time = current_time
                                        except Exception as update_error:
                                            print(
                                                f"更新覆盖窗口位置出错: {str(update_error)}"
                                            )
                                    else:
                                        # 窗口不处于活动状态，无需更新覆盖窗口
                                        print(f"LBPrinter窗口未处于活动状态，跳过覆盖窗口更新")
                                        last_blocker_update_time = current_time  # 更新时间戳，避免频繁检查

                                # 不论是否更新覆盖窗口，都记录最新的窗口位置
                                last_window_rect = current_rect
                    except Exception as rect_error:
                        print(f"获取窗口位置时出错: {str(rect_error)}")
                else:
                    # 如果没找到窗口，定期尝试重新查找
                    current_time = time.time()  # 获取当前时间
                    if current_time - last_blocker_update_time > 5:  # 每5秒尝试一次
                        print(
                            f"未找到赢彩投注单打印助手窗口，将继续查找... 时间: {time.strftime('%H:%M:%S')}"
                        )
                        last_blocker_update_time = current_time

                # 3. 获取鼠标当前位置检测点击
                if 'win32api' in globals():
                    mouse_x, mouse_y = win32api.GetCursorPos()
                    pressed_left = win32api.GetAsyncKeyState(
                        0x01) & 0x8000 != 0  # 检查左键是否按下

                    # 如果左键被按下
                    if pressed_left:
                        # 创建一个模拟的事件对象
                        class MouseEvent:

                            def __init__(self, x, y):
                                self.x = x
                                self.y = y

                        # 处理点击事件
                        on_mouse_click(MouseEvent(mouse_x, mouse_y))
            except Exception as e:
                print(f"检查事件时出错: {str(e)}")

            # 继续循环监控，使用更激进的时间间隔以获得更快的响应速度
            if is_monitoring:
                # 每10毫秒检查一次，大幅提高响应速度
                threading.Timer(0.01, check_events).start()

        # 启动事件监控
        check_events()

        is_monitoring = True
        print("成功设置窗口和鼠标监控（带窗口位置变化检测增强版）")
    except Exception as e:
        print(f"设置窗口监控时出错: {str(e)}")


# 使用全局变量保存阻挡窗口对象
blocker_windows = {}


def create_button_blocker_window(parent_left, parent_top):
    """创建或更新悬浮窗口覆盖保存按钮区域，使用Tkinter实现"""
    global blocker_windows

    try:
        # 使用全局配置的保存按钮区域
        overlay_left = parent_left + SAVE_BUTTON['offset_left']
        overlay_top = parent_top + SAVE_BUTTON['offset_top']
        overlay_width = SAVE_BUTTON['width']
        overlay_height = SAVE_BUTTON['height']

        # 为了更快速响应，直接使用当前时间作为窗口的唯一标识符
        # 这样每次都会创建新窗口并关闭旧窗口，避免了更新窗口可能带来的延迟
        timestamp = int(time.time() * 1000)  # 毫秒级时间戳
        position_id = f"{timestamp}_{parent_left}_{parent_top}"

        # 关闭所有之前的阻挡窗口
        for old_id, old_blocker in list(blocker_windows.items()):
            try:
                if old_blocker:
                    old_blocker.destroy()
                    print(f"关闭旧的阻挡窗口: {old_id}")
            except Exception:
                pass
        # 清空窗口字典
        blocker_windows.clear()

        # 创建一个新的置顶小窗口
        blocker = tk.Toplevel()
        blocker.overrideredirect(True)  # 无边框
        blocker.attributes('-topmost', True)  # 置顶
        blocker.geometry(
            f"{overlay_width}x{overlay_height}+{overlay_left}+{overlay_top}")

        # 窗口标题（仅代码中可见）
        blocker.title("按钮阻挡窗口")

        # 让窗口半透明但可点击，使用红色背景便于调试
        blocker.attributes('-alpha', 0.1)  # 透明度

        # 添加一个标签显示提示信息
        label = tk.Label(blocker, bg="black")

        # 阻止所有鼠标点击事件向下传递
        def block_click(event):
            print(f"阻挡了保存按钮区域的点击: ({event.x}, {event.y})")
            messagebox.showwarning("安全警告", "禁止使用保存按钮!")
            # 终止LBPrinter进程并立即退出程序
            print("检测到点击保存按钮，将终止打印助手进程并退出程序...")
            process_ids = find_lbprinter_process()
            if process_ids:
                for pid in process_ids:
                    subprocess.call(['taskkill', '/F', '/PID', str(pid)], shell=True)
                print(f"已终止 {LBPRINTER_PROCESS_NAME} 进程")
                print("程序即将退出...")
                messagebox.showinfo("程序将退出", 
                                   "检测到您尝试保存文件，已终止打印助手进程。\n解密工具将自动退出。")
                # 延迟1秒后退出程序，确保消息框有时间显示
                time.sleep(1)
                # 强制退出程序
                os._exit(0)
            return "break"  # 阻止事件传递

        label.bind("<Button-1>", block_click)

        # 保存到窗口字典
        blocker_windows[position_id] = blocker

        print(
            f"已创建Tkinter保存按钮阻挡窗口: 位置=({overlay_left}, {overlay_top}, {overlay_left+overlay_width}, {overlay_top+overlay_height})"
        )
        return blocker
    except Exception as e:
        print(f"创建Tkinter阻挡窗口出错: {str(e)}")
        return None


def handle_decrypt_success(decrypted_text):
    """处理解密成功后的操作"""
    try:
        # 1. 查找并激活赢彩投注单打印助手窗口
        if activate_lbprinter_window():
            # 2. 等待一小段时间确保窗口已激活
            time.sleep(0.5)

            # 3. 粘贴内容到活动窗口
            paste_text_to_lbprinter()

            # 4. 清空剪贴板防止二次粘贴
            clear_clipboard()

            # 5. 设置监控，防止非法操作
            setup_window_monitoring()

            # 6. 创建Tkinter阻挡窗口（方案二）
            if lb_printer_hwnd:
                left, top, right, bottom = win32gui.GetWindowRect(
                    lb_printer_hwnd)
                create_button_blocker_window(left, top)

            return True
    except Exception as e:
        print(f"处理解密成功后的操作时出错: {str(e)}")

    return False


def prevent_window_close(root):
    """阻止关闭窗口"""

    def on_closing():
        # 如果找到了LBPrinter进程，则终止它
        if find_lbprinter_process():
            terminate_lbprinter()
            messagebox.showinfo("提示", "解密软件关闭，相关进程已终止")
            root.destroy()
        else:
            # 没有LBPrinter进程时允许正常关闭
            root.destroy()

    # 绑定窗口关闭事件
    root.protocol("WM_DELETE_WINDOW", on_closing)


def find_and_terminate_previous_instance():
    """查找并终止之前运行的解密工具实例"""
    try:
        process_name = os.path.basename(sys.executable)
        if process_name.lower() == "python.exe" or process_name.lower() == "pythonw.exe":
            # 如果是以Python解释器运行的，则查找Python脚本名
            script_name = os.path.basename(sys.argv[0])
            process_name = script_name
        
        current_pid = os.getpid()
        
        if platform.system() == "Windows":
            # 使用tasklist查找相同名称的进程
            cmd = ['tasklist', '/FI', f'IMAGENAME eq {process_name}']
            output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
            
            # 解析输出找到进程ID
            for line in output.split('\n'):
                if process_name.lower() in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            pid = int(parts[1])
                            # 不终止当前进程
                            if pid != current_pid:
                                print(f"找到旧实例 (PID: {pid})，正在终止...")
                                subprocess.call(['taskkill', '/F', '/PID', str(pid)], shell=True)
                                return True
                        except (ValueError, IndexError):
                            pass
        else:
            # Linux/Mac系统使用ps和grep
            try:
                output = subprocess.check_output(
                    ['ps', '-ef'], 
                    universal_newlines=True
                )
                
                for line in output.split('\n'):
                    if process_name in line and str(current_pid) not in line:
                        parts = line.split()
                        if len(parts) > 1:
                            try:
                                pid = int(parts[1])
                                if pid != current_pid:
                                    print(f"找到旧实例 (PID: {pid})，正在终止...")
                                    os.kill(pid, 9)  # SIGKILL
                                    return True
                            except (ValueError, IndexError, ProcessLookupError):
                                pass
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
        
        return False
    except Exception as e:
        print(f"查找并终止旧实例出错: {str(e)}")
        return False

def check_single_instance():
    """检查程序是否已经有一个实例在运行，确保系统中只有一个解密程序
    如果发现有旧实例在运行，尝试终止它，并接管
    """
    # 首先尝试查找并终止旧实例
    old_instance_terminated = find_and_terminate_previous_instance()
    if old_instance_terminated:
        print("已终止旧实例，新实例将继续运行")
        time.sleep(0.5)  # 稍微等待，确保旧实例已完全终止
    
    try:
        # 创建一个全局互斥锁
        mutex_name = "SimpleDecryptTool_SingleInstance_Mutex"
        
        if platform.system() == "Windows":
            # Windows系统
            mutex = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
            last_error = ctypes.windll.kernel32.GetLastError()
            if last_error == 183:  # ERROR_ALREADY_EXISTS
                # 还有另一个实例，但已经尝试终止过旧实例，这可能是一个刚刚启动的新实例
                # 等待更长时间再尝试
                print("还有其他实例在运行，再等待一段时间...")
                time.sleep(1.5)
                
                # 再次尝试创建互斥锁
                mutex = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
                last_error = ctypes.windll.kernel32.GetLastError()
                if last_error == 183:
                    messagebox.showwarning("警告", "解密程序已在运行中！\n请使用已运行的实例来解密文件。")
                    return False
        else:
            # 其他系统(Linux/Mac)，使用简单的文件锁
            lock_file = "/tmp/simple_decrypt_tool.lock"
            try:
                with open(lock_file, 'w') as f:
                    import fcntl
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (IOError, ImportError):
                # 再次尝试终止旧实例
                if find_and_terminate_previous_instance():
                    time.sleep(1.5)
                    try:
                        with open(lock_file, 'w') as f:
                            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except (IOError, ImportError):
                        messagebox.showwarning("警告", "解密程序已在运行中！\n请使用已运行的实例来解密文件。")
                        return False
                else:
                    messagebox.showwarning("警告", "解密程序已在运行中！\n请使用已运行的实例来解密文件。")
                    return False
                
        return True
    except Exception as e:
        print(f"检查单实例失败: {str(e)}")
        # 出错时默认允许继续运行
        return True

def auto_decrypt_file():
    """自动识别和解密当前目录中的单个txt文件
    
    返回值:
        True: 解密成功
        False: 解密失败
        None: 没有找到文件或有多个文件，无法进行解密
    """
    # 获取程序所在目录
    current_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    
    # 查找所有txt文件
    txt_files = glob.glob(os.path.join(current_dir, "*.txt"))
    
    # 排除程序自身
    self_path = os.path.abspath(sys.argv[0])
    filtered_files = [f for f in txt_files if os.path.abspath(f) != self_path]
    
    # 如果没有文件，则显示错误信息并退出
    if len(filtered_files) == 0:
        messagebox.showerror("错误", "没有找到可解密的文件！\n请将需解密的txt文件放在同一目录下。")
        return None
    
    # 如果有多个文件，显示错误信息
    if len(filtered_files) > 1:
        filenames = [os.path.basename(f) for f in filtered_files]
        messagebox.showerror(
            "错误", 
            f"文件夹中存在多个txt文件，无法自动确定哪个是需要解密的文件。\n\n"
            f"请只保留一个需要解密的txt文件：\n"
            f"{', '.join(filenames)}"
        )
        return None
    
    # 文件只有一个，直接解密
    file_path = filtered_files[0]
    
    # 提取标识符
    identifier = extract_identifier_from_file(file_path)
    
    # 获取设备ID
    device_id = get_device_id()
    
    try:
        # 执行解密
        print(f"找到文件：{os.path.basename(file_path)}，正在解密...")
        decrypted_content = decrypt_file_to_text(file_path, identifier)
        
        if decrypted_content:
            # 复制到剪贴板
            pyperclip.copy(decrypted_content)
            print("解密成功! 内容已复制到剪贴板")
            
            # 与赢彩投注单打印助手交互
            handle_decrypt_success(decrypted_content)
            
            # 显示成功消息
            messagebox.showinfo(
                "解密成功", 
                "文件解密成功!\n"
                "内容已复制到剪贴板，正在将内容粘贴到赢彩投注单打印助手。\n"
                "源文件已删除。\n\n"
                "注意：\n"
                "- 禁止使用Ctrl+S保存\n"
                "- 禁止点击左上角带软盘图标的'保存号码'按钮\n"
                "违反上述规则将导致打印助手程序被强制关闭!\n\n"
                "程序将继续在后台运行，监控打印助手窗口。"
            )
            return True
        else:
            messagebox.showerror(
                "解密失败", 
                "解密失败！\n可能原因:\n1. 当前设备ID不正确\n2. 文件格式不正确\n\n"
                "程序将继续在后台运行，监控打印助手窗口。"
            )
            return False
    except Exception as e:
        messagebox.showerror(
            "错误", 
            f"解密过程中出错: {str(e)}\n\n"
            "程序将继续在后台运行，监控打印助手窗口。"
        )
        return False

def main():
    try:
        # 检查是否已有实例运行，如果有，则关闭旧实例
        # 这确保只有一个程序实例运行，但会接管旧实例的监控和遮挡任务
        if not check_single_instance():
            return
        
        # 启动窗口监控（确保能够监控打印助手窗口）
        setup_window_monitoring()
        
        # 创建一个隐藏窗口，用于持续控制保护机制
        tk_root = tk.Tk()
        tk_root.withdraw()  # 隐藏主窗口
        tk_root.title("解密工具监控实例")  # 设置窗口标题方便识别
        
        # 添加小图标到系统托盘，表示程序正在后台运行
        try:
            # 这里只是尝试设置图标，不影响主要功能
            if 'win32gui' in globals() and 'win32con' in globals():
                tk_root.iconbitmap("icon.ico") if os.path.exists("icon.ico") else None
        except Exception:
            pass  # 忽略图标设置错误
        
        # 尝试查找并保护打印助手窗口
        def initialize_protection():
            hwnd = find_window_by_title(LBPRINTER_WINDOW_TITLE)
            if hwnd:
                print(f"找到打印助手窗口，创建遮挡区域...")
                try:
                    if 'win32gui' in globals():
                        left, top, right, bottom = win32gui.GetWindowRect(hwnd)
                        # 创建按钮遮挡
                        create_button_blocker_window(left, top)
                        # 创建透明覆盖（如果有此功能）
                        if 'create_overlay_window' in globals():
                            create_overlay_window(left, top)
                except Exception as e:
                    print(f"创建遮挡区域时出错: {str(e)}")
            else:
                print("未找到赢彩投注单打印助手窗口，稍后再尝试...")
                # 1秒后再次尝试初始化保护
                tk_root.after(1000, initialize_protection)
        
        # 首次尝试初始化保护
        initialize_protection()
        
        # 设置持续监控窗口位置的定时器
        def monitor_window_position():
            try:
                current_hwnd = find_window_by_title(LBPRINTER_WINDOW_TITLE)
                if current_hwnd and 'win32gui' in globals():
                    left, top, right, bottom = win32gui.GetWindowRect(current_hwnd)
                    
                    # 更新全局窗口句柄
                    global lb_printer_hwnd
                    if lb_printer_hwnd != current_hwnd:
                        print(f"窗口句柄变化: {lb_printer_hwnd} -> {current_hwnd}")
                        lb_printer_hwnd = current_hwnd
                    
                    # 检查LBPrinter窗口是否是当前活动窗口
                    if is_window_active(current_hwnd):
                        print("LBPrinter窗口处于活动状态，更新覆盖窗口")
                        create_button_blocker_window(left, top)
                        if 'create_overlay_window' in globals():
                            create_overlay_window(left, top)
            except Exception as e:
                print(f"窗口位置监控出错: {str(e)}")
            
            # 继续监控，每500毫秒检查一次
            tk_root.after(500, monitor_window_position)
        
        # 启动窗口位置监控
        tk_root.after(1000, monitor_window_position)
        
        # 尝试自动解密当前目录中的单个txt文件
        def start_decryption():
            result = auto_decrypt_file()
            # 解密结果提示后，不退出程序，继续监控保存按钮
            if result is True:
                # 解密成功，在状态栏或控制台显示状态
                print("解密成功，继续监控打印助手窗口...")
                # 可以添加一个提示窗口，告诉用户程序将继续在后台运行
                messagebox.showinfo(
                    "解密成功 - 程序将继续运行", 
                    "文件解密成功！\n\n程序将继续在后台运行，监控打印助手窗口。\n\n"
                    "如需解密新文件，请再次双击程序，\n系统将自动关闭此实例并启动新实例。"
                )
            elif result is False:
                # 解密失败，告知用户但仍继续监控
                print("解密失败，继续监控打印助手窗口...")
                # 可以添加一个提示窗口
                messagebox.showinfo(
                    "解密失败 - 程序将继续运行", 
                    "文件解密失败，但程序将继续在后台运行。\n\n"
                    "如需重新尝试，请修正问题后再次双击程序，\n系统将自动关闭此实例并启动新实例。"
                )
        
        # 延迟1秒后开始解密，确保窗口监控已经启动
        tk_root.after(1000, start_decryption)
        
        # 启动主循环，这会使程序持续运行
        tk_root.mainloop()
        
    except Exception as e:
        # 捕获所有异常，确保能显示错误信息
        messagebox.showerror("程序错误", f"程序运行出错: {str(e)}")


if __name__ == "__main__":
    main()
