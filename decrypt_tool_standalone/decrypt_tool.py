#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
文件解密工具 - 独立版本

这个工具用于解密通过系统下载的加密文件。
用户需要提供正确的标识符和加密文件路径。

安全特性:
1. 设备绑定 - 解密工具绑定到特定设备，在其他设备上无法正常工作
2. 一次性解密 - 每个加密文件只能解密一次，防止多次共享

增强功能:
1. 文件拖放 - 支持直接拖放文件到程序界面
2. 自动提取标识符 - 自动从文件中提取标识符
3. 复制设备ID - 方便用户将设备ID发送给管理员进行注册
"""

import os
import sys
import argparse
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from encryptor import decrypt_file, get_device_id
import pyperclip  # 用于复制到剪贴板

# 判断是否可以导入TkinterDnD2（用于文件拖放）
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DRAG_DROP_SUPPORTED = True
except ImportError:
    DRAG_DROP_SUPPORTED = False
    print("警告: TkinterDnD2未安装，文件拖放功能将被禁用")
    print("可以使用 pip install tkinterdnd2 安装")

VERSION = "1.3.0"  # 版本1.3.0增加了多设备解密支持

def create_parser():
    """创建命令行参数解析器"""
    parser = argparse.ArgumentParser(description='文件解密工具')
    parser.add_argument('-i', '--identifier', help='用户标识符')
    parser.add_argument('-f', '--file', help='要解密的文件路径')
    parser.add_argument('-o', '--output', help='解密后的输出文件路径')
    parser.add_argument('-v', '--version', action='version', 
                       version=f'文件解密工具 v{VERSION}')
    parser.add_argument('-g', '--gui', action='store_true', 
                       help='启动图形用户界面')
    parser.add_argument('-c', '--copy-device-id', action='store_true',
                       help='复制当前设备ID到剪贴板')
    return parser

def get_default_output_filename(input_filename):
    """生成默认的输出文件名"""
    base, ext = os.path.splitext(input_filename)
    return f"{base}_decrypted{ext}"

def process_decrypt(identifier, file_path, output_path=None):
    """处理解密请求"""
    if not identifier:
        print("错误: 必须提供标识符")
        return False
    
    if not file_path or not os.path.exists(file_path):
        print(f"错误: 文件不存在 - {file_path}")
        return False
    
    # 如果没有指定输出路径，生成默认输出路径
    if not output_path:
        output_path = get_default_output_filename(file_path)
    
    # 显示安全信息
    device_id = get_device_id()
    device_id_short = device_id[:8] + "..." + device_id[-8:] if device_id else "未知"
    
    print("\n=== 文件解密工具 (安全版 v{}) ===".format(VERSION))
    print(f"设备ID: {device_id_short}")
    print("安全特性: 标识符绑定 + 设备授权 + 一次性解密限制")
    print("注意: 每个标识符可绑定多个授权设备ID，每个文件在每个设备上仅允许解密一次")
    print("=" * 40)
    
    # 解密确认
    confirm = input("\n确认要解密此文件吗? 每个设备只能成功解密一次 [y/N]: ").strip().lower()
    if confirm != 'y':
        print("操作已取消")
        return False
    
    # 执行解密
    print(f"\n正在解密文件: {file_path}")
    success = decrypt_file(file_path, output_path, identifier)
    
    if success:
        print(f"文件解密成功！保存至: {output_path}")
        return True
    else:
        print("\n文件解密失败！可能原因:")
        print(f"1. 当前设备ID不在标识符'{identifier}'的授权列表中")
        print("2. 文件已被此设备解密过")
        print("3. 文件首字符不是正确的标识符")
        print("\n解决方法:")
        print("1. 使用 -c 选项复制设备ID，发送给管理员添加到标识符授权设备列表中")
        print("2. 确保正确提取文件的首字符作为标识符")
        return False

def extract_identifier_from_file(filepath):
    """
    从文件名中提取标识符，标识符是文件名第一个下划线前的内容，且必须是一个中文字符
    
    参数:
        filepath (str): 文件路径
        
    返回:
        str: 提取到的标识符，如果无法提取则返回空字符串
    """
    # 导入必要的模块
    import re
    
    # 获取文件名
    filename = os.path.basename(filepath)
    print(f"正在提取文件标识符，文件名: {filename}")
    
    # 专门匹配标识符的规则：第一个下划线前的内容，且必须是中文字符
    try:
        # 标准格式：标识符_内容_金额XX元_XX张_加密.txt
        # 例如：红_W15_金额1600元_56张_加密.txt
        
        # 匹配文件名第一个下划线前的内容
        prefix_pattern = re.compile(r'^([^_]+)_')
        prefix_match = prefix_pattern.search(filename)
        
        if prefix_match:
            prefix = prefix_match.group(1)
            # 检查前缀是否是单个中文字符
            if len(prefix) == 1 and '\u4e00' <= prefix <= '\u9fff':
                print(f"从文件名提取到标识符: {prefix}")
                return prefix
            # 如果前缀包含中文字符，取第一个中文字符
            else:
                chinese_pattern = re.compile(r'([\u4e00-\u9fff])')
                chinese_match = chinese_pattern.search(prefix)
                if chinese_match:
                    chinese_char = chinese_match.group(1)
                    print(f"从文件名前缀中提取到中文标识符: {chinese_char}")
                    return chinese_char
        
        # 如果上面的匹配失败，尝试直接匹配以中文字符+下划线开头的模式
        zh_pattern = re.compile(r'^([\u4e00-\u9fff])_')
        zh_match = zh_pattern.search(filename)
        if zh_match:
            char = zh_match.group(1)
            print(f"从文件名开头提取到标识符: {char}")
            return char
                
    except Exception as e:
        print(f"从文件名中提取标识符失败: {str(e)}")
    
    # 如果标准提取方法失败，作为最后尝试，提取文件名中的第一个中文字符
    try:
        chinese_pattern = re.compile(r'([\u4e00-\u9fff])')
        chinese_match = chinese_pattern.search(filename)
        if chinese_match:
            chinese_char = chinese_match.group(1)
            print(f"从文件名中提取到中文标识符(备用方法): {chinese_char}")
            return chinese_char
    except Exception as e:
        print(f"使用备用方法提取标识符失败: {str(e)}")
    
    # 无法提取标识符，给出明确的错误信息
    print(f"错误: 无法从文件名 '{filename}' 中提取到中文标识符")
    print("文件名格式应为: 标识符_内容_金额XX元_XX张_加密.txt")
    print("示例: 红_W15_金额1600元_56张_加密.txt")
    print("其中的标识符'红'应为单个中文字符")
    return ""

class DecryptGUI:
    """解密工具图形用户界面"""
    def __init__(self, root):
        self.root = root
        self.root.title("文件解密工具 - 安全版")
        self.root.geometry("550x400")
        self.root.resizable(True, True)
        
        # 如果支持拖放功能，则启用
        if DRAG_DROP_SUPPORTED:
            try:
                # 启用文件拖放
                self.root.drop_target_register(DND_FILES)
                self.root.dnd_bind("<<Drop>>", self.on_drop)
            except Exception as e:
                print(f"配置拖放功能失败: {str(e)}")
        
        # 创建样式
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", background="#ccc")
        self.style.configure("TLabel", padding=6, font=('Helvetica', 10))
        self.style.configure("TEntry", padding=6)
        self.style.configure("Security.TLabel", foreground="darkgreen", font=('Helvetica', 9, 'italic'))
        self.style.configure("DeviceID.TLabel", foreground="navy", font=('Helvetica', 8))
        self.style.configure("Drag.TFrame", background="#f0f0f0", relief="groove")
        
        # 主框架
        self.main_frame = ttk.Frame(root, padding="20 20 20 20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_frame = ttk.Frame(self.main_frame)
        title_frame.pack(fill=tk.X)
        
        title_label = ttk.Label(title_frame, text="文件解密工具", font=('Helvetica', 16))
        title_label.pack(side=tk.LEFT, pady=10)
        
        # 安全图标和提示
        security_label = ttk.Label(title_frame, text="✓ 安全增强版", style="Security.TLabel")
        security_label.pack(side=tk.RIGHT, pady=10)
        
        # 设备ID信息和复制按钮
        device_id_frame = ttk.Frame(self.main_frame)
        device_id_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.device_id = get_device_id()
        device_id_short = self.device_id[:8] + "..." + self.device_id[-8:] if self.device_id else "未知"
        
        device_label = ttk.Label(device_id_frame, 
                              text=f"设备ID: {device_id_short}", 
                              style="DeviceID.TLabel",
                              wraplength=400)
        device_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 添加复制设备ID按钮
        copy_btn = ttk.Button(device_id_frame, text="复制设备ID", command=self.copy_device_id, width=10)
        copy_btn.pack(side=tk.RIGHT, padx=5)
        
        # 安全提示
        security_frame = ttk.Frame(self.main_frame)
        security_frame.pack(fill=tk.X, pady=(0, 10))
        
        security_info = ttk.Label(security_frame, 
                               text="增强安全功能:\n"
                                   "1. 标识符绑定: 文件与标识符(文件名第一个_前的中文字符)关联\n"
                                   "2. 设备授权: 每个标识符可绑定多个授权设备ID\n"
                                   "3. 一次性解密: 每个文件在每个设备上只能解密一次\n"
                                   "4. 授权管理: 使用「复制设备ID」，请管理员添加到授权列表",
                               wraplength=500,
                               style="Security.TLabel")
        security_info.pack(fill=tk.X)
        
        # 拖放区域
        self.drop_frame = ttk.Frame(self.main_frame, style="Drag.TFrame", height=70)
        self.drop_frame.pack(fill=tk.X, pady=5, padx=5)
        self.drop_frame.pack_propagate(False)  # 防止框架被内容压缩
        
        drop_label = ttk.Label(self.drop_frame, 
                              text="将加密文件拖放到此处", 
                              anchor=tk.CENTER, 
                              font=('Helvetica', 11))
        drop_label.pack(fill=tk.BOTH, expand=True)
        
        # 绑定拖放区域的事件
        drop_label.bind("<Button-1>", lambda e: self.browse_file())
        
        # 标识符输入框
        id_frame = ttk.Frame(self.main_frame)
        id_frame.pack(fill=tk.X, pady=5)
        
        id_label = ttk.Label(id_frame, text="标识符:")
        id_label.pack(side=tk.LEFT)
        
        self.id_var = tk.StringVar()
        id_entry = ttk.Entry(id_frame, textvariable=self.id_var)
        id_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        id_note = ttk.Label(id_frame, 
                           text="(会自动从文件中提取)", 
                           font=('Helvetica', 8),
                           foreground="gray")
        id_note.pack(side=tk.RIGHT)
        
        # 文件选择框
        file_frame = ttk.Frame(self.main_frame)
        file_frame.pack(fill=tk.X, pady=5)
        
        file_label = ttk.Label(file_frame, text="加密文件:")
        file_label.pack(side=tk.LEFT)
        
        self.file_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_var)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        browse_btn = ttk.Button(file_frame, text="浏览...", command=self.browse_file)
        browse_btn.pack(side=tk.LEFT)
        
        # 输出文件选择框
        output_frame = ttk.Frame(self.main_frame)
        output_frame.pack(fill=tk.X, pady=5)
        
        output_label = ttk.Label(output_frame, text="输出文件:")
        output_label.pack(side=tk.LEFT)
        
        self.output_var = tk.StringVar()
        output_entry = ttk.Entry(output_frame, textvariable=self.output_var)
        output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # 默认输出到程序所在目录
        default_output_dir = ttk.Checkbutton(output_frame, text="同目录",
                                            command=self.toggle_default_output)
        default_output_dir.pack(side=tk.LEFT, padx=(0, 5))
        
        browse_output_btn = ttk.Button(output_frame, text="浏览...", command=self.browse_output)
        browse_output_btn.pack(side=tk.LEFT)
        
        # 解密按钮
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.decrypt_btn = ttk.Button(button_frame, text="解密文件", command=self.decrypt)
        self.decrypt_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        decrypt_note = ttk.Label(button_frame, 
                              text="注意: 每个设备只能成功解密一次，请确保正确输入所有信息",
                              style="Security.TLabel",
                              wraplength=350)
        decrypt_note.pack(side=tk.LEFT, fill=tk.X)
        
        # 状态框
        status_frame = ttk.LabelFrame(self.main_frame, text="状态信息")
        status_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.status_var = tk.StringVar(value="准备就绪。请将文件拖放到上方区域或点击浏览选择文件。")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, wraplength=500)
        status_label.pack(fill=tk.BOTH, expand=True)
        
        # 版本信息
        version_label = ttk.Label(self.main_frame, text=f"v{VERSION}", font=('Helvetica', 8))
        version_label.pack(side=tk.RIGHT, pady=5)
    
    def on_drop(self, event):
        """处理文件拖放事件"""
        # 获取拖放的文件路径
        file_path = event.data
        
        # 在Windows上，路径可能包含大括号和引号，需要清理
        if file_path.startswith("{") and file_path.endswith("}"):
            file_path = file_path[1:-1]
        
        # 移除可能存在的引号
        file_path = file_path.strip('"')
        
        if os.path.exists(file_path):
            self.file_var.set(file_path)
            
            # 自动设置默认输出文件名，保存到同一目录
            default_output = os.path.join(os.path.dirname(file_path), 
                                         get_default_output_filename(os.path.basename(file_path)))
            self.output_var.set(default_output)
            
            # 尝试从文件中提取标识符
            identifier = extract_identifier_from_file(file_path)
            if identifier:
                self.id_var.set(identifier)
                self.status_var.set(f"已从文件中提取标识符: {identifier}")
            else:
                self.status_var.set("无法从文件中提取标识符，请手动输入。")
    
    def toggle_default_output(self):
        """切换使用默认输出目录（程序所在目录）"""
        file_path = self.file_var.get().strip()
        if file_path:
            # 获取程序所在目录
            program_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            default_output = os.path.join(program_dir, 
                                         get_default_output_filename(os.path.basename(file_path)))
            self.output_var.set(default_output)
            self.status_var.set(f"输出目录已设置为程序所在目录: {program_dir}")
    
    def browse_file(self):
        """浏览文件对话框"""
        filename = filedialog.askopenfilename(
            title="选择加密文件",
            filetypes=[("所有文件", "*.*"), ("文本文件", "*.txt")]
        )
        if filename:
            self.file_var.set(filename)
            
            # 自动设置默认输出文件名，保存到同一目录
            default_output = os.path.join(os.path.dirname(filename), 
                                         get_default_output_filename(os.path.basename(filename)))
            self.output_var.set(default_output)
            
            # 尝试从文件中提取标识符
            identifier = extract_identifier_from_file(filename)
            if identifier:
                self.id_var.set(identifier)
                self.status_var.set(f"已从文件中提取标识符: {identifier}")
            else:
                self.status_var.set("无法从文件中提取标识符，请手动输入。")
    
    def browse_output(self):
        """浏览输出文件对话框"""
        filename = filedialog.asksaveasfilename(
            title="保存解密文件",
            filetypes=[("所有文件", "*.*"), ("文本文件", "*.txt")]
        )
        if filename:
            self.output_var.set(filename)
            
    def copy_device_id(self):
        """复制设备ID到剪贴板"""
        try:
            pyperclip.copy(self.device_id)
            self.status_var.set("设备ID已复制到剪贴板！可以发送给管理员进行注册。")
            messagebox.showinfo("成功", "设备ID已复制到剪贴板！\n您可以将此ID发送给管理员进行注册。")
        except Exception as e:
            self.status_var.set(f"复制设备ID时出错: {str(e)}")
            messagebox.showerror("错误", f"复制设备ID时出错:\n{str(e)}")
    
    def decrypt(self):
        """执行解密操作"""
        identifier = self.id_var.get().strip()
        file_path = self.file_var.get().strip()
        output_path = self.output_var.get().strip()
        
        # 参数验证
        if not identifier:
            # 再次尝试从文件中提取标识符
            if file_path and os.path.exists(file_path):
                identifier = extract_identifier_from_file(file_path)
                if identifier:
                    self.id_var.set(identifier)
                    self.status_var.set(f"已从文件中提取标识符: {identifier}")
                else:
                    self.status_var.set("错误: 无法从文件中提取标识符，请手动输入")
                    messagebox.showerror("错误", "无法从文件中提取标识符，请手动输入")
                    return
            else:
                self.status_var.set("错误: 请输入标识符")
                messagebox.showerror("错误", "请输入标识符")
                return
        
        if not file_path:
            self.status_var.set("错误: 请选择要解密的文件")
            messagebox.showerror("错误", "请选择要解密的文件")
            return
        
        if not os.path.exists(file_path):
            self.status_var.set(f"错误: 文件不存在 - {file_path}")
            messagebox.showerror("错误", f"文件不存在: {file_path}")
            return
        
        if not output_path:
            # 默认将输出文件保存到程序所在目录
            program_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            output_path = os.path.join(program_dir, 
                                     get_default_output_filename(os.path.basename(file_path)))
            self.output_var.set(output_path)
        
        # 解密前确认
        if os.path.exists(output_path):
            if not messagebox.askyesno("确认覆盖", f"输出文件已存在: {output_path}\n是否覆盖?"):
                self.status_var.set("操作已取消")
                return
        
        # 禁用界面元素
        self.decrypt_btn.config(state="disabled")
        self.status_var.set("正在解密文件...")
        self.root.update()
        
        try:
            # 执行解密
            success = decrypt_file(file_path, output_path, identifier)
            
            if success:
                self.status_var.set(f"文件解密成功！保存至: {output_path}")
                messagebox.showinfo("成功", f"文件解密成功！\n保存至: {output_path}")
            else:
                self.status_var.set("文件解密失败！尝试了所有解密方式均未成功。")
                messagebox.showerror("错误", "文件解密失败！\n可能原因:\n1. 当前设备ID不在标识符授权列表中\n2. 文件已被此设备解密过\n3. 标识符不正确，应为文件名第一个下划线前的中文字符\n\n解决方法:\n1. 使用「复制设备ID」按钮，将设备ID发送给管理员添加到标识符授权设备列表中\n2. 确保标识符与文件名格式匹配：标识符_内容_金额XX元_XX张_加密.txt\n   例如 红_W15_金额1600元_56张_加密.txt 中的标识符是'红'")
        except Exception as e:
            self.status_var.set(f"解密过程中发生错误: {str(e)}")
            messagebox.showerror("错误", f"解密过程中发生错误:\n{str(e)}")
        finally:
            # 恢复界面元素
            self.decrypt_btn.config(state="normal")

def copy_device_id_to_clipboard():
    """复制设备ID到剪贴板的命令行功能"""
    device_id = get_device_id()
    try:
        pyperclip.copy(device_id)
        print(f"\n设备ID已复制到剪贴板!")
        print(f"设备ID: {device_id}")
        print("\n您可以将此ID发送给管理员进行注册，以便解密与您标识符关联的文件。")
        return True
    except Exception as e:
        print(f"复制设备ID时出错: {str(e)}")
        print(f"您的设备ID是: {device_id}")
        print("请手动复制上面的设备ID")
        return False

def main():
    """主函数"""
    parser = create_parser()
    args = parser.parse_args()
    
    # 复制设备ID
    if args.copy_device_id:
        success = copy_device_id_to_clipboard()
        sys.exit(0 if success else 1)
    
    # 启动GUI模式
    if args.gui or len(sys.argv) == 1:
        # 创建根窗口
        root = tk.Tk()
        
        # 如果支持拖放功能，适配TkinterDnD
        if DRAG_DROP_SUPPORTED:
            try:
                # 使用TkinterDnD时，需要替换根窗口
                root.destroy()  # 销毁标准Tk实例
                root = TkinterDnD.Tk()  # 创建TkinterDnD.Tk实例
            except Exception as e:
                print(f"拖放功能初始化失败，使用标准GUI: {str(e)}")
                root = tk.Tk()  # 出错时回退到标准Tk
            
        # 创建GUI应用
        app = DecryptGUI(root)
        
        # 如果不支持拖放，禁用相关功能
        if not DRAG_DROP_SUPPORTED:
            try:
                # 找到并修改拖放区域的提示文本
                for child in app.drop_frame.winfo_children():
                    if isinstance(child, ttk.Label):
                        child.configure(text="请点击\"浏览...\"按钮选择文件")
                        break
            except Exception as e:
                print(f"修改拖放区域提示失败: {str(e)}")
        
        # 启动主循环
        root.mainloop()
        return
    
    # 命令行模式
    success = process_decrypt(args.identifier, args.file, args.output)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()