#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
简易解密工具打包脚本 v4.2 (2025-04-07更新)

将simple_decrypt_tool.py打包为独立的可执行文件
注意：此脚本在本地环境中运行效果更佳，Replit环境中可能需要较长时间

更新记录:
- v4.2 (2025-04-07): 成功终止打印助手进程后自动退出程序
- v4.1 (2025-04-07): 增强单实例机制，启动新实例时自动关闭旧实例
- v4.0 (2025-04-07): 移除UI界面，双击自动解密txt文件，完成后继续监控
- v3.0 (2025-04-07): 添加自动解密功能和单实例运行机制
- v2.2 (2025-04-07): 添加与赢彩投注单打印助手的集成功能
- v2.1 (2025-04-05): 修复了文件列表重复显示问题
- v2.0 (2025-04-01): 更新加密算法仅使用设备ID作为密钥
- v1.5 (2025-03-28): 增加窗口大小和调整窗口功能
- v1.0 (2025-03-15): 初始版本
"""

import os
import sys
import platform
import subprocess
import time
import datetime

def build_executable():
    """
    使用PyInstaller打包简易解密工具为独立的可执行文件
    """
    print("正在开始打包过程...")
    
    # 检查simple_decrypt_tool.py是否存在
    if not os.path.exists("simple_decrypt_tool.py"):
        print("错误: simple_decrypt_tool.py文件不存在")
        return False
    
    # 确定操作系统类型
    system = platform.system().lower()
    print(f"检测到操作系统: {system}")
    
    # 生成spec文件，而不是直接运行PyInstaller
    spec_content = f"""# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(['simple_decrypt_tool.py'],
             pathex=['.'],
             binaries=[],
             datas=[],
             hiddenimports=['win32gui', 'win32process', 'win32con', 'win32api', 'win32clipboard', 'keyboard', 'pyperclip'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
             
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
             
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='解密工具_{system}',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=False )
"""

    # 写入spec文件
    spec_file = f"解密工具_{system}.spec"
    with open(spec_file, 'w', encoding='utf-8') as f:
        f.write(spec_content)
    
    print(f"已生成PyInstaller规范文件: {spec_file}")
    
    # 提供两种打包方式的说明
    print("\n==== 打包说明 ====")
    print("方法一: 在本地环境中运行以下命令:")
    print(f"pyinstaller {spec_file}")
    print("\n方法二: 直接使用PyInstaller命令打包:")
    print(f"pyinstaller --onefile --windowed --clean --name=解密工具_{system} simple_decrypt_tool.py")
    
    # 尝试执行PyInstaller (在Replit环境中可能需要很长时间)
    print("\n尝试在当前环境中执行打包...(可能需要较长时间)")
    try:
        cmd = ["pyinstaller", spec_file]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # 设置最长等待时间为60秒
        max_wait = 60
        start_time = time.time()
        
        while process.poll() is None:
            if time.time() - start_time > max_wait:
                print(f"\n打包操作超时 ({max_wait}秒)。")
                print("建议在本地环境中运行打包命令。")
                process.terminate()
                break
            time.sleep(1)
            print(".", end="", flush=True)
        
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            print("\n打包成功!")
            # 检查是否生成了可执行文件
            dist_dir = "dist"
            if system == "windows":
                exe_file = os.path.join(dist_dir, f"解密工具_{system}.exe")
            else:
                exe_file = os.path.join(dist_dir, f"解密工具_{system}")
                
            if os.path.exists(exe_file):
                print(f"可执行文件已生成: {exe_file}")
        else:
            print("\n打包过程中出错，建议在本地环境中运行打包命令。")
            if stdout:
                print("输出:", stdout[:500], "..." if len(stdout) > 500 else "")
            if stderr:
                print("错误:", stderr[:500], "..." if len(stderr) > 500 else "")
    
    except Exception as e:
        print(f"\n执行打包命令时出错: {str(e)}")
        print("建议在本地环境中运行打包命令。")
    
    # 打印使用说明
    print("\n==== 使用说明 ====")
    print("1. 将生成的解密工具和需要解密的文件放在同一个文件夹中")
    print("2. 打开赢彩投注单打印助手(LBPrinter.exe)软件")
    print("3. 直接双击运行解密工具:")
    print("   - 程序会自动识别同文件夹中的TXT文件并解密")
    print("   - 如果文件夹中没有TXT文件或有多个TXT文件，会显示错误提示")
    print("4. 解密成功后将自动执行以下操作:")
    print("   - 将解密内容复制到剪贴板")
    print("   - 自动激活赢彩投注单打印助手窗口")
    print("   - 将内容粘贴到打印助手窗口中")
    print("   - 清空剪贴板防止重复粘贴")
    print("   - 禁止使用Ctrl+S或点击保存按钮(红框区域)")
    print("   - 如果尝试保存，将自动关闭打印助手程序")
    print("   - 程序解密完成后将继续在后台运行，监控打印助手")
    print("\n特别说明:")
    print("- 程序保证系统中只运行一个解密工具实例")
    print("- 如需再次解密新文件，需要双击程序重新运行")
    print("- 程序启动时会自动终止之前运行的实例")
    
    return True

if __name__ == "__main__":
    success = build_executable()
    sys.exit(0 if success else 1)