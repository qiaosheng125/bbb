"""
构建独立的可执行文件 - 安全增强版

此脚本用于将解密工具打包成独立的可执行文件
增加了设备绑定和一次性解密功能，提高安全性
增加了文件拖放和自动提取标识符功能，提升用户体验
"""
import os
import sys
import subprocess
import shutil
import pkg_resources

def install_dependencies():
    """安装必要的依赖包"""
    required_packages = [
        'cryptography',
        'pyinstaller',
        'pyperclip',
        'tkinterdnd2'
    ]
    
    print("正在检查必要的依赖包...")
    missing_packages = []
    
    for package in required_packages:
        try:
            pkg_resources.get_distribution(package)
            print(f"√ 已安装 {package}")
        except pkg_resources.DistributionNotFound:
            missing_packages.append(package)
            print(f"× 未安装 {package}")
    
    if missing_packages:
        print("\n正在安装缺失的依赖包...")
        for package in missing_packages:
            print(f"安装 {package}...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                print(f"√ 成功安装 {package}")
            except subprocess.CalledProcessError as e:
                print(f"× 安装 {package} 失败: {e}")
                return False
    
    return True

def build_executable():
    """构建可执行文件"""
    print("开始构建解密工具可执行文件...")
    
    # 安装必要的依赖包
    if not install_dependencies():
        print("错误: 安装依赖包失败，无法继续构建")
        return False
    
    # 构建命令
    build_cmd = [
        "pyinstaller",
        "--name=解密工具-安全版",  # 更新名称，标明是安全版
        "--onefile",
        "--windowed",
        "--icon=icon.svg",  # 使用SVG图标
        "--add-data=encryptor.py:.",
        "--hidden-import=tkinterdnd2",  # 添加对tkinterdnd2的支持
        "decrypt_tool.py"
    ]
    
    print("执行构建命令:", " ".join(build_cmd))
    result = subprocess.run(build_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("构建失败:")
        print(result.stderr)
        return False
    
    print("构建成功!")
    print(result.stdout)
    
    # 复制可执行文件到上一级目录
    try:
        dist_dir = os.path.join(os.getcwd(), "dist")
        exe_name = "解密工具-安全版.exe"  # 更新为安全版名称
        exe_path = os.path.join(dist_dir, exe_name)
        
        if os.path.exists(exe_path):
            # 复制到上一级目录
            output_path = os.path.join(os.path.dirname(os.getcwd()), exe_name)
            shutil.copy2(exe_path, output_path)
            print(f"已将可执行文件复制到: {output_path}")
            
            # 在控制台输出完成消息和安全提示
            print("\n" + "=" * 60)
            print("解密工具增强版构建完成!")
            print("=" * 60)
            print("安全特性:")
            print("1. 智能解密 - 支持多种解密模式，兼容不同加密方式")
            print("2. 设备绑定 - 工具绑定到特定设备，更安全可控")
            print("3. 一次性解密 - 每个文件在每个设备上只能解密一次")
            print("\n用户体验增强:")
            print("1. 文件拖放 - 支持直接拖放文件到程序界面")
            print("2. 自动提取标识符 - 自动从文件中提取标识符")
            print("3. 复制设备ID - 方便用户将设备ID发送给管理员进行注册")
            print("=" * 60)
            print(f"可执行文件路径: {output_path}")
            print("=" * 60)
        else:
            print(f"警告: 未找到构建的可执行文件: {exe_path}")
    except Exception as e:
        print(f"复制可执行文件时出错: {str(e)}")
    
    return True

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    success = build_executable()
    sys.exit(0 if success else 1)