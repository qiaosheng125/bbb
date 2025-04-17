"""
创建加密测试文件

此脚本用于加密测试文件，以便测试解密工具功能
"""
import os
from encryptor import encrypt_file

def main():
    """主函数"""
    # 测试标识符
    identifier = "测试"
    
    # 文件路径
    input_file = "test_file.txt"
    output_file = "test_file_encrypted.txt"
    
    # 检查测试文件是否存在
    if not os.path.exists(input_file):
        print(f"错误: 测试文件不存在 - {input_file}")
        return False
    
    # 加密文件
    print(f"正在使用标识符 '{identifier}' 加密文件...")
    
    # 使用我们的加密函数
    try:
        # 加密文件
        success = encrypt_file(input_file, output_file, identifier)
        
        if success:
            print(f"文件加密成功！保存至: {output_file}")
            print(f"用标识符 '{identifier}' 可以解密此文件")
            return True
        else:
            print("文件加密失败！")
            return False
    except Exception as e:
        print(f"加密文件失败: {str(e)}")
        return False

if __name__ == "__main__":
    main()