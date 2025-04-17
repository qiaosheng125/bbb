# 加密文件验证脚本
# 用于检查数据库记录与实际文件系统中的文件是否匹配
# 并自动修复或重新生成缺失的加密文件

import os
import sys
import datetime
import logging
from app import app, db
from models import File, EncryptedFile, FileStatus

# 配置日志输出
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# 简化版加密函数，不依赖external模块
def encrypt_content(content, device_id):
    """
    简单的加密算法，使用设备ID生成密钥
    适用于内部维护目的
    """
    if not content:
        return ""
    
    # 使用设备ID生成一个简单的密钥
    device_key = sum(ord(c) for c in device_id) % 256
    
    # 简单的加密方式：每个字符都与密钥进行异或操作
    encrypted_chars = []
    for char in content:
        # 对每个字符应用不同的变换
        encrypted_val = (ord(char) ^ device_key) % 65536  # 保持在Unicode范围内
        encrypted_chars.append(chr(encrypted_val))
    
    return "".join(encrypted_chars)

def verify_upload_folders():
    """验证上传文件夹结构是否存在，如不存在则创建"""
    uploads_folder = app.config.get('UPLOAD_FOLDER', 'uploads')
    encrypted_folder = os.path.join(uploads_folder, 'encrypted')
    
    if not os.path.exists(uploads_folder):
        logging.warning(f"主上传文件夹不存在，正在创建: {uploads_folder}")
        os.makedirs(uploads_folder)
    
    if not os.path.exists(encrypted_folder):
        logging.warning(f"加密文件夹不存在，正在创建: {encrypted_folder}")
        os.makedirs(encrypted_folder)
    
    logging.info(f"文件夹验证完成: {uploads_folder}, {encrypted_folder}")

def verify_file_exists(file_path):
    """验证文件是否存在且可读"""
    if not os.path.exists(file_path):
        return False, "文件不存在"
    
    if not os.path.isfile(file_path):
        return False, "路径不是文件"
    
    if not os.access(file_path, os.R_OK):
        return False, "文件不可读取"
    
    return True, "文件存在且可读"

def create_encrypted_version(file):
    """为原始文件创建加密版本"""
    uploads_folder = app.config.get('UPLOAD_FOLDER', 'uploads')
    encrypted_folder = os.path.join(uploads_folder, 'encrypted')
    
    original_path = os.path.join(uploads_folder, file.stored_filename)
    
    # 检查原始文件
    exists, message = verify_file_exists(original_path)
    if not exists:
        logging.error(f"无法创建加密版本 - 原始文件问题: {message}, 文件ID: {file.id}, 路径: {original_path}")
        return None
    
    try:
        # 读取原始文件内容
        with open(original_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 加密内容，使用设备ID作为密钥
        device_id = "SERVER_DEFAULT_KEY"  # 服务器默认密钥
        encrypted_content = encrypt_content(content, device_id)
        
        # 生成加密文件名
        original_name = file.stored_filename
        name_parts = os.path.splitext(original_name)
        encrypted_filename = f"{name_parts[0]}_encrypted{name_parts[1]}"
        encrypted_path = os.path.join(encrypted_folder, encrypted_filename)
        
        # 写入加密内容
        with open(encrypted_path, 'w', encoding='utf-8') as f:
            f.write(encrypted_content)
        
        # 更新或创建加密文件记录
        encrypted_file = EncryptedFile.query.filter_by(original_file_id=file.id).first()
        if encrypted_file:
            encrypted_file.encrypted_filename = encrypted_filename
        else:
            encrypted_file = EncryptedFile(
                original_file_id=file.id,
                encrypted_filename=encrypted_filename
            )
            db.session.add(encrypted_file)
        
        db.session.commit()
        logging.info(f"成功创建加密文件: {encrypted_filename} (原始文件ID: {file.id})")
        return encrypted_file
        
    except Exception as e:
        logging.error(f"创建加密文件失败: {str(e)}, 文件ID: {file.id}")
        return None

def verify_and_fix_encrypted_files():
    """验证并修复加密文件"""
    uploads_folder = app.config.get('UPLOAD_FOLDER', 'uploads')
    encrypted_folder = os.path.join(uploads_folder, 'encrypted')
    
    # 获取所有非撤销状态的文件
    files = File.query.filter(File.status != FileStatus.REVOKED).all()
    
    logging.info(f"开始验证 {len(files)} 个文件的加密版本")
    
    fixed_count = 0
    error_count = 0
    
    for file in files:
        # 检查原始文件是否存在
        original_path = os.path.join(uploads_folder, file.stored_filename)
        original_exists, original_message = verify_file_exists(original_path)
        
        if not original_exists:
            logging.warning(f"原始文件有问题: {original_message}, 文件ID: {file.id}, 路径: {original_path}")
            continue
        
        # 检查是否有对应的加密记录
        encrypted_file = EncryptedFile.query.filter_by(original_file_id=file.id).first()
        
        if not encrypted_file:
            logging.warning(f"加密记录不存在，正在创建: 文件ID {file.id}")
            encrypted_file = create_encrypted_version(file)
            if encrypted_file:
                fixed_count += 1
            else:
                error_count += 1
            continue
        
        # 检查加密文件是否存在
        encrypted_path = os.path.join(encrypted_folder, encrypted_file.encrypted_filename)
        encrypted_exists, encrypted_message = verify_file_exists(encrypted_path)
        
        if not encrypted_exists:
            logging.warning(f"加密文件有问题: {encrypted_message}, 文件ID: {file.id}, 加密文件ID: {encrypted_file.id}, 路径: {encrypted_path}")
            logging.info(f"重新生成加密文件: 文件ID {file.id}")
            
            if create_encrypted_version(file):
                fixed_count += 1
            else:
                error_count += 1
    
    logging.info(f"验证完成: 共处理 {len(files)} 个文件，修复 {fixed_count} 个问题，失败 {error_count} 个")
    return fixed_count, error_count

def main():
    """主函数"""
    with app.app_context():
        print("=" * 60)
        print("  加密文件验证和修复工具")
        print("=" * 60)
        print("此工具将验证所有文件的加密版本，并修复或重新生成缺失的加密文件")
        print()
        
        # 验证文件夹结构
        verify_upload_folders()
        
        # 验证并修复加密文件
        fixed_count, error_count = verify_and_fix_encrypted_files()
        
        print("\n汇总结果:")
        print(f"修复的加密文件: {fixed_count}")
        print(f"处理失败的文件: {error_count}")
        
        if error_count > 0:
            print("\n警告: 部分文件处理失败，请检查日志了解详情")
        
        print("\n完成!")

if __name__ == "__main__":
    main()