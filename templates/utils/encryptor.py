"""
文件加密工具模块

提供文件加密和解密功能，用于生成加密版本的文件和解密已加密的文件。
支持多种加密模式，包括纯标识符加密和基于标识符+设备ID的加密。
"""
import os
import base64
import json
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

# 确保加密文件目录存在
ENCRYPTED_FOLDER = 'uploads/encrypted'
if not os.path.exists(ENCRYPTED_FOLDER):
    os.makedirs(ENCRYPTED_FOLDER)

# 为加密服务创建一个密钥
# 注意：在实际生产环境中，应该将此密钥安全存储，不应该硬编码在代码中
# 这里为了简化实现，使用固定密钥
SALT = b'sportsbet_file_encryption_salt'

def get_encryption_key(identifier, device_id=None):
    """
    根据客户标识符和设备ID生成加密密钥
    
    参数:
        identifier (str): 用户标识符
        device_id (str, optional): 设备ID，为None时使用纯标识符加密（服务器端使用）
        
    返回:
        bytes: 加密密钥
    """
    if device_id:
        # 客户端设备解密模式 - 使用特定设备ID和标识符组合
        combined_id = f"{identifier}_{device_id}"
        identifier_bytes = combined_id.encode()
    else:
        # 服务器端加密模式 - 只使用标识符（兼容模式，仅用于测试）
        identifier_bytes = identifier.encode()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(identifier_bytes))
    return key

def encrypt_file(filepath, output_filepath, identifier, device_ids=None):
    """
    加密文件
    
    参数:
        filepath (str): 要加密的文件路径
        output_filepath (str): 加密后的文件保存路径
        identifier (str): 用户标识符，用于生成密钥，应为单个中文字符
        device_ids (list, optional): 设备ID列表，用于多设备支持
        
    返回:
        bool: 加密是否成功
    """
    try:
        # 验证标识符格式
        if not identifier:
            logging.error("错误: 未提供标识符")
            return False
            
        # 确保标识符是中文字符
        if not ('\u4e00' <= identifier[0] <= '\u9fff'):
            logging.warning(f"警告: 标识符 '{identifier}' 不是中文字符，可能导致解密问题")
            logging.warning("标识符应该是文件名第一个下划线前的中文字符，例如'红_W15_金额1600元_56张_加密.txt'中的'红'")
        
        # 确保标识符只有一个字符
        if len(identifier) > 1:
            logging.warning(f"标识符长度超过1个字符，将使用第一个字符: '{identifier[0]}'")
            identifier = identifier[0]
            
        logging.info(f"使用标识符: '{identifier}'")
        
        # 读取原始文件内容
        with open(filepath, 'rb') as file:
            original_data = file.read()
        
        # 使用标识符结合设备ID列表进行加密
        if not device_ids or len(device_ids) == 0:
            # 如果没有提供设备ID列表，使用纯标识符加密（向后兼容）
            logging.info(f"使用纯标识符 '{identifier}' 进行加密")
            key = get_encryption_key(identifier)
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(original_data)
        else:
            # 使用多设备ID加密方式
            logging.info(f"使用多设备ID加密方式，设备数量: {len(device_ids)}")
            
            # 先用标识符加密一层（确保向后兼容）
            key = get_encryption_key(identifier)
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(original_data)
            
            # 记录设备ID用于审计
            device_ids_str = ', '.join([f"{d[:8]}..." for d in device_ids])
            logging.info(f"文件使用以下设备ID进行加密: {device_ids_str}")
            
            # 向文件头部添加元数据，记录加密使用的标识符和授权设备ID列表
            # 这样解密工具可以知道使用哪个标识符和哪些设备被授权解密此文件
            metadata = {
                'identifier': identifier,
                'version': '2.0',  # 加密版本，用于将来扩展
                'timestamp': datetime.datetime.now().isoformat(),
                'device_ids': device_ids,  # 添加授权设备ID列表
            }
            
            # 将元数据转换为JSON并编码为base64
            metadata_json = json.dumps(metadata)
            metadata_b64 = base64.b64encode(metadata_json.encode('utf-8'))
            
            # 构建带元数据的加密数据
            # 格式: METADATA:base64数据:DATA:加密数据
            final_data = b'METADATA:' + metadata_b64 + b':DATA:' + encrypted_data
            encrypted_data = final_data
        
        # 写入加密后的文件
        with open(output_filepath, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)
        
        return True
    except Exception as e:
        logging.error(f"加密文件失败: {str(e)}")
        return False

def extract_metadata(encrypted_data):
    """
    从加密数据中提取元数据（如果存在）
    
    参数:
        encrypted_data (bytes): 加密的文件数据
        
    返回:
        tuple: (元数据字典, 实际加密数据)，如果没有元数据则返回(None, 原始数据)
    """
    try:
        # 检查数据是否包含元数据标识
        if encrypted_data.startswith(b'METADATA:'):
            # 查找元数据和实际数据的分隔符
            parts = encrypted_data.split(b':DATA:', 1)
            if len(parts) == 2:
                # 提取元数据部分
                metadata_part = parts[0][len(b'METADATA:'):]
                actual_data = parts[1]
                
                # 解码并解析元数据
                metadata_json = base64.b64decode(metadata_part).decode('utf-8')
                metadata = json.loads(metadata_json)
                
                return metadata, actual_data
    except Exception as e:
        logging.error(f"提取元数据失败: {str(e)}")
    
    # 如果没有元数据或提取失败，返回原始数据
    return None, encrypted_data

def decrypt_file(filepath, output_filepath, identifier, device_ids=None):
    """
    解密文件 - 支持多设备ID尝试
    
    参数:
        filepath (str): 要解密的文件路径
        output_filepath (str): 解密后的文件保存路径
        identifier (str): 用户标识符，用于生成密钥，应为单个中文字符
        device_ids (list, optional): 设备ID列表，按顺序尝试解密
        
    返回:
        bool: 解密是否成功
    """
    # 验证标识符格式
    if not identifier:
        logging.error("错误: 未提供标识符")
        return False
        
    # 确保标识符是中文字符
    if not ('\u4e00' <= identifier[0] <= '\u9fff'):
        logging.warning(f"警告: 标识符 '{identifier}' 不是中文字符，可能导致解密问题")
        logging.warning("标识符应该是文件名第一个下划线前的中文字符，例如'红_W15_金额1600元_56张_加密.txt'中的'红'")
    
    # 确保标识符只有一个字符
    if len(identifier) > 1:
        logging.warning(f"标识符长度超过1个字符，将使用第一个字符: '{identifier[0]}'")
        identifier = identifier[0]
        
    logging.info(f"使用标识符: '{identifier}'")
    
    # 读取加密文件内容
    try:
        with open(filepath, 'rb') as file:
            encrypted_data = file.read()
    except Exception as e:
        logging.error(f"读取加密文件失败: {str(e)}")
        return False
    
    # 获取文件名，用于日志显示
    filename = os.path.basename(filepath)
    logging.info(f"处理文件: '{filename}'")
    
    # 检查是否有嵌入的元数据
    metadata, actual_encrypted_data = extract_metadata(encrypted_data)
    
    # 如果找到元数据，使用元数据中的标识符
    if metadata and 'identifier' in metadata:
        extracted_identifier = metadata.get('identifier')
        if extracted_identifier:
            logging.info(f"从元数据中提取到标识符: {extracted_identifier}")
            # 始终使用元数据中的标识符，它是加密时使用的标识符
            identifier = extracted_identifier
            # 确保从元数据中提取的标识符也只有一个字符
            if len(identifier) > 1:
                logging.warning(f"元数据中的标识符长度超过1个字符，使用第一个字符: '{identifier[0]}'")
                identifier = identifier[0]
    
    # 首先尝试使用纯标识符解密（向后兼容）
    try:
        key = get_encryption_key(identifier)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(actual_encrypted_data)
        
        # 解密成功，写入解密后的文件
        with open(output_filepath, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
        
        logging.info(f"使用纯标识符模式成功解密: {filepath}")
        return True
    except Exception as e:
        logging.info(f"使用纯标识符模式解密失败: {str(e)}")
    
    # 如果提供了设备ID列表，尝试使用每个设备ID解密
    if device_ids:
        for device_id in device_ids:
            try:
                key = get_encryption_key(identifier, device_id)
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(actual_encrypted_data)
                
                # 解密成功，写入解密后的文件
                with open(output_filepath, 'wb') as decrypted_file:
                    decrypted_file.write(decrypted_data)
                
                logging.info(f"使用设备ID ({device_id[:8]}...) 成功解密: {filepath}")
                return True
            except Exception as e:
                logging.info(f"使用设备ID ({device_id[:8]}...) 解密失败: {str(e)}")
                continue
    
    # 所有解密尝试都失败
    logging.error(f"所有解密方法均失败: {filepath}")
    return False

def generate_encrypted_filename(original_filename):
    """
    生成加密文件的文件名
    
    参数:
        original_filename (str): 原始文件名
        
    返回:
        str: 加密文件名
    """
    name, ext = os.path.splitext(original_filename)
    return f"{name}_encrypted{ext}"