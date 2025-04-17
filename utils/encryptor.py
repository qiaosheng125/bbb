#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
文件加密模块

提供用于加密和解密文件的功能。
当前设计为仅使用设备ID来生成加密密钥，不与标识符组合。
"""
import os
import base64
import json
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# 加密使用的盐值
SALT = b'sportsbet_file_encryption_salt'

def get_encryption_key(device_id):
    """仅使用设备ID生成加密密钥"""
    device_bytes = device_id.encode()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(device_bytes))
    return key

def generate_encrypted_filename(original_filename):
    """
    为加密文件生成一个带有时间戳的唯一文件名
    """
    name, ext = os.path.splitext(original_filename)
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    return f"{name}_encrypted_{timestamp}{ext}"

def encrypt_file(input_path, output_path, identifier, device_ids=None):
    """
    加密文件 - 使用共享密钥方案
    
    参数:
        input_path: 输入文件路径
        output_path: 输出文件路径
        identifier: 标识符（文件前缀中的中文字符）
        device_ids: 授权设备ID列表（可以为空）
    
    返回:
        成功返回True，失败返回False
    """
    try:
        # 如果没有指定设备列表，使用空列表
        if device_ids is None:
            device_ids = []
        
        # 读取原始文件内容
        with open(input_path, 'rb') as file:
            original_data = file.read()
        
        # 使用随机字符串作为加密密钥源
        # 这样任何授权设备都可以解密，但密钥本身不依赖于任何特定设备ID
        import uuid
        shared_key_source = str(uuid.uuid4())
        
        # 生成加密密钥
        key = get_encryption_key(shared_key_source)
        
        # 使用Fernet对称加密算法加密
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(original_data)
        
        # 元数据包含标识符、授权设备ID列表和共享密钥源
        metadata = {
            "identifier": identifier,
            "encrypted_at": datetime.datetime.now().isoformat(),
            "device_ids": device_ids,
            "key_source": shared_key_source  # 添加共享密钥源到元数据
        }
        
        # 将元数据添加到加密数据前面
        metadata_json = json.dumps(metadata).encode()
        metadata_encoded = base64.b64encode(metadata_json)
        final_data = b"METADATA:" + metadata_encoded + b":DATA:" + encrypted_data
        
        # 写入加密文件
        with open(output_path, 'wb') as file:
            file.write(final_data)
        
        return True
        
    except Exception as e:
        print(f"加密文件失败: {str(e)}")
        return False

def decrypt_file(input_path, output_path, device_id, delete_source=True):
    """
    解密文件
    
    参数:
        input_path: 加密文件路径
        output_path: 解密后的输出文件路径
        device_id: 设备ID
        delete_source: 解密成功后是否删除源文件，默认为True
    
    返回:
        成功返回True，失败返回False
    """
    try:
        # 读取加密文件
        with open(input_path, 'rb') as file:
            encrypted_data = file.read()
        
        # 提取元数据和加密数据
        metadata = None
        actual_encrypted_data = encrypted_data
        
        if encrypted_data.startswith(b'METADATA:'):
            parts = encrypted_data.split(b':DATA:', 1)
            if len(parts) == 2:
                metadata_part = parts[0][len(b'METADATA:'):]
                actual_encrypted_data = parts[1]
                
                try:
                    metadata_json = base64.b64decode(metadata_part).decode('utf-8')
                    metadata = json.loads(metadata_json)
                except Exception as e:
                    print(f"解析元数据失败: {str(e)}")
        
        # 检查当前设备ID是否在授权设备列表中
        if metadata and 'device_ids' in metadata:
            device_ids = metadata.get('device_ids', [])
            if device_ids and device_id not in device_ids:
                print(f"设备ID {device_id[:8]}... 不在授权列表中，无法解密")
                return False
        
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
            if device_id in device_ids and device_ids:
                decryption_strategies.append(('第一个设备ID', device_ids[0]))
        
        # 策略3: 尝试使用当前设备ID直接解密（旧版兼容）
        decryption_strategies.append(('当前设备ID', device_id))
        
        # 策略4: 尝试使用标识符解密（最早版本兼容）
        if metadata and 'identifier' in metadata:
            identifier = metadata.get('identifier')
            if identifier:
                decryption_strategies.append(('标识符', identifier[0]))
        
        # 尝试所有解密策略
        for strategy_name, key_source in decryption_strategies:
            try:
                print(f"尝试使用{strategy_name}解密...")
                key = get_encryption_key(key_source)
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(actual_encrypted_data)
                
                # 写入解密后的数据
                with open(output_path, 'wb') as file:
                    file.write(decrypted_data)
                
                print(f"使用{strategy_name}解密成功!")
                
                # 解密成功后删除源文件
                if delete_source:
                    try:
                        import os
                        os.remove(input_path)
                        print(f"源文件 {input_path} 已删除")
                    except Exception as e:
                        print(f"删除源文件失败: {str(e)}")
                
                return True
            except Exception as e:
                print(f"使用{strategy_name}解密失败: {str(e)}")
                continue
        
        # 所有策略都失败
        print("所有解密策略都失败了")
        return False
            
    except Exception as e:
        print(f"解密过程出错: {str(e)}")
        return False