#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
文件加密解密库 - 独立版本

提供文件加密和解密功能，用于解密加密版本的文件。
现在仅使用设备ID进行加密解密，不再与标识符组合。
"""
import os
import base64
import json
import uuid
import platform
import socket
import getpass
import hashlib
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# 为加密服务使用固定密钥盐值
# 注意：在实际生产环境中，应该将此密钥安全存储，不应该硬编码在代码中
SALT = b'sportsbet_file_encryption_salt'

# 设备配置目录
USER_HOME = os.path.expanduser("~")
DEVICE_CONFIG_DIR = os.path.join(USER_HOME, ".sportsbet")
DEVICE_CONFIG_FILE = os.path.join(DEVICE_CONFIG_DIR, "device_config.json")
DECRYPT_HISTORY_FILE = os.path.join(DEVICE_CONFIG_DIR, "decrypt_history.json")

def get_device_id():
    """获取设备唯一标识符，如果不存在则生成一个"""
    # 如果配置目录不存在，创建它
    if not os.path.exists(DEVICE_CONFIG_DIR):
        os.makedirs(DEVICE_CONFIG_DIR, exist_ok=True)
    
    # 检查是否已有设备ID
    if os.path.exists(DEVICE_CONFIG_FILE):
        try:
            with open(DEVICE_CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return config.get('device_id')
        except Exception as e:
            print(f"读取设备ID失败: {e}")
    
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
        print(f"保存设备ID失败: {e}")
    
    return device_id

def extract_identifier_from_file(filepath):
    """
    从文件名提取标识符
    标识符是文件名第一个下划线前的中文字符
    例如: 红_W15_金额1600元_56张_加密.txt 中的 "红"
    """
    import re
    # 获取文件名
    filename = os.path.basename(filepath)
    
    try:
        # 专门匹配文件名第一个下划线前的内容作为标识符
        prefix_pattern = re.compile(r'^([^_]+)_')
        prefix_match = prefix_pattern.search(filename)
        
        if prefix_match:
            prefix = prefix_match.group(1)
            # 判断是否是中文字符
            if len(prefix) == 1 and '\u4e00' <= prefix <= '\u9fff':
                return prefix
            # 如果前缀包含中文，提取第一个中文字符
            chinese_pattern = re.compile(r'([\u4e00-\u9fff])')
            chinese_match = chinese_pattern.search(prefix)
            if chinese_match:
                chinese_char = chinese_match.group(1)
                return chinese_char
        
        # 尝试直接匹配以中文字符开头的文件名
        first_char_pattern = re.compile(r'^([\u4e00-\u9fff])')
        first_char_match = first_char_pattern.search(filename)
        if first_char_match:
            chinese_char = first_char_match.group(1)
            return chinese_char
        
        # 尝试从文件名中提取任意中文字符作为标识符
        any_chinese_pattern = re.compile(r'([\u4e00-\u9fff])')
        any_chinese_match = any_chinese_pattern.search(filename)
        if any_chinese_match:
            chinese_char = any_chinese_match.group(1)
            return chinese_char
    
    except Exception as e:
        print(f"提取标识符时出错: {e}")
    
    return ""

def get_encryption_key(device_id=None):
    """
    仅使用设备ID生成加密密钥，不使用标识符
    """
    if device_id is None:
        device_id = get_device_id()
    
    # 仅使用设备ID生成密钥
    device_bytes = device_id.encode()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(device_bytes))
    return key

def encrypt_file(input_path, output_path=None, identifier=None, additional_device_ids=None):
    """
    使用设备ID加密文件
    参数:
        input_path: 输入文件路径
        output_path: 输出文件路径，如果为None则自动生成
        identifier: 加密标识符（仅用于记录在元数据中，不影响加密密钥）
        additional_device_ids: 额外授权的设备ID列表
    返回:
        加密文件的路径
    """
    # 获取设备ID
    device_id = get_device_id()
    
    # 如果没有提供标识符，尝试从文件名获取
    if identifier is None:
        identifier = extract_identifier_from_file(input_path)
    
    # 如果仍然没有标识符，使用默认值
    if not identifier:
        identifier = "未知"
    
    # 创建元数据
    metadata = {
        "identifier": identifier,
        "encrypted_at": datetime.datetime.now().isoformat(),
        "device_id": device_id,
        "device_ids": [device_id]
    }
    
    # 如果提供了额外的设备ID，添加到授权列表
    if additional_device_ids:
        metadata["device_ids"].extend(additional_device_ids)
        # 移除重复项
        metadata["device_ids"] = list(set(metadata["device_ids"]))
    
    # 生成密钥 - 只使用设备ID
    key = get_encryption_key(device_id)
    fernet = Fernet(key)
    
    # 读取输入文件
    with open(input_path, 'rb') as file:
        data = file.read()
    
    # 加密数据
    encrypted_data = fernet.encrypt(data)
    
    # 将元数据添加到加密数据前面
    metadata_json = json.dumps(metadata).encode()
    metadata_encoded = base64.b64encode(metadata_json)
    final_data = b"METADATA:" + metadata_encoded + b":DATA:" + encrypted_data
    
    # 确定输出文件路径
    if output_path is None:
        filename = os.path.basename(input_path)
        dirname = os.path.dirname(input_path)
        base, ext = os.path.splitext(filename)
        if not base.endswith("_加密"):
            output_path = os.path.join(dirname, f"{base}_加密{ext}")
        else:
            output_path = os.path.join(dirname, f"{base}{ext}")
    
    # 写入加密数据
    with open(output_path, 'wb') as file:
        file.write(final_data)
    
    return output_path

def decrypt_file(input_path, output_path=None, check_history=False):
    """
    使用设备ID解密文件
    参数:
        input_path: 加密文件路径
        output_path: 解密后的输出文件路径，如果为None则自动生成
        check_history: 是否检查解密历史（如果为True，每个文件只能解密一次）
    返回:
        解密文件的路径或None（如果解密失败）
    """
    # 获取设备ID
    device_id = get_device_id()
    
    # 如果需要检查解密历史
    if check_history:
        # 计算文件哈希
        file_hash = hashlib.sha256()
        with open(input_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                file_hash.update(chunk)
        file_hash_hex = file_hash.hexdigest()
        
        # 检查文件是否已被解密过
        history_path = DECRYPT_HISTORY_FILE
        if os.path.exists(history_path):
            try:
                with open(history_path, 'r') as f:
                    history = json.load(f)
                    if file_hash_hex in history.get('decrypted_files', []):
                        print("此文件已被解密过，不能重复解密")
                        return None
            except:
                # 如果读取历史记录失败，忽略检查，继续解密
                pass
    
    # 读取加密文件
    with open(input_path, 'rb') as file:
        encrypted_data = file.read()
    
    # 提取元数据
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
                print(f"提取元数据失败: {e}")
    
    # 生成解密密钥 - 只使用设备ID
    key = get_encryption_key(device_id)
    fernet = Fernet(key)
    
    try:
        # 解密数据
        decrypted_data = fernet.decrypt(actual_encrypted_data)
        
        # 如果启用了历史检查，记录解密历史
        if check_history and file_hash_hex:
            history_dir = DEVICE_CONFIG_DIR
            history_path = DECRYPT_HISTORY_FILE
            
            if not os.path.exists(history_dir):
                os.makedirs(history_dir, exist_ok=True)
            
            history = {'decrypted_files': []}
            if os.path.exists(history_path):
                try:
                    with open(history_path, 'r') as f:
                        history = json.load(f)
                except:
                    pass
            
            if 'decrypted_files' not in history:
                history['decrypted_files'] = []
            
            history['decrypted_files'].append(file_hash_hex)
            
            with open(history_path, 'w') as f:
                json.dump(history, f)
        
        # 确定输出文件路径
        if output_path is None:
            filename = os.path.basename(input_path)
            dirname = os.path.dirname(input_path)
            base, ext = os.path.splitext(filename)
            
            # 移除"_加密"后缀，如果有
            if base.endswith("_加密"):
                base = base[:-3]  # 移除"_加密"
            
            # 添加"解密结果_"前缀
            output_path = os.path.join(dirname, f"解密结果_{base}{ext}")
        
        # 写入解密数据
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)
        
        return output_path
    
    except Exception as e:
        print(f"解密失败: {e}")
        return None