#!/usr/bin/env python3
"""
数据库迁移脚本：添加设备注册表和解密记录表

此脚本用于创建设备注册表和解密记录表，以支持设备管理和一次性成功解密功能。
"""

import sys
import os

# 确保当前工作目录正确引入
sys.path.insert(0, os.path.abspath('.'))

def run_migration():
    """
    运行数据库迁移，添加设备注册表和解密记录表
    """
    from app import db, app
    
    # 创建设备注册表和解密记录表
    print("开始创建设备注册表和解密记录表...")
    with app.app_context():
        db.create_all()
    
    print("设备注册表和解密记录表创建成功!")
    
if __name__ == "__main__":
    run_migration()