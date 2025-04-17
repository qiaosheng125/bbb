#!/usr/bin/env python3
"""
创建管理员账户脚本 - 仅用于部署环境中

这个脚本直接连接到数据库并创建管理员账户，无需依赖web应用。
用于在部署环境中初始化管理员账户。

使用方法：
python create_admin.py
"""

import os
import sys
import psycopg2
from werkzeug.security import generate_password_hash
from datetime import datetime

def get_beijing_now():
    """返回北京时间字符串"""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def create_admin():
    """直接在数据库中创建管理员账户"""
    # 获取数据库连接信息
    database_url = os.environ.get("DATABASE_URL")
    
    if not database_url:
        print("错误：没有找到DATABASE_URL环境变量")
        sys.exit(1)
    
    try:
        # 连接到数据库
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        
        # 检查管理员账户是否已存在
        cursor.execute("SELECT id FROM users WHERE is_admin = TRUE")
        admin = cursor.fetchone()
        
        if admin:
            print(f"管理员账户已存在，ID: {admin[0]}")
            conn.close()
            return
        
        # 创建管理员账户
        username = "zucaixu"
        password_hash = generate_password_hash("zhongdajiang888")
        identifier = "zucaixu"
        created_at = get_beijing_now()
        
        cursor.execute(
            "INSERT INTO users (username, password_hash, identifier, is_admin, created_at, client_mode, order_count, max_devices) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (username, password_hash, identifier, True, created_at, 'download', 0, 1)
        )
        
        admin_id = cursor.fetchone()[0]
        
        # 检查系统设置表是否已存在记录
        cursor.execute("SELECT COUNT(*) FROM system_settings")
        settings_count = cursor.fetchone()[0]
        
        if settings_count == 0:
            # 创建系统设置记录
            cursor.execute(
                "INSERT INTO system_settings (registration_enabled, updated_at) VALUES (%s, %s)",
                (True, created_at)
            )
        
        # 提交更改
        conn.commit()
        print(f"成功创建管理员账户，ID: {admin_id}, 用户名: {username}")
        
    except Exception as e:
        print(f"创建管理员账户时出错: {str(e)}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    create_admin()