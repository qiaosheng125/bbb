#!/usr/bin/env python3
"""
检查管理员账户脚本

这个脚本检查现有管理员账户的信息并重置密码。
"""

import os
import sys
import psycopg2
from werkzeug.security import generate_password_hash

def check_and_reset_admin():
    """检查管理员账户并重置密码"""
    # 获取数据库连接信息
    database_url = os.environ.get("DATABASE_URL")
    
    if not database_url:
        print("错误：没有找到DATABASE_URL环境变量")
        sys.exit(1)
    
    try:
        # 连接到数据库
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        
        # 查询管理员账户信息
        cursor.execute("SELECT id, username, identifier FROM users WHERE is_admin = TRUE")
        admin = cursor.fetchone()
        
        if not admin:
            print("未找到管理员账户")
            conn.close()
            return
        
        admin_id, username, identifier = admin
        print(f"现有管理员账户信息:")
        print(f"ID: {admin_id}")
        print(f"用户名: {username}")
        print(f"标识符: {identifier}")
        
        # 重置管理员密码
        new_password = "zhongdajiang888"
        password_hash = generate_password_hash(new_password)
        
        cursor.execute(
            "UPDATE users SET password_hash = %s, username = %s, identifier = %s WHERE id = %s",
            (password_hash, "zucaixu", "zucaixu", admin_id)
        )
        
        conn.commit()
        print(f"已将管理员账户更新为:")
        print(f"用户名: zucaixu")
        print(f"密码: {new_password}")
        print(f"标识符: zucaixu")
        
    except Exception as e:
        print(f"操作数据库时出错: {str(e)}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    check_and_reset_admin()