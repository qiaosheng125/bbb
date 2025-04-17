"""
数据库迁移脚本：添加加密文件表

这个脚本将创建加密文件表并与原始文件建立一对一关联。
"""

from app import app, db
from models import EncryptedFile
import os

def run_migration():
    """
    运行数据库迁移，添加加密文件表
    """
    with app.app_context():
        # 创建加密文件目录
        encrypted_folder = 'uploads/encrypted'
        if not os.path.exists(encrypted_folder):
            os.makedirs(encrypted_folder)
            print(f"Created directory: {encrypted_folder}")
        
        # 创建加密文件表（如果不存在）
        try:
            db.create_all()
            print("Added encrypted_files table to database")
            return True
        except Exception as e:
            print(f"Error adding tables: {str(e)}")
            return False

if __name__ == "__main__":
    run_migration()