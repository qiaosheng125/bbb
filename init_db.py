from app import app, db
from models import User, File, SystemSettings, Notification
from flask_login import login_user
from werkzeug.security import generate_password_hash
import os

def init_db():
    with app.app_context():
        # 创建表
        db.create_all()
        
        # 检查是否存在管理员账号
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            # 创建指定的管理员账号
            admin_user = User(
                username="zucaixu",
                identifier="zucaixu",  # 确保标识符与用户名一致
                is_admin=True
            )
            admin_user.set_password("zhongdajiang888")  # 设置指定的密码
            db.session.add(admin_user)
        else:
            # 确保现有管理员账户信息正确
            admin.username = "zucaixu"
            admin.identifier = "zucaixu"
            admin.set_password("zhongdajiang888")
            print(f"已更新管理员账户信息: ID={admin.id}, 用户名={admin.username}")
        
        # 检查系统设置是否存在
        settings = SystemSettings.query.first()
        if not settings:
            # 创建系统设置
            settings = SystemSettings(registration_enabled=True)
            db.session.add(settings)
        
        db.session.commit()
        print("已创建/更新管理员账号和系统设置")

        # 检查File表是否需要迁移（添加note字段）
        # 直接使用SQLAlchemy执行原始SQL添加列
        try:
            print("正在为文件表添加note备注字段...")
            if db.engine.name == 'postgresql':
                # PostgreSQL语法
                db.session.execute(db.text("ALTER TABLE files ADD COLUMN IF NOT EXISTS note TEXT"))
            else:
                # SQLite语法
                # 首先检查列是否存在
                columns = db.session.execute(db.text("PRAGMA table_info(files)")).fetchall()
                column_names = [column[1] for column in columns]
                if 'note' not in column_names:
                    db.session.execute(db.text("ALTER TABLE files ADD COLUMN note TEXT"))
            
            db.session.commit()
            print("文件表note字段添加成功")
        except Exception as e:
            print(f"添加note字段时出错: {str(e)}")
            # 注意：某些错误如"列已存在"可以忽略
            pass
            
        # 检查是否需要创建通知表
        try:
            print("正在检查通知表...")
            # 检查notification表是否存在
            if db.engine.name == 'postgresql':
                # PostgreSQL语法
                result = db.session.execute(db.text(
                    "SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_name='notifications')")).scalar()
                if not result:
                    print("创建通知表...")
                    db.create_all()
            else:
                # SQLite语法
                result = db.session.execute(db.text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='notifications'")).fetchone()
                if not result:
                    print("创建通知表...")
                    db.create_all()
            
            print("通知功能已设置完成")
        except Exception as e:
            print(f"设置通知功能时出错: {str(e)}")
            # 注意：某些错误如"表已存在"可以忽略
            pass

if __name__ == "__main__":
    init_db()
    print("数据库初始化完成")