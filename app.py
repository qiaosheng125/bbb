import os
import logging
import time
from flask import Flask, g, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user
from sqlalchemy.orm import DeclarativeBase

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

# Initialize extensions
db = SQLAlchemy(model_class=Base)
bcrypt = Bcrypt()
login_manager = LoginManager()

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

# 优化会话配置
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # 会话持续7天
app.config['SESSION_COOKIE_SECURE'] = True  # 使用HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # 防止JavaScript访问
app.config['SESSION_REFRESH_EACH_REQUEST'] = False  # 不要每次请求都刷新会话
app.config['SESSION_USE_SIGNER'] = True  # 使用签名保护会话

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize extensions with app
db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)

# Configure login manager
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# 审计日志钩子
@app.before_request
def log_request():
    """在请求开始时记录时间戳"""
    g.start_time = time.time()
    # 记录敏感操作的开始
    if request.endpoint in ['login', 'register', 'upload_file', 'update_file_status']:
        g.audit_data = {
            'method': request.method,
            'path': request.path,
            'endpoint': request.endpoint,
        }

@app.after_request
def log_response(response):
    """在请求结束时记录审计日志"""
    from models import audit_logger  # 避免循环导入

    if hasattr(g, 'audit_data'):
        duration = (time.time() - g.start_time) * 1000
        g.audit_data.update({
            'status_code': response.status_code,
            'duration_ms': round(duration, 2)
        })

        audit_logger.log(
            user=current_user if current_user.is_authenticated else None,
            action_type=request.endpoint,
            ip_address=request.remote_addr,
            details=g.audit_data,
            status_code=response.status_code,
            duration_ms=round(duration, 2)
        )

    return response

@app.after_request
def add_cache_headers(response):
    """添加缓存控制头，优化静态资源加载速度"""
    # 为静态资源添加长期缓存（1年）
    if request.path.startswith('/static/'):
        # CSS, JS等静态资源长时间缓存
        if any(request.path.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico']):
            response.headers['Cache-Control'] = 'public, max-age=31536000'  # 1年
        else:
            response.headers['Cache-Control'] = 'public, max-age=86400'  # 1天
    
    # 登录页面适度缓存
    elif request.path == '/login' or request.path == '/register':
        response.headers['Cache-Control'] = 'public, max-age=3600'  # 1小时
    
    # API接口不缓存
    elif request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    # 其他页面适度缓存
    elif 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'private, max-age=300'  # 5分钟
    
    return response

with app.app_context():
    # 设置上传文件目录结构
    from utils.directory_setup import setup_file_storage
    file_storage_info = setup_file_storage(app)
    app.logger.info(f"文件存储系统初始化: {file_storage_info}")
    
    # 导入模型和路由
    from models import User  # noqa: F401
    from routes import *  # noqa: F403
    db.create_all()
    
    # 导入并执行初始化函数，创建管理员账户
    from init_db import init_db
    init_db()