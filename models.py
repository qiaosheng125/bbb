from app import db, login_manager, bcrypt
from flask_login import UserMixin
from enum import Enum
from datetime import datetime, timedelta
import json

def beijing_now():
    """返回北京时间"""
    return datetime.utcnow() + timedelta(hours=8)

def get_today_noon():
    """获取今天中午12点的时间"""
    now = beijing_now()
    today_noon = now.replace(hour=12, minute=0, second=0, microsecond=0)
    if now.hour < 12:
        today_noon -= timedelta(days=1)
    return today_noon

def get_formatted_date():
    """获取格式化的日期字符串 年/月/日"""
    now = beijing_now()
    return now.strftime("%Y/%m/%d")

def generate_file_display_id():
    """生成带日期的文件显示ID"""
    date_str = get_formatted_date()
    today_noon = get_today_noon()
    # 获取今天中午12点之后创建的文件数量
    count = File.query.filter(File.uploaded_at >= today_noon).count()
    return f"{date_str}-{count + 1:02d}"  # 使用02d确保序号始终是两位数

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class FileStatus(Enum):
    PENDING = 'pending'
    RECEIVED = 'received' 
    COMPLETED = 'completed'
    REVOKED = 'revoked'

class ClientMode(Enum):
    DOWNLOAD = 'download'
    WEBPAGE = 'webpage'

class UserSession(db.Model):
    """用户会话记录"""
    __tablename__ = 'user_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    session_id = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=beijing_now)
    last_seen = db.Column(db.DateTime, default=beijing_now)

    def __init__(self, user_id, session_id):
        self.user_id = user_id
        self.session_id = session_id
        
    @classmethod
    def update_last_seen(cls, session_id):
        """更新会话的最后活动时间"""
        session = cls.query.filter_by(session_id=session_id).first()
        if session:
            session.last_seen = beijing_now()
            db.session.commit()
            return True
        return False
        
    @classmethod
    def cleanup_inactive_sessions(cls, inactive_period):
        """清理不活跃的会话，但不包括管理员会话
        
        参数:
            inactive_period: timedelta对象，指定多长时间未活动的会话将被清理
        
        返回:
            被清理的会话数量
        """
        try:
            # 计算截止时间
            cutoff_time = beijing_now() - inactive_period
            
            # 获取所有管理员用户ID列表
            admin_user_ids = [user.id for user in User.query.filter_by(is_admin=True).all()]
            
            # 使用先查询后手动删除的方式避免 SQLAlchemy 的删除错误
            expired_sessions_query = cls.query.filter(
                cls.last_seen < cutoff_time
            )
            
            # 排除管理员会话
            if admin_user_ids:
                expired_sessions_query = expired_sessions_query.filter(~cls.user_id.in_(admin_user_ids))
            
            # 查找所有符合条件的过期会话
            expired_sessions = expired_sessions_query.all()
            
            # 准备要更新的用户字典
            users_to_update = {}
            deleted_count = 0
            
            # 手动处理每个会话
            for session in expired_sessions:
                # 收集用户ID和对应的会话ID
                if session.user_id not in users_to_update:
                    users_to_update[session.user_id] = []
                users_to_update[session.user_id].append(session.session_id)
                
                # 手动删除会话
                db.session.delete(session)
                deleted_count += 1
            
            # 更新用户在线状态
            for user_id, sessions in users_to_update.items():
                user = User.query.get(user_id)
                if user and user.session_id in sessions:
                    # 查找是否还有该用户的其他活跃会话
                    remaining_session = cls.query.filter_by(user_id=user_id).first()
                    
                    if remaining_session:
                        # 如果有其他会话，更新当前会话ID
                        user.session_id = remaining_session.session_id
                    else:
                        # 如果没有其他会话，标记为离线
                        user.is_online = False
                        user.session_id = None
            
            # 提交更改
            db.session.commit()
            print(f"已清理 {deleted_count} 个不活跃会话（超过 {inactive_period} 未活动）")
            return deleted_count
            
        except Exception as e:
            db.session.rollback()
            print(f"清理会话时出错: {str(e)}")
            return 0

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    identifier = db.Column(db.String(10))
    is_admin = db.Column(db.Boolean, default=False)
    client_mode = db.Column(db.Enum(ClientMode), default=ClientMode.DOWNLOAD)
    created_at = db.Column(db.DateTime, default=beijing_now)
    is_online = db.Column(db.Boolean, default=False)
    order_count = db.Column(db.Integer, default=0)
    session_id = db.Column(db.String(100))  # 当前会话ID
    max_devices = db.Column(db.Integer, default=1) # 最大设备数
    files = db.relationship('File', backref='client', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    active_sessions = db.relationship('UserSession', backref='user', lazy=True)

    def __init__(self, username, identifier=None, is_admin=False, client_mode=ClientMode.DOWNLOAD):
        self.username = username
        self.identifier = identifier
        self.is_admin = is_admin
        self.client_mode = client_mode
        self.created_at = beijing_now()
        self.is_online = False
        self.order_count = 0
        self.session_id = None
        self.max_devices = 1

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        if self.password_hash:
            return bcrypt.check_password_hash(self.password_hash, password)
        return False

    def update_session(self, session_id):
        """更新用户的会话ID和会话表
        
        改进的方法支持多设备同时在线，不再覆盖先前的session_id
        """
        # 检查是否达到设备数上限
        if not self.can_add_device():
            # 如果达到上限，删除最早的会话以腾出空间
            oldest_session = UserSession.query.filter_by(user_id=self.id)\
                .order_by(UserSession.last_seen.asc())\
                .first()
            if oldest_session:
                db.session.delete(oldest_session)
        
        # 添加新的会话记录
        new_session = UserSession(user_id=self.id, session_id=session_id)
        db.session.add(new_session)
        
        # 记录当前使用的会话ID (最新的会话ID)
        self.session_id = session_id
        self.is_online = True
        db.session.commit()

    def clear_session(self, session_id=None):
        """清除用户的会话信息
        
        参数:
            session_id: 指定要清除的会话ID，如果为None则清除当前用户的所有会话
        """
        if session_id:
            # 仅删除指定的会话
            UserSession.query.filter_by(
                user_id=self.id,
                session_id=session_id
            ).delete()
            
            # 如果删除的是当前活跃会话，更新用户的session_id
            if self.session_id == session_id:
                # 查找最新的其他会话
                newest_session = UserSession.query.filter_by(user_id=self.id)\
                    .order_by(UserSession.last_seen.desc())\
                    .first()
                
                if newest_session:
                    self.session_id = newest_session.session_id
                else:
                    self.session_id = None
                    self.is_online = False
        else:
            # 清除所有会话
            UserSession.query.filter_by(user_id=self.id).delete()
            self.session_id = None
            self.is_online = False
        
        db.session.commit()

    def can_add_device(self):
        """检查是否可以添加新设备"""
        # 管理员不受设备数量限制
        if self.is_admin:
            return True

        # 如果设备数限制为0，不允许任何设备登录
        if self.max_devices == 0:
            return False

        # 获取当前活跃会话数
        active_sessions_count = UserSession.query.filter_by(user_id=self.id).count()

        # 检查是否达到最大设备数限制
        return active_sessions_count < self.max_devices

    def get_active_sessions_count(self):
        """获取当前活跃会话数"""
        return UserSession.query.filter_by(user_id=self.id).count()

    def increment_order_count(self):
        self.order_count += 1
        db.session.commit()

    def decrement_order_count(self):
        if self.order_count > 0:
            self.order_count -= 1
            db.session.commit()

    def get_completed_amount(self):
        """获取今天中午12点到明天中午12点之间的已完成订单总金额"""
        start_time = get_today_noon()
        end_time = start_time + timedelta(days=1)

        completed_files = File.query.filter(
            File.client_id == self.id,
            File.status == FileStatus.COMPLETED,
            File.uploaded_at >= start_time,
            File.uploaded_at < end_time
        ).all()

        return sum(float(file.amount) for file in completed_files)

    def __repr__(self):
        return f'<User {self.username}>'

    def update_max_devices(self, max_devices):
        """更新用户允许的最大在线设备数
        max_devices: 0表示不允许任何设备登录，正数表示允许的最大设备数
        """
        self.max_devices = max_devices
        db.session.commit()

        # 如果设置为0或减少了设备数限制，可能需要强制登出一些设备
        if max_devices == 0:
            # 删除所有会话
            UserSession.query.filter_by(user_id=self.id).delete()
            self.is_online = False
            self.session_id = None
            db.session.commit()
            return True  # 返回True表示有会话被删除

        return False  # 返回False表示没有会话被删除

    def is_session_valid(self, current_session_id):
        """检查当前会话是否有效
        
        改进后的方法检查会话是否存在于用户的活跃会话列表中
        而不是仅检查与用户的当前session_id是否匹配
        """
        # 如果用户的最大设备数为0，所有会话都无效
        if self.max_devices == 0:
            return False
            
        # 检查会话记录是否存在
        session = UserSession.query.filter_by(
            user_id=self.id,
            session_id=current_session_id
        ).first()
        
        return session is not None


class SystemSettings(db.Model):
    __tablename__ = 'system_settings'
    id = db.Column(db.Integer, primary_key=True)
    registration_enabled = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=beijing_now, onupdate=beijing_now)

    @classmethod
    def get_settings(cls):
        settings = cls.query.first()
        if not settings:
            settings = cls()
            db.session.add(settings)
            db.session.commit()
        return settings

class EncryptedFile(db.Model):
    """加密文件模型，与原始文件一对一关联"""
    __tablename__ = 'encrypted_files'
    id = db.Column(db.Integer, primary_key=True)
    original_file_id = db.Column(db.Integer, db.ForeignKey('files.id'), unique=True, nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)  # 加密后的文件名
    created_at = db.Column(db.DateTime, default=beijing_now)
    
    # 与原始文件的关联
    original_file = db.relationship('File', backref=db.backref('encrypted_version', uselist=False))
    
    def __init__(self, original_file_id, encrypted_filename):
        self.original_file_id = original_file_id
        self.encrypted_filename = encrypted_filename

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    display_id = db.Column(db.String(20), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    status = db.Column(db.Enum(FileStatus), default=FileStatus.PENDING)
    amount = db.Column(db.Numeric(10,2))
    count = db.Column(db.Integer)
    current_page = db.Column(db.Integer, default=0)
    uploaded_at = db.Column(db.DateTime, default=beijing_now)
    completed_at = db.Column(db.DateTime)
    note = db.Column(db.Text)  # 添加备注字段，可以为空
    transactions = db.relationship('StatusLog', backref='file', lazy=True)

    def __init__(self, **kwargs):
        super(File, self).__init__(**kwargs)
        self.display_id = generate_file_display_id()

    def is_last_page(self):
        return self.current_page >= self.count - 1 if self.count else True

    def can_download(self):
        """检查文件是否可以下载
        规则:
        1. 未完成的文件可以下载
        2. 已完成的文件需要等待2小时后才能下载
        """
        if self.status == FileStatus.PENDING:
            return True
        elif self.status == FileStatus.COMPLETED and self.completed_at:
            # 使用completed_at而不是uploaded_at来计算等待期
            two_hours_after = self.completed_at + timedelta(hours=2)
            return beijing_now() >= two_hours_after
        return False
    
    def can_download_original(self):
        """检查是否可以下载原始文件（非加密版本）
        规则: 完成状态的文件需要等待2小时后才能下载原始版本
        """
        if self.status == FileStatus.COMPLETED and self.completed_at:
            # 2小时后才能下载原始文件
            two_hours_after = self.completed_at + timedelta(hours=2)
            return beijing_now() >= two_hours_after
        # 其他状态不允许下载原始文件
        return False
    
    def can_download_encrypted(self):
        """检查是否可以下载加密版本
        规则: 所有状态的文件都可以立即下载加密版本
        """
        # 检查是否存在加密版本
        return hasattr(self, 'encrypted_version') and self.encrypted_version is not None

    def set_completed(self):
        """设置文件为完成状态"""
        self.status = FileStatus.COMPLETED
        self.completed_at = beijing_now()
        db.session.commit()
        
    @classmethod
    def cleanup_old_files(cls):
        """清理7天前已完成或已撤销的文件
        
        清理规则:
        1. 删除7天前已完成(COMPLETED)或已撤销(REVOKED)的文件
        2. 同时清理加密版本和原始文件
        3. 从文件系统删除实际文件
        4. 更新数据库记录
        
        返回:
            清理的文件数量
        """
        import os
        import shutil
        from app import app
        
        try:
            # 计算7天前的时间点
            cutoff_time = beijing_now() - timedelta(days=7)
            
            # 查询7天前已完成或已撤销的文件
            old_files = cls.query.filter(
                db.or_(
                    cls.status == FileStatus.COMPLETED,
                    cls.status == FileStatus.REVOKED
                ),
                db.or_(
                    cls.completed_at < cutoff_time,  # 已完成文件以完成时间为准
                    cls.uploaded_at < cutoff_time    # 已撤销文件以上传时间为准
                )
            ).all()
            
            if not old_files:
                print("没有需要清理的旧文件")
                return 0
                
            files_count = len(old_files)
            print(f"找到 {files_count} 个需要清理的旧文件")
            
            upload_folder = os.path.join(app.root_path, 'uploads')
            encrypted_folder = os.path.join(upload_folder, 'encrypted')
            
            cleaned_count = 0
            
            for file in old_files:
                try:
                    # 1. 删除原始文件
                    original_path = os.path.join(upload_folder, file.stored_filename)
                    if os.path.exists(original_path):
                        os.remove(original_path)
                        print(f"已删除原始文件: {original_path}")
                    
                    # 2. 如果有加密版本，也删除加密文件
                    if hasattr(file, 'encrypted_version') and file.encrypted_version:
                        encrypted_path = os.path.join(encrypted_folder, file.encrypted_version.encrypted_filename)
                        if os.path.exists(encrypted_path):
                            os.remove(encrypted_path)
                            print(f"已删除加密文件: {encrypted_path}")
                        
                        # 删除加密文件记录
                        db.session.delete(file.encrypted_version)
                    
                    # 3. 删除该文件的所有关联记录
                    # 先删除该文件的状态日志
                    for log in file.transactions:
                        db.session.delete(log)
                    
                    # 删除解密记录
                    if hasattr(file, 'decryption_records'):
                        for record in file.decryption_records:
                            db.session.delete(record)
                    
                    # 4. 最后删除文件记录本身
                    db.session.delete(file)
                    cleaned_count += 1
                    
                except Exception as e:
                    print(f"清理文件 {file.filename} 时出错: {str(e)}")
                    continue
            
            # 提交所有更改
            db.session.commit()
            print(f"成功清理了 {cleaned_count} 个旧文件")
            return cleaned_count
            
        except Exception as e:
            db.session.rollback()
            print(f"清理文件过程中发生错误: {str(e)}")
            return 0

class StatusLog(db.Model):
    __tablename__ = 'status_logs'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'))
    old_status = db.Column(db.String(20))
    new_status = db.Column(db.String(20))
    changed_at = db.Column(db.DateTime, default=beijing_now)
    changed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=beijing_now, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    ip_address = db.Column(db.String(45), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    status_code = db.Column(db.Integer)
    duration_ms = db.Column(db.Float)

    __table_args__ = (
        db.Index('idx_logs_user', user_id),
        db.Index('idx_logs_time', timestamp.desc()),
    )

class AuditLogger:
    @staticmethod
    def log(user, action_type, ip_address, details, status_code=None, duration_ms=None):
        """记录审计日志"""
        log = AuditLog(
            user_id=user.id if user else None,
            ip_address=ip_address,
            action_type=action_type,
            details=json.dumps(details) if isinstance(details, dict) else str(details),
            status_code=status_code,
            duration_ms=duration_ms
        )
        db.session.add(log)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()

audit_logger = AuditLogger()

class DeviceRegistry(db.Model):
    """设备注册表"""
    __tablename__ = 'device_registry'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), unique=True, nullable=False)  # 设备唯一标识符
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    device_name = db.Column(db.String(100))  # 设备名称（可选）
    first_seen = db.Column(db.DateTime, default=beijing_now)
    last_active = db.Column(db.DateTime, default=beijing_now)
    is_authorized = db.Column(db.Boolean, default=True)  # 设备是否被授权
    client_info = db.Column(db.Text)  # 存储客户端信息（如操作系统、浏览器等）
    
    # 关联用户
    user = db.relationship('User', backref=db.backref('registered_devices', lazy=True))
    
    def __init__(self, device_id, user_id=None, device_name=None, client_info=None):
        self.device_id = device_id
        self.user_id = user_id
        self.device_name = device_name
        self.client_info = client_info
        self.first_seen = beijing_now()
        self.last_active = beijing_now()
        self.is_authorized = True

    def update_activity(self):
        """更新设备最后活动时间"""
        self.last_active = beijing_now()
        db.session.commit()
    
    def authorize(self, authorize=True):
        """授权或禁用设备"""
        self.is_authorized = authorize
        db.session.commit()
        return self.is_authorized

class DecryptionRecord(db.Model):
    """解密记录表，记录文件解密成功的历史"""
    __tablename__ = 'decryption_records'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'))
    device_id = db.Column(db.String(64), nullable=False)  # 设备ID
    decrypted_at = db.Column(db.DateTime, default=beijing_now)
    is_successful = db.Column(db.Boolean, default=True)  # 解密是否成功
    
    # 关联文件
    file = db.relationship('File', backref=db.backref('decryption_records', lazy=True))
    
    def __init__(self, file_id, device_id, is_successful=True):
        self.file_id = file_id
        self.device_id = device_id
        self.is_successful = is_successful
        self.decrypted_at = beijing_now()
    
    @classmethod
    def has_successful_decryption(cls, file_id, device_id):
        """检查文件是否已被特定设备成功解密过"""
        return cls.query.filter_by(
            file_id=file_id, 
            device_id=device_id,
            is_successful=True
        ).first() is not None
    
    @classmethod
    def record_attempt(cls, file_id, device_id, is_successful):
        """记录一次解密尝试"""
        record = cls(file_id, device_id, is_successful)
        db.session.add(record)
        try:
            db.session.commit()
            return True
        except:
            db.session.rollback()
            return False

class Notification(db.Model):
    """通知公告"""
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=beijing_now)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_by = db.relationship('User', backref='notifications')
    
    def __init__(self, content, created_by=None):
        self.content = content
        self.created_by = created_by
        self.is_active = True