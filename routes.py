import os
import re
import random
import string
import json
from io import BytesIO
from datetime import datetime
from decimal import Decimal
from flask import render_template, url_for, flash, redirect, request, jsonify, g, Response, send_file, send_from_directory, make_response
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from sqlalchemy import text
from models import User, File, EncryptedFile, FileStatus, StatusLog, audit_logger, ClientMode, SystemSettings, beijing_now, UserSession, Notification, DeviceRegistry, DecryptionRecord, AuditLog
from forms import LoginForm, RegistrationForm
from functools import wraps
import time
from utils.image_generator import BettingCalculator
from urllib.parse import quote
from collections import defaultdict

# 文件上传配置
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt'}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB限制
PATTERN = re.compile(r'^([\u4e00-\u9fa5])_.+_金额(\d+)元_(\d+)张\.txt$')

# 确保上传目录存在
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 确保静态目录存在
STATIC_FOLDER = 'static'
if not os.path.exists(STATIC_FOLDER):
    os.makedirs(STATIC_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['STATIC_FOLDER'] = STATIC_FOLDER

@app.route('/static/<path:filename>')
def serve_static(filename):
    """提供静态文件服务"""
    return send_from_directory(app.config['STATIC_FOLDER'], filename)

# 图片生成功能已移除

def generate_unique_filename(original_filename):
    """生成带时间戳的唯一文件名"""
    name, ext = os.path.splitext(original_filename)
    timestamp = beijing_now().strftime('%Y%m%d%H%M%S')
    return f"{name}_{timestamp}{ext}"

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('需要管理员权限。', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 记录每个客户最后上传的序号
last_sequence_numbers = defaultdict(list)

def extract_sequence_number(filename):
    """
    从文件名中提取序号信息
    返回：(客户标识, 字母前缀, 序号)
    例如：
    对于 "我_P11总进球3倍投_金额444元_4张_20250408220927.txt"
    返回 ("我", "P", 11)
    """
    # 文件名格式：[客户标识]_[字母+序号+类型名]_金额X元_X张_时间戳.txt
    match = re.match(r'^([\u4e00-\u9fa5]+)_([A-Za-z])(\d+).*?_金额.*?_.*张.*\.txt$', filename)
    if not match:
        return None, None, None
    
    client_id = match.group(1)    # 客户标识，如"我"或"韩"
    letter_prefix = match.group(2) # 字母前缀，如"P"、"V"、"W"
    try:
        sequence_number = int(match.group(3)) # 序号，如"11"、"1"、"15"
        return client_id, letter_prefix, sequence_number
    except (ValueError, TypeError):
        return client_id, letter_prefix, None

def check_sequence_continuity(files):
    """
    检查上传文件的序号是否连续（只按客户标识符分组）
    参数：
    - files: 上传的文件列表
    返回：
    - 序号不连续的警告信息列表
    """
    # 初始化当前批次的序号记录
    batch_sequence_numbers = defaultdict(list)
    sequence_warnings = []
    
    # 第一步：提取所有文件的序号并按客户分组
    for file in files:
        client_id, letter_prefix, seq_num = extract_sequence_number(file.filename)
        if client_id and letter_prefix and seq_num is not None:
            # 记录到当前批次，同时保留前缀字母以便在警告信息中显示
            batch_sequence_numbers[client_id].append((letter_prefix, seq_num))
    
    # 第二步：对每个客户检查序号是否连续
    for client_id, prefix_numbers in batch_sequence_numbers.items():
        # 按序号排序
        prefix_numbers.sort(key=lambda x: x[1])
        
        # 提取纯序号列表
        numbers = [num for _, num in prefix_numbers]
        
        # 检查当前批次序号是否连续
        if len(numbers) > 1:
            for i in range(len(numbers) - 1):
                if numbers[i + 1] - numbers[i] > 1:
                    # 序号不连续，找出缺失的序号
                    missing_numbers = list(range(numbers[i] + 1, numbers[i + 1]))
                    # 获取相应的字母前缀列表
                    missing_items = []
                    for missing_num in missing_numbers:
                        # 使用缺失序号相邻的前缀
                        if i < len(prefix_numbers):
                            prefix = prefix_numbers[i][0]
                            missing_items.append(f"{prefix}{missing_num}")
                    
                    missing_str = ", ".join(missing_items)
                    warning = f"客户「{client_id}」可能漏上传了序号：{missing_str}"
                    sequence_warnings.append(warning)
        
        # 检查与上一批次对比是否连续
        if client_id in last_sequence_numbers and last_sequence_numbers[client_id]:
            last_numbers = last_sequence_numbers[client_id]
            last_max = max(last_numbers)
            current_min = min(numbers)
            
            if current_min - last_max > 1:
                # 与上一批次序号不连续
                missing_numbers = list(range(last_max + 1, current_min))
                # 使用当前批次第一个项目的前缀
                prefix = prefix_numbers[0][0]
                missing_items = [f"{prefix}{num}" for num in missing_numbers]
                missing_str = ", ".join(missing_items)
                warning = f"客户「{client_id}」可能漏上传了序号：{missing_str}"
                sequence_warnings.append(warning)
        
        # 更新最后的序号记录
        last_sequence_numbers[client_id] = numbers
    
    return sequence_warnings

@app.route('/upload_file', methods=['POST'])
@login_required
@admin_required
def upload_file():
    if 'files' not in request.files:
        return jsonify({'success': False, 'error': '没有选择文件'}), 400

    files = request.files.getlist('files')
    if not files or all(f.filename == '' for f in files):
        return jsonify({'success': False, 'error': '没有选择文件'}), 400

    # 确保加密文件目录存在
    encrypted_folder = 'uploads/encrypted'
    if not os.path.exists(encrypted_folder):
        os.makedirs(encrypted_folder)
        
    # 计算3小时前的时间点用于检查同名文件
    from models import beijing_now
    from datetime import timedelta
    three_hours_ago = beijing_now() - timedelta(hours=3)

    success_count = 0
    errors = []

    for file in files:
        if not allowed_file(file.filename):
            errors.append(f'{file.filename}: 不支持的文件类型')
            continue

        try:
            match = PATTERN.match(file.filename)
            if not match:
                errors.append(f'{file.filename}: 文件名格式错误')
                continue

            identifier, amount, count = match.groups()
            client = User.query.filter_by(identifier=identifier, is_admin=False).first()
            if not client:
                errors.append(f'{file.filename}: 未找到匹配的客户（标识符：{identifier}）')
                continue
                
            # 检查是否在过去3小时内上传过同名文件（忽略时间戳）
            # 提取文件基本名称（不包含时间戳），格式例如: 红_W2胜负3倍投_金额111元_4张
            base_filename = None
            if match := re.match(r'^(.+?)_(.+?)_金额(\d+)元_(\d+)张.*?\.txt$', file.filename):
                identifier = match.group(1)
                content = match.group(2)
                amount = match.group(3)
                count = match.group(4)
                # 构建基本文件名（不含时间戳）
                base_filename = f"{identifier}_{content}_金额{amount}元_{count}张"
            
            if base_filename:
                # 使用LIKE查询匹配相似文件名（忽略时间戳）
                recent_duplicate = File.query.filter(
                    File.filename.like(f"{base_filename}%"),
                    File.uploaded_at >= three_hours_ago
                ).first()
            else:
                # 如果无法解析文件名，则使用完整文件名比较
                recent_duplicate = File.query.filter(
                    File.filename == file.filename,
                    File.uploaded_at >= three_hours_ago
                ).first()
            
            # 初始化文件重复警告列表（如果不存在）
            if not hasattr(file, '_duplicate_warning'):
                file._duplicate_warning = None
                
            if recent_duplicate:
                # 格式化上传时间
                upload_time = recent_duplicate.uploaded_at.strftime("%Y-%m-%d %H:%M:%S")
                # 仍然上传文件，但记录警告信息
                warning_msg = f'检测到相似文件已在过去3小时内上传：{recent_duplicate.filename} (上传时间: {upload_time})'
                file._duplicate_warning = warning_msg
                app.logger.warning(warning_msg)

            # 确保上传目录存在
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

            # 生成唯一文件名并保存原始文件
            unique_filename = generate_unique_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)

            # 创建原始文件记录
            file_record = File(
                filename=file.filename,  # 保存原始文件名
                stored_filename=unique_filename,  # 新增：保存实际存储的文件名
                client_id=client.id,
                status=FileStatus.PENDING,
                amount=Decimal(amount),
                count=int(count)
            )
            db.session.add(file_record)
            db.session.flush()  # 获取file_record.id

            # 生成加密文件
            from utils.encryptor import encrypt_file, generate_encrypted_filename
            
            # 生成加密文件名
            encrypted_filename = generate_encrypted_filename(unique_filename)
            encrypted_filepath = os.path.join(encrypted_folder, encrypted_filename)
            
            # 获取用户关联的所有设备ID列表
            device_ids = []
            user_devices = DeviceRegistry.query.filter_by(user_id=client.id, is_authorized=True).all()
            if user_devices:
                device_ids = [device.device_id for device in user_devices]
                app.logger.info(f"为标识符 {identifier} 找到 {len(device_ids)} 个已授权设备，将用于加密")
            else:
                app.logger.info(f"标识符 {identifier} 没有关联设备，使用纯标识符加密")
            
            # 加密文件
            encryption_success = encrypt_file(filepath, encrypted_filepath, identifier, device_ids)
            
            if not encryption_success:
                errors.append(f'{file.filename}: 文件加密失败')
                db.session.rollback()
                if os.path.exists(filepath):
                    os.remove(filepath)
                continue
            
            # 创建加密文件记录
            encrypted_record = EncryptedFile(
                original_file_id=file_record.id,
                encrypted_filename=encrypted_filename
            )
            db.session.add(encrypted_record)

            # 创建状态日志
            status_log = StatusLog(
                file=file_record,
                old_status=None,
                new_status=FileStatus.PENDING.value,
                changed_by_id=current_user.id
            )
            db.session.add(status_log)

            try:
                db.session.commit()
                success_count += 1
                
                # 记录详细信息，包括是否有重复文件警告
                audit_details = {
                    'filename': file.filename,
                    'stored_filename': unique_filename,
                    'encrypted_filename': encrypted_filename,
                    'client_id': client.id,
                    'amount': str(amount),
                    'count': count
                }
                
                # 如果有重复文件警告，添加到审计日志
                if hasattr(file, '_duplicate_warning') and file._duplicate_warning:
                    audit_details['duplicate_warning'] = file._duplicate_warning
                    # 复制警告到当前文件对象以便在响应中收集
                    file_record._duplicate_warning = file._duplicate_warning

                audit_logger.log(
                    user=current_user,
                    action_type='file_upload_success',
                    ip_address=request.remote_addr,
                    details=audit_details
                )
            except Exception as db_error:
                db.session.rollback()
                # 清理文件
                if os.path.exists(filepath):
                    os.remove(filepath)
                if os.path.exists(encrypted_filepath):
                    os.remove(encrypted_filepath)
                errors.append(f'{file.filename}: 数据库错误 - {str(db_error)}')

        except Exception as e:
            db.session.rollback()
            errors.append(f'{file.filename}: {str(e)}')
            app.logger.error(f"File upload error: {str(e)}")
            audit_logger.log(
                user=current_user,
                action_type='file_upload_error',
                ip_address=request.remote_addr,
                details={'error': str(e), 'filename': file.filename}
            )

    # 检查文件序号是否连续
    sequence_warnings = check_sequence_continuity(files)
    
    # 收集所有重复文件警告
    duplicate_warnings = []
    for file in files:
        if hasattr(file, '_duplicate_warning') and file._duplicate_warning:
            duplicate_warnings.append(file._duplicate_warning)

    # 合并所有警告
    all_warnings = duplicate_warnings + sequence_warnings
    
    response = {
        'success': True,
        'message': f'成功上传 {success_count} 个文件',
        'errors': errors if errors else None,
        'warnings': all_warnings if all_warnings else None
    }
    
    return jsonify(response)

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            # 检查是否可以添加新设备
            if not user.can_add_device():
                flash('该账号已达到最大在线设备数限制。', 'danger')
                audit_logger.log(
                    user=user,
                    action_type='login_failed_device_limit',
                    ip_address=request.remote_addr,
                    details={'username': user.username, 'reason': 'max_devices_reached'}
                )
                return render_template('login.html', title='登录', form=form)

            # 生成新的会话ID并登录
            login_user(user, remember=form.remember.data)
            new_session_id = os.urandom(24).hex()
            user.update_session(new_session_id)

            audit_logger.log(
                user=user,
                action_type='login_success',
                ip_address=request.remote_addr,
                details={'username': user.username, 'remember_me': form.remember.data}
            )
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            audit_logger.log(
                user=None,
                action_type='login_failed',
                ip_address=request.remote_addr,
                details={'attempted_username': form.username.data}
            )
            flash('登录失败。请检查用户名和密码。', 'danger')
    return render_template('login.html', title='登录', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    settings = SystemSettings.get_settings()
    if not settings.registration_enabled:
        flash('当前不允许注册新用户。', 'warning')
        return redirect(url_for('login'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            identifier=form.identifier.data if form.identifier.data else None
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        audit_logger.log(
            user=user,
            action_type='user_registration',
            ip_address=request.remote_addr,
            details={'username': user.username, 'identifier': user.identifier}
        )

        flash('注册成功！现在您可以登录了。', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='注册', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if current_user.is_admin:
        return render_template('dashboard.html', title='控制面板')
    else:
        files = File.query.filter_by(client_id=current_user.id)\
                         .order_by(File.uploaded_at.desc())\
                         .paginate(page=page, per_page=per_page)
        return render_template('dashboard.html', title='控制面板', files=files)

@app.route('/admin')
@app.route('/admin/<int:nocache>')  # 添加nocache参数用于强制浏览器刷新
@login_required
@admin_required
def admin(nocache=None):
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # 获取在线用户并按需求单量排序
    online_users = User.query.filter_by(is_online=True, is_admin=False)\
                           .order_by(User.order_count.desc())\
                           .all()

    users = User.query.filter_by(is_admin=False)\
                     .order_by(User.created_at.desc())\
                     .paginate(page=page, per_page=per_page)

    files = File.query.order_by(File.uploaded_at.desc())\
                     .paginate(page=page, per_page=per_page)

    settings = SystemSettings.get_settings()

    response = make_response(render_template('admin.html', 
                         title='管理员控制面板',
                         users=users,
                         online_users=online_users,
                         files=files,
                         settings=settings))
    # 添加禁用缓存头
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def _is_valid_status_transition(current_status, new_status):
    """验证状态转换是否合法
    规则：
    1. PENDING -> RECEIVED, REVOKED
    2. RECEIVED -> COMPLETED, REVOKED
    3. COMPLETED -> 不允许任何转换
    4. REVOKED -> 不允许任何转换
    """
    transitions = {
        FileStatus.PENDING: [FileStatus.RECEIVED.value, FileStatus.REVOKED.value],
        FileStatus.RECEIVED: [FileStatus.COMPLETED.value, FileStatus.REVOKED.value],
        FileStatus.COMPLETED: [],  # 完成状态不允许任何转换
        FileStatus.REVOKED: []     # 撤销状态不允许任何转换
    }
    return new_status in transitions.get(current_status, [])

@app.route('/api/files/<int:file_id>/note', methods=['PUT'])
@login_required
def update_file_note(file_id):
    """更新文件备注"""
    file = File.query.get_or_404(file_id)
    
    # 验证权限（只允许文件所有者或管理员编辑）
    if file.client_id != current_user.id and not current_user.is_admin:
        audit_logger.log(
            user=current_user,
            action_type='unauthorized_file_edit',
            ip_address=request.remote_addr,
            details={'file_id': file_id}
        )
        return jsonify({'status': 'error', 'message': '无权修改此文件'}), 403
    
    data = request.get_json()
    new_note = data.get('note', '').strip()
    
    # 更新备注
    file.note = new_note
    db.session.commit()
    
    audit_logger.log(
        user=current_user,
        action_type='update_file_note',
        ip_address=request.remote_addr,
        details={'file_id': file_id, 'note': new_note}
    )
    
    return jsonify({'status': 'success', 'message': '备注已更新'})

@app.route('/api/files/<int:file_id>/status', methods=['PUT'])
@login_required
def update_file_status(file_id):
    """更新文件状态
    确保状态转换的合法性和事务的完整性
    """
    try:
        file = File.query.get_or_404(file_id)
        data = request.get_json()
        new_status = data.get('status')

        # 验证状态转换是否合法
        if not _is_valid_status_transition(file.status, new_status):
            audit_logger.log(
                user=current_user,
                action_type='invalid_status_transition',
                ip_address=request.remote_addr,
                details={
                    'file_id': file_id,
                    'current_status': file.status.value,
                    'attempted_status': new_status
                }
            )
            return jsonify({'error': '非法的状态转换'}), 409

        # 验证权限
        if new_status == FileStatus.REVOKED.value and not current_user.is_admin:
            audit_logger.log(
                user=current_user,
                action_type='unauthorized_status_change',
                ip_address=request.remote_addr,
                details={
                    'file_id': file_id,
                    'attempted_status': new_status
                }
            )
            return jsonify({'error': '没有权限执行此操作'}), 403

        old_status = file.status.value

        # 开始事务
        try:
            # 如果状态变更为completed，调用set_completed方法设置完成时间
            if new_status == FileStatus.COMPLETED.value:
                file.set_completed()
            else:
                file.status = FileStatus(new_status)

            # 如果文件状态变更为received，减少客户的需求单量
            if new_status == FileStatus.RECEIVED.value:
                file.client.decrement_order_count()

            # 记录状态变更
            status_log = StatusLog(
                file=file,
                old_status=old_status,
                new_status=new_status,
                changed_by_id=current_user.id
            )
            db.session.add(status_log)
            db.session.commit()

            audit_logger.log(
                user=current_user,
                action_type='status_change_success',
                ip_address=request.remote_addr,
                details={
                    'file_id': file_id,
                    'old_status': old_status,
                    'new_status': new_status
                }
            )

            return jsonify({'status': 'success'})

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Status update transaction failed: {str(e)}")
            return jsonify({'error': '状态更新失败'}), 500

    except Exception as e:
        app.logger.error(f"Status update error: {str(e)}")
        return jsonify({'error': '状态更新处理失败'}), 500

@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        current_user.clear_session()

    audit_logger.log(
        user=current_user,
        action_type='logout',
        ip_address=request.remote_addr,
        details={'username': current_user.username}
    )
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/files/<int:file_id>/download')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)

    # 验证权限和下载条件
    if file.client_id != current_user.id and not current_user.is_admin:
        audit_logger.log(
            user=current_user,
            action_type='unauthorized_file_access',
            ip_address=request.remote_addr,
            details={'file_id': file_id}
        )
        return jsonify({'error': '权限不足'}), 403
        
    # 获取请求中的下载模式，默认为用户的客户端模式
    download_mode = request.args.get('mode', current_user.client_mode.value)
    
    try:
        # 基于下载模式和时间条件确定要下载的文件版本
        is_original_file = False  # 默认不是原始文件
        
        # 如果用户选择了DOWNLOAD模式（即非网页查看模式）
        if download_mode == ClientMode.DOWNLOAD.value:
            # 如果文件状态为完成且在2小时后，或管理员，则允许下载原始文件
            if file.can_download_original() or current_user.is_admin:
                # 返回原始文件
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_filename)
                is_original_file = True
                download_type = "original"
            # 否则，如果有加密版本，则返回加密版本
            elif file.can_download_encrypted():
                # 返回加密文件
                encrypted_file = file.encrypted_version
                if not encrypted_file:
                    return jsonify({'error': '文件加密版本不存在'}), 404
                filepath = os.path.join('uploads/encrypted', encrypted_file.encrypted_filename)
                download_type = "encrypted"
            else:
                # 既没有原始文件访问权限，也没有加密版本
                return jsonify({'error': '文件当前不可下载，请等待2小时后再试或联系管理员'}), 403
        # 如果是网页查看模式，始终返回原始文件（网页内容）
        else:  # ClientMode.WEBPAGE
            if not file.can_download():
                return jsonify({'error': '文件当前不可查看，请等待2小时后再试'}), 403
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_filename)
            is_original_file = True
            download_type = "original_preview"
        
        # 检查文件是否存在
        if not os.path.exists(filepath):
            app.logger.error(f"文件不存在: {filepath}")
            audit_logger.log(
                user=current_user,
                action_type='file_download_error',
                ip_address=request.remote_addr,
                details={'error': '文件不存在', 'file_id': file_id, 'filepath': filepath, 'download_type': download_type}
            )
            return jsonify({'error': '文件不存在或已被删除'}), 404

        # 设置文件名和Content-Disposition
        if is_original_file:
            display_filename = file.filename
        else:
            # 为加密文件添加后缀标识
            base_name, ext = os.path.splitext(file.filename)
            display_filename = f"{base_name}_加密{ext}"
        
        # 生成符合RFC 5987标准的文件名（现代浏览器）
        encoded_filename = quote(display_filename.encode('utf-8'))
        content_disposition = f"attachment; filename*=UTF-8''{encoded_filename}"

        # 生成ASCII回退文件名（旧浏览器）
        ascii_name = display_filename.encode('ascii', errors='ignore').decode().replace(' ', '_')
        content_disposition += f'; filename="{ascii_name}"'

        # 是否作为附件下载
        if download_mode == ClientMode.WEBPAGE.value:
            # 网页查看模式下，在浏览器中显示而非下载
            content_disposition = "inline"

        # 手动创建响应对象
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except Exception as e:
            app.logger.error(f"读取文件失败: {str(e)}")
            audit_logger.log(
                user=current_user,
                action_type='file_download_error',
                ip_address=request.remote_addr,
                details={'error': f'读取文件失败: {str(e)}', 'file_id': file_id, 'download_type': download_type}
            )
            return jsonify({'error': '读取文件失败，请联系管理员'}), 500

        response = Response(
            data,
            mimetype='text/plain; charset=utf-8',
            headers={'Content-Disposition': content_disposition}
        )

        # 记录成功下载
        audit_logger.log(
            user=current_user,
            action_type='file_download_success',
            ip_address=request.remote_addr,
            details={
                'file_id': file_id, 
                'filename': display_filename,
                'download_type': download_type,
                'client_mode': download_mode
            }
        )

        return response

    except Exception as e:
        app.logger.error(f"文件下载失败: {str(e)}")
        audit_logger.log(
            user=current_user,
            action_type='file_download_error',
            ip_address=request.remote_addr,
            details={'error': str(e), 'file_id': file_id}
        )
        return jsonify({'error': '文件下载失败，请联系管理员'}), 500
@app.route('/api/files/<int:file_id>/view_content')
@login_required
@admin_required
def view_file_content(file_id):
    """查看文件内容（仅限管理员）"""
    file = File.query.get_or_404(file_id)
    
    # 检查文件是否存在
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_filename)
    if not os.path.exists(filepath):
        return jsonify({
            'status': 'error',
            'message': '文件不存在或已被删除'
        }), 404
    
    try:
        # 读取文件内容，过滤空行
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # 过滤空行，只保留有内容的行
            non_empty_lines = [line.rstrip() for line in lines if line.strip()]
            content = '\n'.join(non_empty_lines)
        
        # 确保内容不为空，如果是空文件，明确说明
        if not content.strip():
            content = "[空文件]"
            
        app.logger.info(f"文件 {file.filename} 读取: 原始行数 {len(lines)}, 过滤后 {len(non_empty_lines)} 行")
            
        # 记录文件查看操作
        audit_logger.log(
            user=current_user,
            action_type='view_file_content',
            ip_address=request.remote_addr,
            details={'file_id': file_id, 'filename': file.filename}
        )
            
        return jsonify({
            'status': 'success',
            'filename': file.filename,
            'content': content
        })
    except Exception as e:
        app.logger.error(f"查看文件内容错误: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'读取文件内容失败: {str(e)}'
        }), 500

@app.route('/api/files/<int:file_id>/page/<int:page>')
@login_required
def get_file_page(file_id, page):
    file = File.query.get_or_404(file_id)

    # 验证权限
    if file.client_id != current_user.id and not current_user.is_admin:
        audit_logger.log(
            user=current_user,
            action_type='unauthorized_page_access',
            ip_address=request.remote_addr,
            details={'file_id': file_id, 'page': page}
        )
        return jsonify({'error': '没有权限访问此文件'}), 403

    try:
        # 更新当前页码
        file.current_page = page
        db.session.commit()

        # 图片生成功能已移除

        # 解析文件名信息
        match = re.match(r'^(.+?)_(.+?)_金额(\d+)元_(\d+)张\.txt$', file.filename)
        if not match:
            return jsonify({'error': '文件名格式错误'}), 400

        # 提取文件名数据
        filename_data = {
            'identifier': match.group(1),
            'content': match.group(2),
            'amount': match.group(3),
            'quantity': match.group(4)
        }

        # 获取文本内容以便文本模式渲染
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        if page >= len(lines) or page < 0:
            return jsonify({'error': '页码超出范围'}), 400

        # 解析当前行
        line = lines[page].strip()

        # 解析投注数据
        line_parts = line.split('|')
        selections = []
        if len(line_parts) > 1:
            selections_text = line_parts[1].split(',')
            for sel in selections_text:
                if match := re.match(r'(\d+)=(.+)', sel.strip()):
                    match_num, choices = match.groups()
                    selections.append({
                        'match_number': match_num,
                        'choices': choices.split('/')
                    })

        # 计算金额
        calculated_amount = None
        try:
            if len(line_parts) >= 4:
                calculated_amount = BettingCalculator.calculate({
                    'bet_code': line_parts[0],
                    'fields': {
                        s.split('=')[0]: s.split('=')[1].split('/')
                        for s in line_parts[1].split(',')
                    },
                    'base_multiplier': {
                        'base': 2
                    },
                    'final_multiplier': int(line_parts[3])
                })
        except Exception as e:
            app.logger.error(f"Amount calculation error: {str(e)}")

        # 返回结果，专注于HTML模式渲染
        return jsonify({
            'current_page': page,
            'total_pages': file.count,
            'text_content': {
                'filename_data': filename_data,
                'line': line,
                'selections': selections,
                'calculated_amount': calculated_amount,
                'bet_code': line_parts[0] if len(line_parts) > 0 else '',
                'multiplier': line_parts[3] if len(line_parts) > 3 else '1'
            }
        })
    except Exception as e:
        app.logger.error(f"Page access error: {str(e)}")
        audit_logger.log(
            user=current_user,
            action_type='page_access_error',
            ip_address=request.remote_addr,
            details={'error': str(e), 'file_id': file_id, 'page': page}
        )
        return jsonify({'error': '页面加载失败'}), 500

@app.route('/api/users/<int:user_id>/mode', methods=['PUT'])
@login_required
@admin_required
def update_user_mode(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({'error': '不能修改管理员的模式'}), 400

    data = request.get_json()
    new_mode = data.get('mode')
    
    # 记录旧模式
    old_mode = user.client_mode.value

    try:
        # 更新模式
        user.client_mode = ClientMode(new_mode)
        db.session.commit()

        audit_logger.log(
            user=current_user,
            action_type='client_mode_update',
            ip_address=request.remote_addr,
            details={
                'user_id': user_id,
                'old_mode': old_mode,
                'new_mode': new_mode
            }
        )
        
        app.logger.info(f"用户模式更改: {user.username} ({user_id}) 模式从 {old_mode} 变更为 {new_mode}")

        return jsonify({'status': 'success'})
    except ValueError:
        return jsonify({'error': '无效的客户端模式'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({'error': '不能重置管理员密码'}), 400

    try:
        # 生成随机密码
        new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        user.set_password(new_password)
        db.session.commit()

        audit_logger.log(
            user=current_user,
            action_type='password_reset',
            ip_address=request.remote_addr,
            details={'user_id': user_id}
        )

        return jsonify({'status': 'success', 'password': new_password})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    """删除用户及其所有文件（全新强制模式）"""
    try:
        app.logger.info(f"开始删除用户 ID: {user_id}")
        user = User.query.get_or_404(user_id)
        app.logger.info(f"用户信息: {user.username}, 管理员:{user.is_admin}")

        # 不允许删除管理员账号
        if user.is_admin:
            app.logger.warning(f"尝试删除管理员账号被拒绝: {user.username}")
            return jsonify({'error': '不能删除管理员账号'}), 400

        # 1. 先删除物理文件（无数据库依赖）
        # 获取用户相关的所有文件
        files = File.query.filter_by(client_id=user.id).all()
        app.logger.info(f"用户 {user.username} (ID: {user_id}) 有 {len(files)} 个文件需要删除")
        
        # 删除每个文件的关联的物理文件
        for file in files:
            # 删除原始文件
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_filename)
            if os.path.exists(filepath):
                os.remove(filepath)
                app.logger.info(f"已删除原始文件: {filepath}")
            else:
                app.logger.warning(f"文件不存在: {filepath}")
            
            # 查找并删除加密文件
            encrypted_file = EncryptedFile.query.filter_by(original_file_id=file.id).first()
            if encrypted_file:
                encrypted_path = os.path.join('uploads/encrypted', encrypted_file.encrypted_filename)
                if os.path.exists(encrypted_path):
                    os.remove(encrypted_path)
                    app.logger.info(f"已删除加密文件: {encrypted_path}")
                else:
                    app.logger.warning(f"加密文件不存在: {encrypted_path}")

        # 2. 使用SQL直接一次性解决所有数据库依赖
        app.logger.info("开始执行一次性SQL数据库清理操作")
        
        # 使用带事务的一次性SQL操作，处理所有外键约束
        try:
            # 创建参数化SQL，一次处理所有表关系
            db.session.execute(db.text("""
                START TRANSACTION;

                -- 先将所有引用该用户的外键设为NULL
                UPDATE notifications SET created_by_id = NULL WHERE created_by_id = :user_id;
                UPDATE status_logs SET changed_by_id = NULL WHERE changed_by_id = :user_id;
                UPDATE system_settings SET updated_by_id = NULL WHERE updated_by_id = :user_id;
                UPDATE device_codes SET user_id = NULL WHERE user_id = :user_id;
                UPDATE device_codes SET created_by_id = NULL WHERE created_by_id = :user_id;
                
                -- 删除审计日志
                DELETE FROM audit_logs WHERE user_id = :user_id;
                
                -- 删除用户会话
                DELETE FROM user_sessions WHERE user_id = :user_id;
                
                -- 删除设备注册
                DELETE FROM device_registry WHERE user_id = :user_id;
                
                -- 删除文件相关记录（按依赖顺序）
                DELETE FROM decryption_records 
                WHERE file_id IN (SELECT id FROM files WHERE client_id = :user_id);
                
                DELETE FROM status_logs 
                WHERE file_id IN (SELECT id FROM files WHERE client_id = :user_id);
                
                DELETE FROM encrypted_files 
                WHERE original_file_id IN (SELECT id FROM files WHERE client_id = :user_id);
                
                -- 删除文件
                DELETE FROM files WHERE client_id = :user_id;
                
                -- 最后删除用户
                DELETE FROM users WHERE id = :user_id;
                
                COMMIT;
            """), {"user_id": user_id})
            
            app.logger.info(f"用户 {user.username} (ID: {user_id}) 已通过一次性SQL操作成功删除")
            return jsonify({
                'status': 'success', 
                'message': f'用户 {user.username} 及其所有数据已成功删除'
            })
            
        except Exception as sql_error:
            app.logger.error(f"一次性SQL删除失败: {str(sql_error)}")
            
            # 尝试最后的补救措施
            try:
                app.logger.info("尝试使用特殊权限模式删除用户")
                # 临时禁用外键约束和触发器
                db.session.execute(db.text("""
                    DO $$
                    BEGIN
                        -- 开启特殊权限模式（禁用触发器）
                        SET session_replication_role = 'replica';
                        
                        -- 直接删除用户(PostgreSQL会忽略外键约束)
                        DELETE FROM users WHERE id = :user_id;
                        
                        -- 恢复正常模式
                        SET session_replication_role = 'origin';
                    END $$;
                """), {"user_id": user_id})
                
                app.logger.info(f"用户 ID: {user_id} 已通过特殊权限模式成功删除")
                return jsonify({
                    'status': 'success',
                    'message': f'用户删除成功（使用特殊权限模式）'
                })
            except Exception as final_e:
                app.logger.error(f"所有删除用户尝试均失败: {str(final_e)}")
                return jsonify({
                    'status': 'error',
                    'message': f'无法删除用户，所有尝试均已失败: {str(final_e)}'
                }), 500

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"删除用户操作异常: {str(e)}")
        return jsonify({'error': f'删除用户失败: {str(e)}'}), 500

@app.route('/api/users/increment-order-count', methods=['POST'])
@login_required
def increment_order_count():
    try:
        current_user.increment_order_count()
        return jsonify({'status': 'success', 'new_count': current_user.order_count})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/registration', methods=['PUT'])
@login_required
@admin_required
def update_registration_setting():
    try:
        data = request.get_json()
        enabled = data.get('enabled', True)

        settings = SystemSettings.get_settings()
        settings.registration_enabled = enabled
        db.session.commit()

        audit_logger.log(
            user=current_user,
            action_type='registration_setting_update',
            ip_address=request.remote_addr,
            details={'enabled': enabled}
        )

        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/current-info')
@login_required
def get_current_user_info():
    response = jsonify({
        'order_count': current_user.order_count,
        'is_online': current_user.is_online,
        'client_mode': current_user.client_mode.value  # 添加客户端模式信息
    })
    
    # 添加防缓存头信息
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/api/users/online')
@login_required
@admin_required
def get_online_users():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 6, type=int)  # 默认每页6条记录
    
    # 获取在线用户，按需求单数量排序
    online_users_query = User.query.filter_by(is_online=True, is_admin=False)\
                           .order_by(User.order_count.desc())
    
    # 获取在线用户总数
    total_online_users = online_users_query.count()
    
    # 分页处理
    pagination = online_users_query.paginate(page=page, per_page=per_page)
    online_users = pagination.items
    
    # 构建用户数据
    users_data = [{
        'id': user.id,  # 添加用户ID以便前端操作
        'username': user.username,
        'identifier': user.identifier,
        'client_mode': user.client_mode.value,
        'order_count': user.order_count,
        'max_devices': user.max_devices,
        'active_sessions': user.get_active_sessions_count(),
        'active_files': File.query.filter_by(
            client_id=user.id,
            status=FileStatus.RECEIVED
        ).count(),
        'completed_amount': user.get_completed_amount()
    } for user in online_users]
    
    # 构建分页信息
    response = jsonify({
        'users': users_data,
        'total_online': total_online_users,  # 添加在线用户总数
        'pagination': {
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page,
            'total': pagination.total,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev,
            'next_num': pagination.next_num,
            'prev_num': pagination.prev_num
        }
    })
    
    # 添加防缓存头信息
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/api/clients/list')
@login_required
@admin_required
def get_clients_list():
    """获取客户列表，用于客户筛选器"""
    clients = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
    clients_list = [{
        'id': client.id,
        'username': client.username,
        'identifier': client.identifier or ""
    } for client in clients]
    
    response = jsonify({
        'status': 'success',
        'clients': clients_list
    })
    
    # 添加防缓存头信息
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/api/files/list')
@login_required
def get_files_list():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # 获取筛选参数
    client_id = request.args.get('client_id', type=int)
    time_filter = request.args.get('time_filter', 'all')  # 新增：时间筛选参数，默认全部时间
    date_filter = request.args.get('date_filter')  # 新增：日期筛选参数，格式：YYYY-MM-DD
    
    # 添加防缓存头以确保每次请求都获取最新数据
    response = jsonify({"error": "初始化响应"})
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    if current_user.is_admin:
        # 基础查询
        files_query = File.query
        
        # 如果提供了客户ID，添加筛选条件
        if client_id:
            files_query = files_query.filter_by(client_id=client_id)
        
        # 新增：根据时间筛选
        from datetime import datetime, timedelta
        now = beijing_now()
        
        if time_filter == '12h':
            # 12小时以内
            time_threshold = now - timedelta(hours=12)
            files_query = files_query.filter(File.uploaded_at >= time_threshold)
        elif time_filter == '24h':
            # 24小时以内
            time_threshold = now - timedelta(hours=24)
            files_query = files_query.filter(File.uploaded_at >= time_threshold)
        elif date_filter:
            # 特定日期筛选
            try:
                filter_date = datetime.strptime(date_filter, '%Y-%m-%d')
                next_date = filter_date + timedelta(days=1)
                
                # 如果选择的是未来日期，返回空结果集
                if filter_date.date() > now.date():
                    files_query = files_query.filter(File.id == -1)  # 使用不可能满足的条件返回空结果集
                else:
                    files_query = files_query.filter(
                        File.uploaded_at >= filter_date,
                        File.uploaded_at < next_date
                    )
            except ValueError:
                # 如果日期格式不正确，忽略日期筛选
                pass
            
        # 添加排序
        files_query = files_query.order_by(File.uploaded_at.desc())
        
        # 分页
        files_pagination = files_query.paginate(page=page, per_page=per_page)
        
        response = jsonify({
            'files': [{
                'id': file.id,
                'display_id': file.display_id,
                'filename': file.filename,
                'client_username': file.client.username if file.client else 'unknown',
                'client_identifier': file.client.identifier if file.client else '',
                'amount': float(file.amount),
                'count': file.count,
                'status': file.status.value,
                'uploaded_at': file.uploaded_at.strftime('%Y-%m-%d %H:%M'),
                'uploaded_at_iso': file.uploaded_at.isoformat(),
                'note': file.note or "",
                'can_download': file.can_download()
            } for file in files_pagination.items],
            'pagination': {
                'page': files_pagination.page,
                'pages': files_pagination.pages,
                'per_page': files_pagination.per_page,
                'total': files_pagination.total,
                'has_next': files_pagination.has_next,
                'has_prev': files_pagination.has_prev,
                'next_num': files_pagination.next_num,
                'prev_num': files_pagination.prev_num
            }
        })
        
        # 添加防缓存头信息
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    else:
        files_query = File.query.filter_by(client_id=current_user.id).order_by(File.uploaded_at.desc())
        files_pagination = files_query.paginate(page=page, per_page=per_page)
        
        response = jsonify({
            'files': [{
                'id': file.id,
                'display_id': file.display_id,
                'filename': file.filename,
                'amount': float(file.amount),
                'count': file.count,
                'status': file.status.value,
                'uploaded_at': file.uploaded_at.strftime('%Y-%m-%d %H:%M'),
                'uploaded_at_iso': file.uploaded_at.isoformat(),
                'client_mode': current_user.client_mode.value,
                'note': file.note or "",
                'can_download': file.can_download()
            } for file in files_pagination.items],
            'pagination': {
                'page': files_pagination.page,
                'pages': files_pagination.pages,
                'per_page': files_pagination.per_page,
                'total': files_pagination.total,
                'has_next': files_pagination.has_next,
                'has_prev': files_pagination.has_prev,
                'next_num': files_pagination.next_num,
                'prev_num': files_pagination.prev_num
            }
        })
        
        # 添加防缓存头信息
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response

@app.route('/api/users/<int:user_id>/max-devices', methods=['PUT'])
@login_required
@admin_required
def update_max_devices(user_id):
    """更新用户允许的最大在线设备数"""
    try:
        user = User.query.get_or_404(user_id)
        if user.is_admin:
            return jsonify({'error': '不能修改管理员的设备限制'}), 400

        data = request.get_json()
        max_devices = data.get('max_devices')

        if not isinstance(max_devices, int) or max_devices < 0:
            return jsonify({'error': '设备数量必须是不小于0的整数'}), 400

        old_max_devices = user.max_devices
        sessions_removed = 0

        if max_devices == 0:
            # 如果设置为0，删除所有会话
            all_sessions = UserSession.query.filter_by(user_id=user.id).all()
            sessions_removed = len(all_sessions)
            user.update_max_devices(max_devices)  # 这会删除所有会话
        else:
            user.update_max_devices(max_devices)
            # 如果新的设备数限制小于当前活跃会话数，强制关闭多余的会话
            active_sessions = UserSession.query.filter_by(user_id=user.id)\
                .order_by(UserSession.last_seen.desc())\
                .all()

            if len(active_sessions) > max_devices:
                # 保留最近活跃的会话，删除其他的
                sessions_to_remove = active_sessions[max_devices:]
                sessions_removed = len(sessions_to_remove)
                for session in sessions_to_remove:
                    db.session.delete(session)

                # 如果还有活跃会话，保持用户在线
                user.is_online = max_devices > 0
                db.session.commit()

        audit_logger.log(
            user=current_user,
            action_type='update_max_devices',
            ip_address=request.remote_addr,
            details={
                'user_id': user_id,
                'old_max_devices': old_max_devices,
                'new_max_devices': max_devices,
                'sessions_removed': sessions_removed
            }
        )

        return jsonify({
            'status': 'success',
            'sessions_removed': sessions_removed
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-session')
@login_required
def check_session():
    """检查当前会话是否仍然有效
    
    改进的逻辑支持多设备同时登录，只验证当前设备的会话有效性，
    不会影响同一用户在其他设备上的会话
    """
    try:
        # 获取当前会话ID
        current_session_id = request.cookies.get('session_id') or current_user.session_id
        
        if not current_user.is_authenticated or not current_session_id:
            return jsonify({'valid': False, 'reason': 'session_expired'}), 401
            
        # 查找该用户的当前会话记录
        session = UserSession.query.filter_by(
            user_id=current_user.id,
            session_id=current_session_id
        ).first()

        if not session:
            # 当前设备的会话不存在，可能是已过期或被管理员终止
            return jsonify({'valid': False, 'reason': 'session_expired'}), 401

        # 更新最后活跃时间
        session.last_seen = beijing_now()
        db.session.commit()
            
        # 检查会话是否过期 (24小时未活动)
        if (beijing_now() - session.last_seen).total_seconds() > 86400:  # 24小时 = 86400秒
            return jsonify({'valid': False, 'reason': 'session_inactive'}), 401

        # 检查用户账号是否被限制登录 (max_devices设置为0)
        if current_user.max_devices == 0:
            return jsonify({'valid': False, 'reason': 'login_restricted'}), 401
            
        response = jsonify({
            'valid': True,
            'active_sessions': current_user.get_active_sessions_count(),
            'max_devices': current_user.max_devices
        })
        
        # 添加防缓存头信息
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    except Exception as e:
        app.logger.error(f"检查会话时出错: {str(e)}")
        return jsonify({'valid': False, 'reason': str(e)}), 500

@app.before_request
def before_request():
    """每次请求时检查用户会话是否有效并更新活动时间
    
    改进的机制支持多设备同时在线，只检查当前会话而不影响用户在其他设备上的会话
    """
    if current_user.is_authenticated:
        # 获取当前会话ID (从cookie或用户对象)
        current_session_id = request.cookies.get('session_id') or current_user.session_id
        
        # 检查session_id是否存在
        if not current_session_id:
            logout_user()
            flash('您的会话已过期，请重新登录。', 'warning')
            return redirect(url_for('login'))
        
        # 检查当前设备的会话是否在数据库中存在
        session = UserSession.query.filter_by(
            user_id=current_user.id,
            session_id=current_session_id
        ).first()
        
        if not session:
            # 当前设备的会话不存在，可能是已被管理员强制下线或清理过期会话
            logout_user()
            flash('您的会话已失效，请重新登录。', 'warning')
            return redirect(url_for('login'))
        
        # 检查用户账号是否被禁止登录 (max_devices设置为0)
        if current_user.max_devices == 0:
            logout_user()
            flash('您的账号已被禁止登录，请联系管理员。', 'warning')
            return redirect(url_for('login'))
            
        # 定期更新session的last_seen时间 (每5分钟更新一次，避免频繁更新数据库)
        now = beijing_now()
        if (now - session.last_seen).total_seconds() > 300:  # 5分钟 = 300秒
            session.last_seen = now
            db.session.commit()

# 通知栏相关API
@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    """获取最新的一条活跃通知 - 该API无需登录即可访问"""
    try:
        notification = Notification.query.filter_by(is_active=True)\
                                    .order_by(Notification.created_at.desc())\
                                    .first()
        
        result = {
            'status': 'success',
            'notification': None
        }
        
        if notification:
            result['notification'] = {
                'id': notification.id,
                'content': notification.content,
                'created_at': notification.created_at.strftime('%Y-%m-%d %H:%M'),
                'created_by': notification.created_by.username if notification.created_by else None
            }
        
        # 添加防缓存头信息
        response = jsonify(result)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    except Exception as e:
        app.logger.error(f"获取通知出错: {str(e)}")
        return jsonify({'status': 'error', 'message': f'获取通知失败: {str(e)}'}), 500

@app.route('/api/notifications', methods=['POST'])
@login_required
@admin_required
def create_notification():
    """创建新通知"""
    data = request.get_json()
    content = data.get('content', '').strip()
    
    if not content:
        return jsonify({'status': 'error', 'message': '通知内容不能为空'}), 400
    
    # 获取活跃的通知
    active_notification = Notification.query.filter_by(is_active=True).first()
    
    # 如果有活跃通知，将其设为不活跃
    if active_notification:
        active_notification.is_active = False
        
    # 创建新通知
    notification = Notification(
        content=content,
        created_by=current_user
    )
    # is_active 默认为 True
    
    db.session.add(notification)
    db.session.commit()
    
    audit_logger.log(
        user=current_user,
        action_type='create_notification',
        ip_address=request.remote_addr,
        details={'notification_id': notification.id, 'content': content}
    )
    
    return jsonify({
        'status': 'success', 
        'message': '通知创建成功',
        'notification': {
            'id': notification.id,
            'content': notification.content,
            'created_at': notification.created_at.strftime('%Y-%m-%d %H:%M'),
            'created_by': notification.created_by.username if notification.created_by else None
        }
    })

@app.route('/api/notifications/<int:notification_id>', methods=['PUT'])
@login_required
@admin_required
def update_notification(notification_id):
    """更新通知内容或激活状态"""
    notification = Notification.query.get_or_404(notification_id)
    data = request.get_json()
    
    if 'content' in data:
        notification.content = data['content'].strip()
    
    if 'is_active' in data:
        notification.is_active = bool(data['is_active'])
    
    db.session.commit()
    
    audit_logger.log(
        user=current_user,
        action_type='update_notification',
        ip_address=request.remote_addr,
        details={
            'notification_id': notification.id, 
            'content': notification.content,
            'is_active': notification.is_active
        }
    )
    
    return jsonify({
        'status': 'success', 
        'message': '通知更新成功'
    })

@app.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_notification(notification_id):
    """删除通知"""
    notification = Notification.query.get_or_404(notification_id)
    
    db.session.delete(notification)
    db.session.commit()
    
    audit_logger.log(
        user=current_user,
        action_type='delete_notification',
        ip_address=request.remote_addr,
        details={'notification_id': notification_id}
    )
    
    return jsonify({
        'status': 'success', 
        'message': '通知已删除'
    })

@app.context_processor
def inject_timestamp():
    """向所有模板注入当前时间戳，用于防止缓存"""
    return {'now': int(time.time())}

@app.context_processor
def inject_notifications():
    """向所有模板注入通知数据 - 只保留最新的一条通知"""
    if current_user.is_authenticated:
        notification = Notification.query.filter_by(is_active=True)\
                                       .order_by(Notification.created_at.desc())\
                                       .first()
        return {'notification': notification}
    return {'notification': None}

# ===== 设备管理API =====
@app.route('/api/devices', methods=['GET'])
@login_required
@admin_required
def get_devices():
    """获取所有注册设备列表"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    query = DeviceRegistry.query
    
    # 过滤条件
    identifier = request.args.get('identifier')
    if identifier:
        user = User.query.filter_by(identifier=identifier).first()
        if user:
            query = query.filter_by(user_id=user.id)
    
    # 排序
    sort_by = request.args.get('sort_by', 'last_active')
    if sort_by == 'last_active':
        query = query.order_by(DeviceRegistry.last_active.desc())
    elif sort_by == 'first_seen':
        query = query.order_by(DeviceRegistry.first_seen.desc())
    
    # 分页
    pagination = query.paginate(page=page, per_page=per_page)
    devices = pagination.items
    
    # 处理返回数据
    device_list = []
    for device in devices:
        # 获取关联的用户信息
        user_info = None
        if device.user_id:
            user = User.query.get(device.user_id)
            if user:
                user_info = {
                    'id': user.id,
                    'username': user.username,
                    'identifier': user.identifier
                }
        
        device_list.append({
            'id': device.id,
            'device_id': device.device_id,
            'device_name': device.device_name,
            'first_seen': device.first_seen.strftime('%Y-%m-%d %H:%M'),
            'last_active': device.last_active.strftime('%Y-%m-%d %H:%M'),
            'is_authorized': device.is_authorized,
            'client_info': device.client_info,
            'user': user_info
        })
    
    return jsonify({
        'devices': device_list,
        'pagination': {
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page,
            'total': pagination.total,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev,
            'next_num': pagination.next_num if pagination.has_next else None,
            'prev_num': pagination.prev_num if pagination.has_prev else None
        }
    })

@app.route('/api/devices/<int:device_id>/authorize', methods=['PUT'])
@login_required
@admin_required
def authorize_device(device_id):
    """授权或撤销设备授权"""
    device = DeviceRegistry.query.get_or_404(device_id)
    
    # 获取请求体中的授权状态
    data = request.get_json()
    authorize = data.get('authorize', True)
    
    device.authorize(authorize)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': '设备授权状态已更新',
        'device_id': device_id,
        'is_authorized': device.is_authorized
    })

@app.route('/api/devices/<int:device_id>/link', methods=['PUT'])
@login_required
@admin_required
def link_device_to_user(device_id):
    """将设备关联到特定用户"""
    device = DeviceRegistry.query.get_or_404(device_id)
    
    # 获取请求体中的用户ID或标识符
    data = request.get_json()
    user_id = data.get('user_id')
    identifier = data.get('identifier')
    
    # 根据用户ID或标识符查找用户
    user = None
    if user_id:
        user = User.query.get(user_id)
    elif identifier:
        user = User.query.filter_by(identifier=identifier).first()
    
    if not user:
        return jsonify({
            'status': 'error',
            'message': '未找到指定的用户'
        }), 404
    
    # 更新设备关联的用户
    device.user_id = user.id
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': '设备已关联到用户',
        'device_id': device_id,
        'user': {
            'id': user.id,
            'username': user.username,
            'identifier': user.identifier
        }
    })

@app.route('/api/devices/<string:device_id>/link-user', methods=['PUT'])
@login_required
@admin_required
def link_device_to_user_by_device_id(device_id):
    """通过设备ID将设备关联到用户"""
    # 查找设备记录，如果不存在则创建新的
    device = DeviceRegistry.query.filter_by(device_id=device_id).first()
    
    if not device:
        device = DeviceRegistry(device_id=device_id)
        db.session.add(device)
    
    # 获取请求体中的用户ID
    data = request.get_json()
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({
            'status': 'error',
            'message': '未提供用户ID'
        }), 400
    
    # 查找用户
    user = User.query.get(user_id)
    if not user:
        return jsonify({
            'status': 'error',
            'message': '未找到指定的用户'
        }), 404
    
    # 更新设备关联的用户
    device.user_id = user.id
    device.is_authorized = True  # 确保设备被授权
    db.session.commit()
    
    audit_logger.log(
        user=current_user,
        action_type='link_device_to_user',
        ip_address=request.remote_addr,
        details={
            'device_id': device_id,
            'user_id': user.id,
            'username': user.username
        }
    )
    
    return jsonify({
        'status': 'success',
        'message': '设备已关联到用户',
        'device_id': device_id,
        'user': {
            'id': user.id,
            'username': user.username,
            'identifier': user.identifier
        }
    })

@app.route('/api/devices/<string:device_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_device_by_id(device_id):
    """通过设备ID删除设备注册记录"""
    device = DeviceRegistry.query.filter_by(device_id=device_id).first_or_404()
    
    # 记录设备信息用于审计
    user_info = None
    if device.user_id:
        user = User.query.get(device.user_id)
        if user:
            user_info = {
                'id': user.id,
                'username': user.username,
                'identifier': user.identifier
            }
    
    db.session.delete(device)
    db.session.commit()
    
    audit_logger.log(
        user=current_user,
        action_type='delete_device',
        ip_address=request.remote_addr,
        details={
            'device_id': device_id,
            'user': user_info
        }
    )
    
    return jsonify({
        'status': 'success',
        'message': '设备已删除',
        'device_id': device_id
    })

# 移除冲突的路由，保留 /api/devices/<string:device_id> 处理所有设备删除请求
# 之前使用 device_id 作为数据库主键已不再适用

# 会话管理API
from datetime import timedelta

@app.route('/api/sessions/cleanup', methods=['POST'])
@login_required
@admin_required
def cleanup_inactive_sessions():
    """清理不活跃的会话
    
    请求参数:
    - hours: 不活跃时间（小时），超过此时间的会话将被清理，默认24小时
    """
    try:
        data = request.get_json()
        hours = data.get('hours', 24)
        
        # 确保hours是有效的数字
        try:
            hours = float(hours)
            if hours <= 0:
                return jsonify({'status': 'error', 'message': '时间必须大于0'}), 400
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': '无效的时间格式'}), 400
            
        # 获取清理前的会话数
        before_count = UserSession.query.count()
        
        # 执行清理
        deleted = UserSession.cleanup_inactive_sessions(timedelta(hours=hours))
        
        # 获取清理后的会话数
        after_count = UserSession.query.count()
        
        # 记录审计日志
        audit_logger.log(
            user=current_user,
            action_type='cleanup_sessions',
            ip_address=request.remote_addr,
            details={
                'hours': hours,
                'deleted_count': deleted,
                'before_count': before_count,
                'after_count': after_count
            }
        )
        
        return jsonify({
            'status': 'success',
            'message': f'已清理 {deleted} 个不活跃会话',
            'details': {
                'hours': hours,
                'before_count': before_count,
                'after_count': after_count
            }
        })
    except Exception as e:
        app.logger.error(f"清理会话时出错: {str(e)}")
        return jsonify({'status': 'error', 'message': f'清理会话失败: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>/devices', methods=['GET'])
@login_required
@admin_required
def get_user_devices(user_id):
    """获取用户关联的所有设备ID列表"""
    # 查找用户
    user = User.query.get_or_404(user_id)
    
    # 获取设备ID列表
    devices = DeviceRegistry.query.filter_by(user_id=user_id).all()
    device_list = [
        {
            'device_id': d.device_id,
            'device_name': d.device_name or '未命名设备',
            'first_seen': d.first_seen.strftime('%Y-%m-%d %H:%M') if d.first_seen else None,
            'last_active': d.last_active.strftime('%Y-%m-%d %H:%M') if d.last_active else None,
            'is_authorized': d.is_authorized
        }
        for d in devices
    ]
    
    audit_logger.log(
        user=current_user,
        action_type='get_user_devices',
        ip_address=request.remote_addr,
        details={'user_id': user_id, 'device_count': len(device_list)}
    )
    
    return jsonify({
        'status': 'success', 
        'user': {
            'id': user.id,
            'username': user.username,
            'identifier': user.identifier
        },
        'devices': device_list,
        'total_count': len(device_list)
    })