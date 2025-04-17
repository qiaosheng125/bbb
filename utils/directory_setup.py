"""
目录结构验证和设置模块
确保应用所需的文件夹结构存在并具有正确的权限
"""

import os
import logging

def ensure_upload_directories(app):
    """
    确保上传文件所需的目录结构存在，并设置适当的权限
    
    参数:
        app: Flask应用实例
    """
    upload_folder = app.config.get('UPLOAD_FOLDER', 'uploads')
    encrypted_folder = os.path.join(upload_folder, 'encrypted')
    
    # 确保主上传目录存在
    if not os.path.exists(upload_folder):
        try:
            os.makedirs(upload_folder, mode=0o755)
            app.logger.info(f"创建上传目录: {upload_folder}")
        except Exception as e:
            app.logger.error(f"创建上传目录失败: {str(e)}")
    
    # 确保加密文件目录存在
    if not os.path.exists(encrypted_folder):
        try:
            os.makedirs(encrypted_folder, mode=0o755)
            app.logger.info(f"创建加密文件目录: {encrypted_folder}")
        except Exception as e:
            app.logger.error(f"创建加密文件目录失败: {str(e)}")
    
    # 验证并修复目录权限
    try:
        # 主上传目录需要可写
        os.chmod(upload_folder, 0o755)
        # 加密文件目录也需要可写
        os.chmod(encrypted_folder, 0o755)
        app.logger.info(f"目录权限设置完成: {upload_folder}, {encrypted_folder}")
    except Exception as e:
        app.logger.error(f"设置目录权限失败: {str(e)}")
    
    # 统计目录中的文件数
    try:
        main_files_count = len([f for f in os.listdir(upload_folder) if os.path.isfile(os.path.join(upload_folder, f))])
        encrypted_files_count = len([f for f in os.listdir(encrypted_folder) if os.path.isfile(os.path.join(encrypted_folder, f))])
        app.logger.info(f"上传目录状态: 主目录文件数 {main_files_count}, 加密文件数 {encrypted_files_count}")
    except Exception as e:
        app.logger.error(f"统计文件数量失败: {str(e)}")
    
    return {
        'upload_folder': upload_folder,
        'encrypted_folder': encrypted_folder,
        'main_files_count': main_files_count if 'main_files_count' in locals() else -1,
        'encrypted_files_count': encrypted_files_count if 'encrypted_files_count' in locals() else -1
    }

def setup_file_storage(app):
    """
    设置文件存储系统，确保目录结构和配置正确
    
    参数:
        app: Flask应用实例
    """
    # 配置上传路径
    if 'UPLOAD_FOLDER' not in app.config:
        app.config['UPLOAD_FOLDER'] = 'uploads'
        app.logger.info(f"设置默认上传路径: {app.config['UPLOAD_FOLDER']}")
    
    # 确保必要目录存在
    directory_info = ensure_upload_directories(app)
    
    # 记录配置信息
    app.logger.info(f"文件存储系统就绪: 上传路径={directory_info['upload_folder']}")
    
    return directory_info