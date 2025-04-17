# 部署环境下文件下载问题解决方案

## 问题症状
在部署环境中，客户端点击下载文件时显示"下载失败，请稍后重试。如果问题持续存在，请联系管理员。"

## 可能的原因及解决方案

### 1. 路径问题
部署环境中的文件路径可能与开发环境不同。

**解决方案**:
- 确保部署环境中存在`uploads`和`uploads/encrypted`目录
- 修改文件路径为绝对路径

在部署服务器上运行以下命令:
```bash
# 创建必要的目录
mkdir -p /var/www/flask-app/uploads
mkdir -p /var/www/flask-app/uploads/encrypted

# 设置适当的权限
chmod -R 755 /var/www/flask-app/uploads
chown -R www-data:www-data /var/www/flask-app/uploads  # 使用相应的Web服务器用户
```

### 2. 文件权限问题
部署环境中文件权限可能不正确。

**解决方案**:
```bash
# 确保Web服务器用户有权限读取文件
find /var/www/flask-app/uploads -type f -exec chmod 644 {} \;
find /var/www/flask-app/uploads -type d -exec chmod 755 {} \;
```

### 3. 数据库记录与文件不匹配
数据库中的文件记录可能指向不存在的文件。

**解决方案**:
- 检查数据库中的文件记录与实际文件系统中的文件是否匹配
- 使用提供的`simple_decrypt_tool.py`工具重新生成加密文件

### 4. 应用程序代码需更新
修复下载函数的实现不完整问题。

**解决方案**:
- 确保部署环境中的`routes.py`文件包含完整的`download_file`函数实现
- 从Replit环境复制修改后的`routes.py`文件到部署环境
- 重启Web服务器使更改生效

### 5. 文件存储模式差异
部署环境可能使用不同的文件存储模式。

**解决方案**:
- 检查部署环境中的配置文件，确保`UPLOAD_FOLDER`路径正确
- 如果使用外部存储服务，确保路径和访问权限正确配置

## 快速验证步骤

1. 检查日志文件中的错误信息:
```bash
tail -f /var/log/flask-app/error.log
```

2. 手动验证文件是否存在:
```bash
# 获取数据库中文件的路径
psql -U <用户名> -d <数据库名> -c "SELECT id, stored_filename FROM files LIMIT 10;"

# 验证文件是否存在
ls -la /var/www/flask-app/uploads/<stored_filename>
```

3. 检查数据库中的加密文件记录:
```bash
psql -U <用户名> -d <数据库名> -c "SELECT e.id, e.original_file_id, e.encrypted_filename FROM encrypted_files e JOIN files f ON e.original_file_id = f.id LIMIT 10;"
```

4. 检查应用程序路径配置:
```bash
grep "UPLOAD_FOLDER" /var/www/flask-app/*.py
```

5. 手动测试文件下载API:
```bash
curl -v -H "Cookie: session=<有效会话Cookie>" http://<服务器地址>/api/files/1/download
```

## 部署后检查清单

- [ ] 确认`uploads`和`uploads/encrypted`目录存在且权限正确
- [ ] 验证数据库中的文件记录指向实际存在的文件
- [ ] 确认Web服务器有权限读取文件
- [ ] 更新应用程序代码，修复下载函数实现
- [ ] 重启Web服务器使更改生效
- [ ] 检查应用程序日志观察错误信息