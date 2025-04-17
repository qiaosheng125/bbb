with open('routes.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 在响应部分之前添加序号检查代码
old_code = """    # 收集所有重复文件警告
    duplicate_warnings = []
    for file in files:
        if hasattr(file, '_duplicate_warning') and file._duplicate_warning:
            duplicate_warnings.append(file._duplicate_warning)
    
    response = {
        'success': True,
        'message': f'成功上传 {success_count} 个文件',
        'errors': errors if errors else None,
        'warnings': duplicate_warnings if duplicate_warnings else None
    }
    """

new_code = """    # 检查文件序号是否连续
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
    """

content = content.replace(old_code, new_code)

with open('routes.py', 'w', encoding='utf-8') as f:
    f.write(content)
    
print("文件已修改")
