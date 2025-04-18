# 解密软件守护系统

## 系统组成
本守护系统由以下几个部分组成：
1. **decrypt_guardian.py** - 守护程序源代码
2. **decrypt_guardian.exe** - 打包后的守护程序可执行文件（由build_guardian.py生成）
3. **build_guardian.py** - 打包守护程序的脚本
4. **test_guardian.py** - 守护程序测试工具

## 功能说明
守护系统的主要功能是保护解密内容安全，防止解密软件被关闭后，解密内容泄露：

1. **实时监控**：
   - 监控解密软件的运行状态
   - 如果解密软件被关闭（如通过任务管理器强制结束），立即终止LBPrinter.exe进程

2. **自动启动**：
   - 解密软件启动时，自动启动守护程序
   - 如果守护程序已在运行，则不会重复启动

3. **防止关闭**：
   - 如果守护程序被关闭，解密软件会自动重新启动它
   - 守护程序在后台静默运行，不显示窗口

## 使用方法

### 基本使用
正常情况下，您只需要运行解密软件，守护程序会自动启动和运行。无需手动操作。

### 程序打包
如果需要重新打包守护程序，请按照以下步骤操作：

1. 运行 `build_guardian.py`
2. 等待打包完成（可能需要几分钟时间）
3. 成功后会在同一目录下生成 `decrypt_guardian.exe` 文件

### 测试功能
可以使用测试工具来验证守护程序的功能：

1. 运行 `test_guardian.py`
2. 使用界面上的按钮进行测试操作
3. 查看测试日志了解守护程序的行为

## 工作原理
1. 解密软件启动时，检查守护程序是否运行，如果没有则启动它
2. 解密软件每5秒检查一次守护程序是否在运行，如果不在则重新启动它
3. 守护程序每秒检查一次解密软件是否在运行
4. 如果守护程序发现解密软件不在运行，立即终止LBPrinter.exe进程
5. 守护程序使用管理员权限运行，以确保能够终止其他进程

## 日志文件
守护程序会在同目录下的logs文件夹中生成日志文件，格式为：`guardian_YYYYMMDD.log`。
日志记录包括：
- 程序启动和退出
- 解密软件状态变化
- 终止LBPrinter.exe的操作
- 错误信息

## 安全注意事项
- 守护程序需要管理员权限才能正常终止其他进程
- 如果系统安全策略限制进程操作，可能需要手动授予权限
- 在某些高安全级别的环境中，可能需要在安全策略中添加例外
