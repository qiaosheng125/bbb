from app import app
from scheduler import schedule_tasks

if __name__ == "__main__":
    # 启动定时任务
    scheduler = schedule_tasks()
    # 启动Flask应用
    app.run(host="0.0.0.0", port=5000, debug=True)