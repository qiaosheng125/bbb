from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from app import app, db
from models import User, File, UserSession, beijing_now
from datetime import timedelta

def schedule_tasks():
    scheduler = BackgroundScheduler()

    # 每天中午12点执行文件清理
    scheduler.add_job(
        File.cleanup_old_files,
        trigger=CronTrigger(hour=12, minute=0),
        id='cleanup_files',
        name='Clean up old files',
        timezone='Asia/Shanghai'
    )

    # 每天凌晨1点清理未活动会话 (超过24小时未活动)
    scheduler.add_job(
        UserSession.cleanup_inactive_sessions,
        trigger=CronTrigger(hour=1, minute=0),
        id='cleanup_sessions',
        name='Clean up inactive sessions',
        timezone='Asia/Shanghai',
        args=[timedelta(hours=24)]
    )

    scheduler.start()
    return scheduler