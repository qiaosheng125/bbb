#!/usr/bin/env python
"""
会话清理工具

此脚本用于清理不活跃的用户会话，应当定期运行
"""

from datetime import timedelta
from app import app, db
from models import UserSession, User

def clean_inactive_sessions(hours=24):
    """清理指定时间内未活动的会话
    
    参数:
        hours: 未活动小时数，超过此时间的会话将被清理
    """
    with app.app_context():
        try:
            print(f"清理会话前: {UserSession.query.count()} 个会话")
            
            # 使用UserSession类的方法清理会话
            deleted = UserSession.cleanup_inactive_sessions(timedelta(hours=hours))
            
            print(f"已清理 {deleted} 个不活跃会话（超过 {hours} 小时未活动）")
            print(f"清理会话后: {UserSession.query.count()} 个会话")
            
            # 更新用户在线状态，确保没有会话的用户显示为离线
            users_with_no_session = User.query.filter(User.is_online == True).all()
            offline_count = 0
            
            for user in users_with_no_session:
                # 检查用户是否有活跃会话
                has_sessions = UserSession.query.filter_by(user_id=user.id).first() is not None
                
                if not has_sessions and user.is_online:
                    # 没有会话但状态为在线，将状态更新为离线
                    user.is_online = False
                    user.session_id = None
                    offline_count += 1
            
            if offline_count > 0:
                print(f"已将 {offline_count} 个无会话但状态为在线的用户更新为离线状态")
                db.session.commit()
                
            return deleted
                
        except Exception as e:
            print(f"清理会话时出错: {e}")
            db.session.rollback()
            return 0

if __name__ == "__main__":
    # 默认清理24小时未活动的会话
    clean_inactive_sessions(24)