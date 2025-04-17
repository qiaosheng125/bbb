from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, ValidationError
from models import User

class LoginForm(FlaskForm):
    username = StringField('用户名', 
                         validators=[DataRequired(), Length(min=2, max=32)])
    password = PasswordField('密码', validators=[DataRequired()])
    remember = BooleanField('记住我')
    submit = SubmitField('登录')

class RegistrationForm(FlaskForm):
    username = StringField('用户名', 
                         validators=[DataRequired(), Length(min=2, max=32)])
    password = PasswordField('密码', validators=[DataRequired()])
    identifier = StringField('标识符', validators=[Length(max=10)])
    submit = SubmitField('注册')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('用户名已存在，请选择其他用户名。')