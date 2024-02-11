from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


class CreatePostForm(FlaskForm):
    title = StringField(label='title of post', validators=[DataRequired()])
    subtitle = StringField(label='subtitle of post', validators=[DataRequired()])
    img_url = StringField(label='background img url', validators=[URL()])
    author = StringField(label='author name', validators=[DataRequired()])
    body = CKEditorField(label='body of post', validators=[DataRequired()])
    submit = SubmitField(label='submit post')


# TODO: Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    name = StringField(label='username', validators=[DataRequired()])
    email = StringField(label='email id', validators=[DataRequired()])
    password = PasswordField(label='password', validators=[DataRequired()])
    submit = SubmitField()      # set label later in register and user_details update


# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = StringField(label='email id', validators=[DataRequired()])
    password = PasswordField(label='password', validators=[DataRequired()])
    submit = SubmitField(label='Login')
