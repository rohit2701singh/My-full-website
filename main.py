from flask import Flask, abort, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from forms import CreatePostForm, LoginForm, RegisterForm
from functools import wraps
from datetime import date
import os
from dotenv import load_dotenv  # to read .env file data
import smtplib

load_dotenv()

SENDER_EMAIL = os.getenv("SENDER_MAIL")  # my smtp mail
SENDER_PASS = os.getenv("SMTP_MAIL_PASSWORD")
RECEIVER_EMAIL = os.getenv("RECEIVER_MAIL")  # client's mail

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv('FLASK_KEY')
bootstrap = Bootstrap5(app)
ckeditor = CKEditor(app)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):     # If id is not 1 then return abort with 403 error
        if current_user.id != 1:    # id 1 means first user is admin
            return abort(403)
        return f(*args, **kwargs)     # Otherwise continue with the route function
    return decorated_function


# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def loader_user(user_id):
    return db.session.execute(db.select(User).where(User.id == user_id)).scalar()


# TODO: CONNECT TO Database(DB)
# DB_URI env name in host server,upgrade sqlite database to postgresql,server will provide database location/file name

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DB_URI", "sqlite:///posts.db")    # database name local server
db = SQLAlchemy()
db.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100),  unique=True,  nullable=False)
    password = db.Column(db.String(100), nullable=False)
    pet_name = db.Column(db.String(100), nullable=False)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    author = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


with app.app_context():
    db.create_all()

@app.route('/')
def home():
    posts = db.session.execute(db.select(BlogPost)).scalars().all()     # [<BlogPost 1(oldest)>, <BlogPost 2>, <BlogPost 3(latest created)>]
    return render_template("index.html", all_posts=posts[::-1], is_home_active=True)   # send latest first [<BlogPost 3>, <BlogPost 2>, <BlogPost 1>]


@app.route('/post')
def show_post():
    post_id = request.args.get('post_id', 1)     # if post_id not provided then take this num by default
    requested_post = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalar()
    return render_template("post_blog.html", blog=requested_post, is_show_post_active=True)


@app.route('/blog_collection')
def all_collection():
    all_data = db.session.execute(db.select(BlogPost)).scalars().all()
    return render_template("blog_collection.html", all_blog=all_data[::-1], is_all_collection_active=True)


@app.route('/recover', methods=['GET', 'POST'])
def account_recover():
    if request.method == 'POST':
        if "login" in request.form:
            recover_mail = request.form.get('mail').lower().strip()
            user_pet = request.form.get('pet').lower().strip()
            select_user = db.session.execute(db.select(User).where(User.email == recover_mail)).scalar()
            if select_user:
                pet_name_match = check_password_hash(pwhash=select_user.pet_name, password=user_pet)
                if recover_mail == select_user.email and pet_name_match:
                    login_user(select_user)  # for authentication
                    flash('Successfully logged in. Please update your information', 'success')
                    return render_template('user_details.html', current_user=current_user, is_user_detail_active=True )
                else:
                    flash("detail is incorrect. Pet name is wrong", 'warning')
                    return redirect(url_for('account_recover'))
            else:
                flash("email does not exist.", 'warning')
                return redirect(url_for('account_recover'))
        elif "cancel" in request.form:
            flash("account recovery cancelled", 'info')
            return redirect(url_for('home'))
        else:
            flash("please fill the details to register", 'info')
            return redirect(url_for('register'))
    return render_template('recover_account.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user_email = login_form.email.data.strip().lower()
        user_password = login_form.password.data
        select_user = db.session.execute(db.select(User).where(User.email == user_email)).scalar()

        if select_user:
            password_from_database = select_user.password
            match_password = check_password_hash(pwhash=password_from_database, password=user_password)
            if match_password:
                login_user(select_user)  # for authentication
                flash('successfully logged in', 'success')
                return redirect(url_for('home'))
            else:
                flash('password does not match, please enter again.', 'warning')
                return redirect(url_for('login'))
        else:
            flash('email does not exist, please register.', 'warning')
            return redirect(url_for('register'))

    return render_template("login.html", form=login_form, current_user=current_user, is_login_active=True)


# TODO: Werkzeug to hash the user's password when creating a new user.

@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()  # new fresh registration
    register_form.submit.label.text = 'register me!'   # submit buttons is dynamic for registration and update user info
    if register_form.validate_on_submit():
        user_name = register_form.name.data
        user_email = register_form.email.data.strip().lower()
        user_pet = register_form.pet.data.lower().strip()

        select_user = db.session.execute(db.select(User).where(User.email == user_email)).scalar()
        # print(current_user.is_authenticated)
        if select_user:
            if current_user.is_authenticated:
                flash('already registered with email, choose other email to register', 'warning')
                return redirect(url_for('register'))
            else:
                flash('already registered with email, login instead!', 'info')
                return redirect(url_for('login'))

        user_password = generate_password_hash(register_form.password.data, salt_length=8, method='pbkdf2:sha256:600000')
        pet_name_hash = generate_password_hash(user_pet, salt_length=8, method='pbkdf2:sha256:600000')

        new_user = User(username=user_name, email=user_email, password=user_password, pet_name=pet_name_hash)
        db.session.add(new_user)
        db.session.commit()

        # login_user(new_user)   # it will consider user as logged in without even entering details in login form

        if not current_user.is_authenticated:
            flash('registered successfully, please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('new user registered successfully', 'success')
            return redirect(url_for('home'))
    return render_template("register.html", form=register_form, current_user=current_user, is_register_active=True)


@app.route('/logout')
def logout():
    logout_user()
    flash('logged out successfully', 'success')
    return redirect(url_for('home'))


@app.route('/add_post', methods=["GET", "POST"])
@admin_only
def add_new_post():
    post_form = CreatePostForm()
    if post_form.validate_on_submit():
        title = post_form.title.data
        subtitle = post_form.subtitle.data
        img_url = post_form.img_url.data
        if not img_url or "https://" not in img_url:
            img_url = "static/images/default.jpg"
        author = post_form.author.data
        body = post_form.body.data
        # print(title, subtitle, img_url, author, body)

        add_in_database = BlogPost(
            title=title,
            subtitle=subtitle,
            img_url=img_url,
            author=author,
            body=body,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(add_in_database)
        db.session.commit()
        flash("new post added successfully", 'success')
        return redirect(url_for('home'))
    return render_template('make_post.html', form=post_form, current_user=current_user, is_add_post_active=True)


@app.route('/edit-post', methods=["GET", "POST"])
@admin_only
def edit_post():
    blog_id = request.args.get('post_id')
    post = db.session.execute(db.select(BlogPost).where(BlogPost.id == blog_id)).scalar()

    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        author=post.author,
        body=post.body,
        img_url=post.img_url,
        date=post.date
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        if not post.img_url or "https://" not in post.img_url:  # if img url not given then take default img
            post.img_url = "static/images/default.jpg"
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        flash("Post edit successful", 'success')
        return redirect(url_for("show_post", post_id=post.id))
    return render_template('make_post.html', form=edit_form, is_edit=True, current_user=current_user, is_edit_post_active=True)


@app.route('/delete')
@admin_only
def delete_post():
    blog_id = request.args.get('post_id')
    post_to_delete = db.session.execute(db.select(BlogPost).where(BlogPost.id == blog_id)).scalar()
    return render_template('confirm_delete.html', post=post_to_delete)


@app.route('/confirm_delete', methods=['GET', 'POST'])
def confirm_delete():
    if request.args.get('user_delete'):
        if request.method == "POST":
            # print(request.form.get('password'))
            if "delete" in request.form:
                password_from_database = current_user.password   # password in database are hashed
                user_password = request.form.get('password')
                if user_password:
                    match_password = check_password_hash(pwhash=password_from_database, password=user_password)
                    if match_password:
                        db.session.delete(current_user)
                        db.session.commit()
                        flash("account deleted successfully", 'success')
                        return redirect(url_for('home'))
                    else:
                        flash("Can't delete account, Please enter correct password", 'warning')
                        return redirect(url_for('user_details'))
                else:
                    flash("Can't delete account, Please enter your password", 'warning')
                    return redirect(url_for('user_details'))
            elif "cancel" in request.form:
                flash("Account deletion cancelled", 'info')
                return redirect(url_for('user_details'))

    else:
        post_id = request.args.get('post_id')
        if request.method == 'POST':
            if "delete" in request.form:
                post_to_delete = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalar()
                db.session.delete(post_to_delete)
                db.session.commit()
                flash(f'post {post_id} titled "{post_to_delete.title}" deleted successfully', 'success')
                return redirect(url_for('home'))
            elif "cancel" in request.form:
                flash("you chose not to delete the post", 'info')
                return redirect(url_for('home'))


@app.route('/user_account_delete')
def account_delete():
    return render_template('confirm_delete.html', current_user=current_user, want_account_del=True)


@app.route('/user_detail', methods=['GET', 'POST'])
def user_details():
    update_info = request.args.get('user_update')  # update logged in user's detail
    # print(update_info)
    if update_info:
        update_form = RegisterForm(name=current_user.username, email=current_user.email)
        update_form.submit.label.text = 'Update me!'    # set submit button label name (dynamic submit button with registration form)

        if update_form.validate_on_submit():
            user_name = update_form.name.data
            user_email = update_form.email.data.strip().lower()
            user_pet_name = update_form.pet.data.strip().lower()
            select_user = db.session.execute(db.select(User).where(User.email == user_email)).scalar()

            def update_user():
                user_old_data = db.session.execute(db.select(User).where(User.id == current_user.id)).scalar()
                user_old_data.username = user_name
                user_old_data.email = user_email
                user_old_data.password = generate_password_hash(update_form.password.data, salt_length=8, method='pbkdf2:sha256:600000')
                user_old_data.pet = user_pet_name
                db.session.commit()
                flash("User Details update successfully", 'success')

            if select_user:     # if email present and both are email same, then user can update
                if select_user.email == current_user.email:
                    update_user()
                    return redirect(url_for('user_details'))
                else:
                    flash("Can't change email. Email already exists. Choose another email.", 'warning')
                    return redirect(url_for('user_details'))
            else:
                update_user()
                return redirect(url_for('user_details'))

        return render_template('register.html', form=update_form, current_user=current_user, is_detail_update_active=True)
    return render_template("user_details.html", current_user=current_user, is_user_detail_active=True)  # ex. <user 3>


@app.route('/about')
def about():
    return render_template("about.html", current_user=current_user, is_about_active=True)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("login is required to contact.")
            return redirect(url_for("login"))

        user_name = request.form["name"]
        email = request.form["email"]
        user_message = request.form["message"]
        # print(user_message, user_name, email)
        if user_name and email:
            with smtplib.SMTP("smtp.gmail.com", 587) as connection:
                connection.starttls()
                connection.login(SENDER_EMAIL, SENDER_PASS)
                connection.sendmail(
                    from_addr=SENDER_EMAIL,
                    to_addrs=RECEIVER_EMAIL,
                    msg=f"subject: email from website\n\nuser: {user_name}\nemail id: {email}\nmessage: {user_message}"
                )
                flash("message sent successfully", 'success')
                return redirect(url_for('home', msg_sent=True))
        else:
            flash("message not sent", 'info')
            return redirect(url_for('home', msg_sent=False))


if __name__ == '__main__':
    app.run(debug=True)

