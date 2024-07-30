from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
from google.cloud import storage
from functools import wraps
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from Forms import *
from flask_mail import Mail, Message
from datetime import timedelta, datetime
from dotenv import load_dotenv
import hashlib
from itsdangerous import URLSafeTimedSerializer
import string, random

load_dotenv()
# If on Samuel's laptop
# os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'C:/Users/123sa/Desktop/SIT/Y2S1/Applications Security Project/Project/eloquent-walker-427707-e0-4e9f777acb39.json'
# If on Samuel's PC
os.environ[
    'GOOGLE_APPLICATION_CREDENTIALS'] = 'C:/Users/65915/Desktop/stuff 3/app sec/ASPJ-main/ASPJ-main/Project/eloquent-walker-427707-e0-4e9f777acb39.json'
app = Flask(__name__)
app.config['GOOGLE_CLOUD_PROJECT'] = 'eloquent-walker-427707-e0'
app.config['CLOUD_STORAGE_BUCKET'] = 'aspj_product_images'
app.secret_key = 'secret'
app.config['SECRET_KEY'] = 'secret'
app.config["SECURITY_PASSWORD_SALT"] = 'thisisasalt'
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://aspj:aspj@127.0.0.1:3306/aspj"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 25
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "relego432@gmail.com"
app.config['MAIL_PASSWORD'] = "gbalazubjuelgmhg "
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config["RECAPTCHA_PUBLIC_KEY"] = "6LfYnBYqAAAAAO-TOTSguVeW0r2t8H8vnGR11Zyn"
app.config["RECAPTCHA_PRIVATE_KEY"] = "6LfYnBYqAAAAAOv5H_3KkafVFtxdq5VnbRJIJqLK"
mail = Mail()
mail.init_app(app)
db = SQLAlchemy()
db.init_app(app)
csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.login_view = 'login_check'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    condition = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Numeric, nullable=False)
    description = db.Column(db.String(500))
    images = db.relationship('Image', backref='item', lazy=True, cascade="all, delete")
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('Users', backref='owned_items', lazy=True, cascade="all, delete")


class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    confirmed = db.Column(db.Integer, nullable=False, default=0)
    failed = db.Column(db.Integer, nullable=False, default=0)
    twofa = db.Column(db.Integer, nullable=False, default=0)
    otp = db.Column(db.String(10), nullable=True)
    admin = db.Column(db.Integer, nullable=False, default=0)
    banned = db.Column(db.Integer, nullable=False, default=0)


with app.app_context():
    db.create_all()


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)


def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = serializer.loads(
            token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration
        )
        return email
    except:
        return False


def logout_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            flash("You are already logged in.", "info")
            return redirect(url_for("home"))
        return func(*args, **kwargs)
    return decorated_function


def confirmed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.confirmed != 1:
            return redirect(url_for("inactive"))
        return func(*args, **kwargs)

    return decorated_function


def admin(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.admin != 1:
            flash("Access Denied", "info")
            return redirect(url_for("home"))
        return func(*args, **kwargs)
    return decorated_function


def generateOTP():
    otp = ''.join([random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for n in range(6)])
    return otp


def logging(email, status):
    logs = open('logs.txt', 'a')
    now = datetime.now()
    time = now.strftime("%d/%m/%Y %H:%M:%S")
    logs.write(time + ',' + email + ',' + status + '\n')
    logs.close()


def upload_to_gcs(file, bucket_name, destination_blob_name):
    """Uploads a file to Google Cloud Storage."""
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)
    blob.upload_from_file(file)

    return blob.public_url


@app.route('/')
def home():
    items = Item.query.all()
    return render_template("home.html", products=items)


# Sam Test
@app.route("/sell", methods=["GET", "POST"])
@login_required
@confirmed
def sell():
    form = ItemForm()
    if form.validate_on_submit():
        item = Item(
            name=form.name.data,
            category=form.category.data,
            condition=form.condition.data,
            price=form.price.data,
            description=form.description.data,
            user_id=current_user.id
        )
        db.session.add(item)
        db.session.commit()

        for file in form.images.data:
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                # Upload to Google Cloud Storage
                gcs_url = upload_to_gcs(file, app.config['CLOUD_STORAGE_BUCKET'], filename)
                image = Image(filename=gcs_url, item_id=item.id)
                db.session.add(image)

        db.session.commit()
        return redirect(url_for("home"))

    return render_template("sell.html", form=form)


@app.route('/products/<int:product_id>')
def product(product_id):
    product = Item.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)


# End of Sam Test


@app.route('/userprofile')
@login_required
@confirmed
def user_profile():
    return render_template('userprofile.html', username=current_user.username, email=current_user.email,
                           phone=current_user.phone, address=current_user.address)


@app.route('/admin')
@login_required
@admin
def admin_profile():
    logs = open('logs.txt', 'r')
    log_list = []
    for line in logs:
        x = line.split(',')
        y = x[0].split(' ')
        log = {"date": y[0], "time": y[1], "email": x[1], "status": x[2]}
        log_list.append(log)
    return render_template('adminprofile.html', username=current_user.username, log_list=log_list)


@app.route('/adminusers')
@login_required
@admin
def admin_users():
    users = Users.query.all()
    user_list = []
    for x in users:
        if x.banned == 0:
            status = "Active"
        else:
            status = "Banned"
        user = {"id": x.id, "username": x.username, "email": x.email, "banned": status}
        user_list.append(user)
    return render_template('adminusers.html', username=current_user.username, user_list=user_list)


@app.route('/banuser/<int:id>/')
@login_required
@admin
def ban(id):
    user = Users.query.filter_by(id=id).first()
    user.banned = 1
    db.session.commit()
    return redirect(url_for("admin_users"))


@app.route('/unbanuser/<int:id>/')
@login_required
@admin
def unban(id):
    user = Users.query.filter_by(id=id).first()
    user.banned = 0
    db.session.commit()
    return redirect(url_for("admin_users"))



@app.route('/profile:orders')
@login_required
@confirmed
def orders():
    return render_template('orders.html', username=current_user.username)


@app.route('/sconfirm')
@logout_required
def signupconfirm():
    return render_template('signupconfirm.html')


@app.route('/logout')
@login_required
def logout():
    logging(current_user.email, "Log Out")
    logout_user()
    return redirect(url_for('home'))


@app.route('/signup', methods=['GET', 'POST'])
@logout_required
def create_user():
    create_user_form = CreateUserForm(request.form)
    if request.method == 'POST' and create_user_form.validate():
        dupe = Users.query.filter_by(email=create_user_form.email.data).first()
        if dupe:
            flash('Email address already exists')
            return redirect(url_for('create_user'))
        today = datetime.today().strftime('%Y-%m-%d')
        passstr = f"{create_user_form.password.data}{today}"
        hashed = hashlib.sha256(passstr.encode())
        newuser = Users(username=create_user_form.username.data, password=hashed.hexdigest(), date=today,
                        email=create_user_form.email.data, phone=create_user_form.phone.data,
                        address=create_user_form.mailing_address.data, confirmed=0, failed = 0, twofa = 0, admin = 0, banned = 0)
        token = generate_token(create_user_form.email.data)
        confirm_url = url_for("confirm_email", token=token, _external=True)
        msg = Message()
        msg.subject = "Welcome!"
        msg.recipients = [create_user_form.email.data]
        msg.sender = 'relego432@gmail.com'
        msg.body = f'Welcome! Thanks for signing up. Please follow this link to activate your account: {confirm_url}'
        mail.send(msg)
        db.session.add(newuser)
        db.session.commit()
        logging(create_user_form.email.data, "Account Created")
        return redirect(url_for('signupconfirm'))
    return render_template('signup.html', form=create_user_form)


@app.route("/inactive")
@login_required
def inactive():
    if current_user.confirmed == 1:
        return redirect(url_for("home"))
    return render_template("inactive.html")


@app.route("/confirm/<token>")
@login_required
def confirm_email(token):
    if current_user.confirmed == 1:
        flash("Account already confirmed.", "success")
        return redirect(url_for("home"))
    email = confirm_token(token)
    user = Users.query.filter_by(email=current_user.email).first_or_404()
    if user.email == email:
        user.confirmed = 1
        db.session.commit()
        logging(email, "Account Confirmed")
        flash("You have confirmed your account. Thanks!", "success")
    else:
        flash("The confirmation link is invalid or has expired.", "danger")
    return redirect(url_for("home"))


@app.route("/resend")
@login_required
def resend_confirmation():
    if current_user.confirmed == 1:
        flash("Your account has already been confirmed.", "success")
        return redirect(url_for("home"))
    token = generate_token(current_user.email)
    confirm_url = url_for("confirm_email", token=token, _external=True)
    msg = Message()
    msg.subject = "Welcome!"
    msg.recipients = [current_user.email]
    msg.sender = 'relego432@gmail.com'
    msg.body = f'Welcome! Thanks for signing up. Please follow this link to activate your account: {confirm_url}'
    mail.send(msg)
    flash("A new confirmation email has been sent.", "success")
    return redirect(url_for("inactive"))


@app.route('/loginpage', methods=['GET', 'POST'])
@logout_required
def login_check():
    user_login_form = UserLogin(request.form)
    if request.method == 'POST' and user_login_form.validate():
        email_check = user_login_form.email_address_check.data
        password_check = user_login_form.password_check.data
        user = Users.query.filter_by(email=email_check).first()
        if not user:
            flash('Please check your login details and try again.')
            logging(email_check, "Login Fail (False Email)")
            return redirect(url_for('login_check'))
        if user.failed > 10:
            flash('Please reset your password.')
            logging(email_check, "Login Fail (Failures>10)")
            return redirect(url_for('login_check'))
        passstr = f"{password_check}{user.date}"
        hashed = hashlib.sha256(passstr.encode())
        if user.password == hashed.hexdigest():
            if user.admin == 1:
                user.failed = 0
                db.session.commit()
                logging(email_check, "Login Success (Admin)")
                login_user(user, remember=True)
                return redirect(url_for('admin_profile'))
            if user.banned == 1:
                flash('You have been banned.')
                logging(email_check, "Login Fail (Banned)")
                return redirect(url_for('login_check'))
            if user.twofa == 1:
                otp = generateOTP()
                user.otp = otp
                msg = Message()
                msg.subject = "Logging in?"
                msg.recipients = [user.email]
                msg.sender = 'relego432@gmail.com'
                msg.body = f'Thank you for enabling 2FA. Use this OTP to login: {otp}'
                mail.send(msg)
                token = generate_token(user.email)
                db.session.commit()
                return redirect(url_for('twofalogin', token=token, _external=True))
            user.failed = 0
            db.session.commit()
            logging(email_check, "Login Success")
            login_user(user, remember=True)
            next_page = request.args.get("next")
            return redirect(next_page or url_for('home'))
        flash('Please check your login details and try again.')
        user.failed += 1
        db.session.commit()
        logging(email_check, "Login Fail (False Password)")
        return redirect(url_for('login_check'))
    return render_template('loginpage.html', form=user_login_form)


@app.route("/2fa/<token>", methods=['GET', 'POST'])
@logout_required
def twofalogin(token):
    twofaform = twofa_otp(request.form)
    if request.method == 'POST' and twofaform.validate():
        email = confirm_token(token)
        user = Users.query.filter_by(email=email).first_or_404()
        otp = twofaform.otpcheck.data
        if user.otp == otp:
            user.failed = 0
            user.otp = None
            db.session.commit()
            logging(email, "Login Success")
            login_user(user, remember=True)
            next_page = request.args.get("next")
            return redirect(next_page or url_for('home'))
        flash('Wrong OTP. Please login again.')
        user.failed += 1
        user.otp = None
        db.session.commit()
        logging(email, "Login Fail (False 2FA)")
        return redirect(url_for('login_check'))
    return render_template('2facheck.html', form=twofaform)


@app.route('/forgot', methods=['GET', 'POST'])
@logout_required
def forgot():
    forgot_form = forgotpassword(request.form)
    if request.method == 'POST' and forgot_form.validate():
        email_check = forgot_form.email_address_check.data
        user = Users.query.filter_by(email=email_check).first()
        if user:
            email = user.email
            token = generate_token(email)
            reset_url = url_for("reset_password", token=token, _external=True)
            msg = Message()
            msg.subject = "Forgot your password?"
            msg.recipients = [email]
            msg.sender = 'relego432@gmail.com'
            msg.body = f'Forgot your password? No worries! Click this link to reset it: {reset_url}'
            mail.send(msg)
            return redirect(url_for('forgotconfirm'))
        return redirect(url_for('forgotconfirm'))
    return render_template('forgot.html', form=forgot_form)


@app.route("/reset/<token>", methods=['GET', 'POST'])
@logout_required
def reset_password(token):
    reset_form = forgotreset(request.form)
    if request.method == 'POST' and reset_form.validate():
        email = confirm_token(token)
        user = Users.query.filter_by(email=email).first_or_404()
        passstr = f"{reset_form.password.data}{user.date}"
        hashed = hashlib.sha256(passstr.encode())
        user.password = hashed.hexdigest()
        user.failed = 0
        db.session.commit()
        return redirect(url_for('resetconfirm'))
    return render_template('forgotreset.html', form=reset_form)


@app.route('/fconfirm')
@logout_required
def forgotconfirm():
    return render_template('forgotconfirm.html')


@app.route('/rconfirm')
@logout_required
def resetconfirm():
    return render_template('resetconfirm.html')


@app.route('/update:address', methods=['GET', 'POST'])
@login_required
@confirmed
def update_address():
    new_address = newaddress(request.form)
    if request.method == 'POST' and new_address.validate():
        current_user.address = new_address.mailing_address.data
        db.session.commit()
        return redirect(url_for('user_profile'))
    return render_template('userprofileaddress.html', form=new_address, username=current_user.username)


@app.route('/update:username', methods=['GET', 'POST'])
@login_required
@confirmed
def update_username():
    new_username = newusername(request.form)
    if request.method == 'POST' and new_username.validate():
        current_user.username = new_username.username.data
        db.session.commit()
        return redirect(url_for('user_profile'))
    return render_template('userprofileusername.html', form=new_username, username=current_user.username)


@app.route('/update:phone', methods=['GET', 'POST'])
@login_required
@confirmed
def update_phone():
    new_phone = newphone(request.form)
    if request.method == 'POST' and new_phone.validate():
        current_user.phone = new_phone.phone.data
        db.session.commit()
        return redirect(url_for('user_profile'))
    return render_template('userprofilephone.html', form=new_phone, username=current_user.username)


@app.route('/update:password', methods=['GET', 'POST'])
@login_required
@confirmed
def update_password():
    new_password = newpassword(request.form)
    if request.method == 'POST' and new_password.validate():
        passstr = f"{new_password.password_check.data}{current_user.date}"
        hashed = hashlib.sha256(passstr.encode())
        if hashed.hexdigest() == current_user.password:
            passstr = f"{new_password.password.data}{current_user.date}"
            hashed = hashlib.sha256(passstr.encode())
            current_user.password = hashed.hexdigest()
            db.session.commit()
            return redirect(url_for('user_profile'))
        flash("Old password is incorrect.")
        return redirect(url_for('update_password'))
    return render_template('userprofilepassword.html', form=new_password, username=current_user.username)


@app.route('/update:email', methods=['GET', 'POST'])
@login_required
@confirmed
def update_email():
    new_email = newemail(request.form)
    if request.method == 'POST' and new_email.validate():
        passstr = f"{new_email.password_check.data}{current_user.date}"
        hashed = hashlib.sha256(passstr.encode())
        if hashed.hexdigest() == current_user.password:
            dupe = Users.query.filter_by(email=new_email.email.data).first()
            if dupe:
                flash('Email address already exists.')
                return redirect(url_for('update_email'))
            current_user.email = new_email.email.data
            db.session.commit()
            return redirect(url_for('user_profile'))
        flash("Password is incorrect.")
        return redirect(url_for('update_email'))
    return render_template('userprofileemail.html', form=new_email, username=current_user.username)


@app.route('/2fasettings', methods=['GET', 'POST'])
@login_required
@confirmed
def twofa_settings():
    if current_user.twofa == 1:
        status = "enabled"
    else:
        status = "disabled"
    change_2fa = change2fa(request.form)
    if request.method == 'POST' and change_2fa.validate():
        passstr = f"{change_2fa.password_check.data}{current_user.date}"
        hashed = hashlib.sha256(passstr.encode())
        if hashed.hexdigest() == current_user.password:
            if current_user.twofa == 1:
                current_user.twofa = 0
            else:
                current_user.twofa = 1
            db.session.commit()
            return redirect(url_for('user_profile'))
        flash("Password is incorrect.")
        return redirect(url_for('twofa_settings'))
    return render_template('userprofile2fa.html', username=current_user.username, status=status , form=change_2fa)


@app.route('/deleteaccount', methods=['GET', 'POST'])
@login_required
@confirmed
def delete_account():
    delete = deleteaccount(request.form)
    if request.method == 'POST' and delete.validate():
        passstr = f"{delete.password_check.data}{current_user.date}"
        hashed = hashlib.sha256(passstr.encode())
        if hashed.hexdigest() == current_user.password:
            Item.query.filter_by(user_id=current_user.id).delete()
            Users.query.filter_by(id=current_user.id).delete()
            db.session.commit()
            logging(current_user.email, "Account Deleted")
            logout_user()
            return redirect(url_for('deleteconfirm'))
        flash("Password is incorrect.")
        return redirect(url_for('delete_account'))
    return render_template('deleteaccount.html', form=delete, username=current_user.username)


@app.route('/login')
@logout_required
def login():
    return render_template('login.html')


@app.route('/deleteconfirm')
@logout_required
def deleteconfirm():
    return render_template('deleteconfirm.html')


'''logging'''

if __name__ == "__main__":
    app.run(debug=True)