from flask import Flask, render_template, redirect, url_for, request, session, flash
from forms import ItemForm
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
"""YY
from functools import wraps
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from Forms import *
from flask_mail import Mail, Message
from datetime import timedelta, datetime
from dotenv import load_dotenv
from sqlalchemy.orm import Mapped, mapped_column
import hashlib
from itsdangerous import URLSafeTimedSerializer
"""


app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:C7L6raph4wUha&R#GA5$@localhost/ASPJ_DB"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')

db = SQLAlchemy()
db.init_app(app)
csrf = CSRFProtect(app)

"""YY 
load_dotenv()
app = Flask(__name__)
app.secret_key = 'secret'
app.config['SECRET_KEY'] = 'secret'
app.config["SECURITY_PASSWORD_SALT"] = 'thisisasalt'
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://aspj:aspj@127.0.0.1:3306/aspj"
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 25
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "relego432@gmail.com"
app.config['MAIL_PASSWORD'] = "gbalazubjuelgmhg "
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
mail = Mail()
mail.init_app(app)
db = SQLAlchemy()
db.init_app(app)
"""

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    condition = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Numeric, nullable=False)
    description = db.Column(db.String(500))
    images = db.relationship('Image', backref='item', lazy=True)
    # user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)

with app.app_context():
    db.create_all()

@app.route("/")
def main():
    items = Item.query.all()
    return render_template("main.html", products=items)

@app.route("/sell", methods=["GET", "POST"])
def sell():
    form = ItemForm()
    if form.validate_on_submit():
        item = Item(
            name=form.name.data,
            category=form.category.data,
            condition=form.condition.data,
            price=form.price.data,
            description=form.description.data
        )
        db.session.add(item)
        db.session.commit()

        # Ensure upload folder exists
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

        for file in form.images.data:
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image = Image(filename=filename, item_id=item.id)
                db.session.add(image)
        
        db.session.commit()
        return redirect(url_for("main"))
    
    return render_template("sell.html", form=form)


'''YY
class Users(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str]
    password: Mapped[str]
    date: Mapped[str]
    email: Mapped[str]
    phone: Mapped[int]
    address: Mapped[str]
    confirmed: Mapped[str]

    def set_username(self, username):
        self.username = username

    def set_password(self, password):
        self.password = password

    def set_date(self, date):
        self.date = date

    def set_email(self, email):
        self.email = email

    def set_phone(self, phone):
        self.phone = phone

    def set_address(self, address):
        self.address = address

    def set_confirmed(self, confirmed):
        self.confirmed = confirmed


with app.app_context():
    db.create_all()


@app.before_request
def func():
    session.modified = True


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


@app.route('/')
def home():
    return render_template('home.html')


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
        if current_user.confirmed != "1":
            flash("Please confirm your account!", "warning")
            return redirect(url_for("inactive"))
        return func(*args, **kwargs)

    return decorated_function


@app.route('/userprofile')
@login_required
@confirmed
def user_profile():
    return render_template('userprofile.html', username=current_user.username, email=current_user.email, phone=current_user.phone, address=current_user.address)


@app.route('/profile:orders')
@login_required
@confirmed
def orders():
    return render_template('orders.html', username=current_user.username)


@app.route('/fconfirm')
def forgotconfirm():
    return render_template('forgotconfirm.html')


@app.route('/rconfirm')
def resetconfirm():
    return render_template('resetconfirm.html')


@app.route('/rfail')
def resetfail():
    return render_template('resetfail.html')


@app.route('/sconfirm')
@logout_required
def signupconfirm():
    return render_template('signupconfirm.html')


@app.route('/logout')
@login_required
def logout():
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
        newuser = Users()
        newuser.set_email(create_user_form.email.data)
        newuser.set_password(hashed.hexdigest())
        newuser.set_date(today)
        newuser.set_address(create_user_form.mailing_address.data)
        newuser.set_phone(create_user_form.phone.data)
        newuser.set_username(create_user_form.username.data)
        newuser.set_confirmed("0")
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
    if current_user.confirmed == "1":
        flash("Account already confirmed.", "success")
        return redirect(url_for("home"))
    email = confirm_token(token)
    user = Users.query.filter_by(email=current_user.email).first_or_404()
    if user.email == email:
        user.confirmed = "1"
        db.session.commit()
        flash("You have confirmed your account. Thanks!", "success")
    else:
        flash("The confirmation link is invalid or has expired.", "danger")
    return redirect(url_for("home"))


@app.route("/resend")
@login_required
def resend_confirmation():
    if current_user.confirmed == 1:
        flash("Your account has already been confirmed.", "success")
        return redirect(url_for("core.home"))
    token = generate_token(current_user.email)
    confirm_url = url_for("confirm_email", token=token, _external=True)
    subject = "Please confirm your email"
    msg = Message()
    msg.subject = "Welcome!"
    msg.recipients = [current_user.email.data]
    msg.sender = 'relego432@gmail.com'
    msg.body = f'Welcome! Thanks for signing up. Please follow this link to activate your account: {confirm_url}'
    mail.send(msg)
    flash("A new confirmation email has been sent.", "success")
    return redirect(url_for("inactive"))


login_manager = LoginManager()
login_manager.login_view = 'login_check'
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


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
            return redirect(url_for('login_check'))
        passstr = f"{password_check}{user.date}"
        hashed = hashlib.sha256(passstr.encode())
        if user.password != hashed.hexdigest():
            flash('Please check your login details and try again.')
            return redirect(url_for('login_check'))
        login_user(user, remember=True)
        return redirect(url_for('home'))
    return render_template('loginpage.html', form=user_login_form)


@app.route('/freset', methods=['GET', 'POST'])
def forgotresetpassword():
    reset_form = forgotreset(request.form)
    if request.method == 'POST' and reset_form.validate():
        return redirect(url_for('resetconfirm'))
    return render_template('forgotreset.html', form=reset_form)


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    forgot_form = forgotpassword(request.form)
    if request.method == 'POST' and forgot_form.validate():
        return redirect(url_for('forgotconfirm'))
    return render_template('forgot.html', form=forgot_form)


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
        if hashed.hexdigest() != current_user.password:
            flash("Old password is incorrect.")
            return redirect(url_for('update_password'))
        passstr = f"{new_password.password.data}{current_user.date}"
        hashed = hashlib.sha256(passstr.encode())
        current_user.password = hashed.hexdigest()
        db.session.commit()
        return redirect(url_for('user_profile'))
    return render_template('userprofilepassword.html', form=new_password, username=current_user.username)


@app.route('/update:email', methods=['GET', 'POST'])
@login_required
@confirmed
def update_email():
    new_email = newemail(request.form)
    if request.method == 'POST' and new_email.validate():
        passstr = f"{new_email.password_check.data}{current_user.date}"
        hashed = hashlib.sha256(passstr.encode())
        if hashed.hexdigest() != current_user.password:
            flash("Password is incorrect.")
            return redirect(url_for('update_email'))
        dupe = Users.query.filter_by(email=new_email.email.data).first()
        if dupe:
            flash('Email address already exists.')
            return redirect(url_for('update_email'))
        current_user.email = new_email.email.data
        db.session.commit()
        return redirect(url_for('user_profile'))
    return render_template('userprofileemail.html', form=new_email, username=current_user.username)


@app.route('/deleteaccount', methods=['GET', 'POST'])
@login_required
@confirmed
def delete_account():
    delete = deleteaccount(request.form)
    if request.method == 'POST' and delete.validate():
        passstr = f"{delete.password_check.data}{current_user.date}"
        hashed = hashlib.sha256(passstr.encode())
        if hashed.hexdigest() != current_user.password:
            flash("Password is incorrect.")
            return redirect(url_for('delete_account'))
        Users.query.filter_by(id=current_user.id).delete()
        db.session.commit()
        logout_user()
        return redirect(url_for('deleteconfirm'))
    return render_template('deleteaccount.html', form=delete, username=current_user.username)


@app.route('/login')
@logout_required
def login():
    return render_template('login.html')


@app.route('/deleteconfirm')
@logout_required
def deleteconfirm():
    return render_template('deleteconfirm.html')
'''

if __name__ == "__main__":
    app.run(debug=True)


""" Samuel's LASTEST Changes 20/7/2024
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
from sqlalchemy.orm import Mapped, mapped_column
import hashlib
from itsdangerous import URLSafeTimedSerializer


load_dotenv()
# If on Samuel's laptop
# os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'C:/Users/123sa/Desktop/SIT/Y2S1/Applications Security Project/Project/eloquent-walker-427707-e0-4e9f777acb39.json'
# If on Samuel's PC
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'G:/Other computers/My Laptop/SIT/Y2S1/Applications Security Project/Project/eloquent-walker-427707-e0-4e9f777acb39.json'
app = Flask(__name__)
app.config['GOOGLE_CLOUD_PROJECT'] = 'eloquent-walker-427707-e0'
app.config['CLOUD_STORAGE_BUCKET'] = 'aspj_product_images'
app.secret_key = 'secret'
app.config['SECRET_KEY'] = 'secret'
app.config["SECURITY_PASSWORD_SALT"] = 'thisisasalt'
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:C7L6raph4wUha&R#GA5$@localhost/ASPJ_DB"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 25
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "relego432@gmail.com"
app.config['MAIL_PASSWORD'] = "gbalazubjuelgmhg "
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
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


with app.app_context():
    db.create_all()


@app.before_request
def func():
    session.modified = True


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
            flash("Please confirm your account!", "warning")
            return redirect(url_for("inactive"))
        return func(*args, **kwargs)

    return decorated_function


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
    return render_template('userprofile.html', username=current_user.username, email=current_user.email, phone=current_user.phone, address=current_user.address)


@app.route('/profile:orders')
@login_required
@confirmed
def orders():
    return render_template('orders.html', username=current_user.username)


@app.route('/fconfirm')
def forgotconfirm():
    return render_template('forgotconfirm.html')


@app.route('/rconfirm')
def resetconfirm():
    return render_template('resetconfirm.html')


@app.route('/rfail')
def resetfail():
    return render_template('resetfail.html')


@app.route('/sconfirm')
@logout_required
def signupconfirm():
    return render_template('signupconfirm.html')


@app.route('/logout')
@login_required
def logout():
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
        newuser = Users(username=create_user_form.username.data, password=hashed.hexdigest(), date=today, email=create_user_form.email.data, phone=create_user_form.phone.data, address=create_user_form.mailing_address.data, confirmed=0)
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
    subject = "Please confirm your email"
    msg = Message()
    msg.subject = "Welcome!"
    msg.recipients = [current_user.email.data]
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
            return redirect(url_for('login_check'))
        passstr = f"{password_check}{user.date}"
        hashed = hashlib.sha256(passstr.encode())
        if user.password != hashed.hexdigest():
            flash('Please check your login details and try again.')
            return redirect(url_for('login_check'))
        login_user(user, remember=True)
        next_page = request.args.get("next")
        return redirect(next_page or url_for('home'))
    return render_template('loginpage.html', form=user_login_form)


@app.route('/freset', methods=['GET', 'POST'])
def forgotresetpassword():
    reset_form = forgotreset(request.form)
    if request.method == 'POST' and reset_form.validate():
        return redirect(url_for('resetconfirm'))
    return render_template('forgotreset.html', form=reset_form)


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    forgot_form = forgotpassword(request.form)
    if request.method == 'POST' and forgot_form.validate():
        return redirect(url_for('forgotconfirm'))
    return render_template('forgot.html', form=forgot_form)


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
        if hashed.hexdigest() != current_user.password:
            flash("Old password is incorrect.")
            return redirect(url_for('update_password'))
        passstr = f"{new_password.password.data}{current_user.date}"
        hashed = hashlib.sha256(passstr.encode())
        current_user.password = hashed.hexdigest()
        db.session.commit()
        return redirect(url_for('user_profile'))
    return render_template('userprofilepassword.html', form=new_password, username=current_user.username)


@app.route('/update:email', methods=['GET', 'POST'])
@login_required
@confirmed
def update_email():
    new_email = newemail(request.form)
    if request.method == 'POST' and new_email.validate():
        passstr = f"{new_email.password_check.data}{current_user.date}"
        hashed = hashlib.sha256(passstr.encode())
        if hashed.hexdigest() != current_user.password:
            flash("Password is incorrect.")
            return redirect(url_for('update_email'))
        dupe = Users.query.filter_by(email=new_email.email.data).first()
        if dupe:
            flash('Email address already exists.')
            return redirect(url_for('update_email'))
        current_user.email = new_email.email.data
        db.session.commit()
        return redirect(url_for('user_profile'))
    return render_template('userprofileemail.html', form=new_email, username=current_user.username)


@app.route('/deleteaccount', methods=['GET', 'POST'])
@login_required
@confirmed
def delete_account():
    delete = deleteaccount(request.form)
    if request.method == 'POST' and delete.validate():
        passstr = f"{delete.password_check.data}{current_user.date}"
        hashed = hashlib.sha256(passstr.encode())
        if hashed.hexdigest() != current_user.password:
            flash("Password is incorrect.")
            return redirect(url_for('delete_account'))
        Item.query.filter_by(user_id=current_user.id).delete()
        Users.query.filter_by(id=current_user.id).delete()
        db.session.commit()
        logout_user()
        return redirect(url_for('deleteconfirm'))
    return render_template('deleteaccount.html', form=delete, username=current_user.username)


@app.route('/login')
@logout_required
def login():
    return render_template('login.html')


@app.route('/deleteconfirm')
@logout_required
def deleteconfirm():
    return render_template('deleteconfirm.html')


if __name__ == "__main__":
    app.run(debug=True)


"""


