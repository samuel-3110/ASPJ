from flask import Flask, render_template,request, jsonify, send_from_directory, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column
import shelve
from Forms import *
from dotenv import load_dotenv
from datetime import timedelta


db = SQLAlchemy()
load_dotenv()
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
db.init_app(app)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    img = db.Column(db.String(200))
    price = db.Column(db.Float, nullable=False)
    condition = db.Column(db.String(50))
    fav = db.Column(db.Boolean, default=False)

    def __init__(self, name, img, price, condition, fav=False):
        self.name = name
        self.img = img
        self.price = price
        self.condition = condition
        self.fav = fav

with app.app_context():
    db.drop_all()
    db.create_all()

    products_data = [
        ("Trinx Bicycle", "https://media.karousell.com/media/photos/products/2024/3/16/trinx_bicycle_1710574225_bfb46207_progressive_thumbnail.jpg", 950, "Like new", True),
        ("Trinx Bicycle", "https://media.karousell.com/media/photos/products/2024/3/16/trinx_bicycle_1710574225_bfb46207_progressive_thumbnail.jpg", 950, "Like new", True),
        ("Trinx Bicycle", "https://media.karousell.com/media/photos/products/2024/3/16/trinx_bicycle_1710574225_bfb46207_progressive_thumbnail.jpg", 950, "Like new", True),
        ("Trinx Bicycle", "https://media.karousell.com/media/photos/products/2024/3/16/trinx_bicycle_1710574225_bfb46207_progressive_thumbnail.jpg", 950, "Like new", True),
        ("Trinx Bicycle", "https://media.karousell.com/media/photos/products/2024/3/16/trinx_bicycle_1710574225_bfb46207_progressive_thumbnail.jpg", 950, "Like new", True)
    ]

    products = [Product(*data) for data in products_data]

    db.session.add_all(products)
    db.session.commit()


# conditions: "Heavily Used", "Well Used", "Lightly Used", "Like New", "Brand New"


@app.route("/")
def main():
    products = Product.query.all()
    return render_template("main.html", products=products)

@app.route("/sell")
def sell():
    return render_template("sell.html")


#sex demon junkee
from flask import Flask, request, jsonify, send_from_directory, redirect, render_template
import shelve

app = Flask(__name__, static_folder='')

DATABASE = 'reviews.db'

def get_all_reviews():
    with shelve.open(DATABASE) as db:
        reviews = db.get('reviews', [])
    return reviews

def save_review(rating, text):
    with shelve.open(DATABASE, writeback=True) as db:
        if 'reviews' not in db:
            db['reviews'] = []
        db['reviews'].append({'rating': rating, 'text': text})

@app.route('/get-reviews', methods=['GET'])
def get_reviews():
    reviews = get_all_reviews()
    return jsonify({'reviews': reviews})

@app.route('/submit-review', methods=['POST'])
def submit_review():
    data = request.json
    rating = data.get('rating')
    text = data.get('text')
    if rating and text:
        save_review(rating, text)
        return jsonify({'success': True})
    return jsonify({'success': False}), 400

@app.route('/delete-reviews')
def delete_reviews():
    return render_template( 'delete_reviews.html')

@app.route('/delete-review/<int:index>', methods=['DELETE'])
def delete_review(index):
    with shelve.open(DATABASE, writeback=True) as db:
        reviews = db.get('reviews', [])
        if 0 <= index < len(reviews):
            del reviews[index]
            db['reviews'] = reviews
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Review not found'}), 404

@app.route('/review')
def index():
    return render_template( 'index.html')

#YY
@app.route('/userprofile')
def user_profile():
    return render_template('userprofile.html')


@app.route('/profile:orders')
def orders():
    return render_template('orders.html')


@app.route('/fconfirm')
def forgotconfirm():
    return render_template('forgotconfirm.html')


@app.route('/rconfirm')
def resetconfirm():
    return render_template('resetconfirm.html')


@app.route('/rfail')
def resetfail():
    return render_template('resetfail.html')


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


@app.route('/sconfirm')
def signupconfirm():
    return render_template('signupconfirm.html')


@app.route('/logout')
def logout():
    session.pop('id', None)
    return redirect(url_for('home'))


@app.route('/signup', methods=['GET', 'POST'])
def create_user():
    create_user_form = CreateUserForm(request.form)
    if request.method == 'POST' and create_user_form.validate():
        return redirect(url_for('signupconfirm'))
    return render_template('signup.html', form=create_user_form)


@app.route('/loginpage', methods=['GET', 'POST'])
def login_check():
    user_login_form = UserLogin(request.form)
    if request.method == 'POST' and user_login_form.validate():
        x = ["1", "John", "john@gmail.com", "abcdefg",
             "earth", "12345678"]
        session["id"] = x
        session.permanent = True
        return redirect(url_for('home'))
    return render_template('loginpage.html', form=user_login_form)


@app.route('/loginfail', methods=['GET', 'POST'])
def loginfail():
    user_login_form = UserLogin(request.form)
    if request.method == 'POST' and user_login_form.validate():
        x = ["1", "John", "john@gmail.com", "abcdefg",
             "earth", "12345678"]
        session["id"] = x
        session.permanent = True
        return redirect(url_for('home'))
    return render_template('loginfail.html', form=user_login_form)


@app.route('/update:address', methods=['GET', 'POST'])
def update_address():
    new_address = newaddress(request.form)
    if request.method == 'POST' and new_address.validate():
        x = session['id']
        x[4] = new_address.mailing_address.data
        session["id"] = x
        return redirect(url_for('user_profile'))
    return render_template('userprofileaddress.html', form=new_address)


@app.route('/update:username', methods=['GET', 'POST'])
def update_username():
    new_username = newusername(request.form)
    if request.method == 'POST' and new_username.validate():
        x = session['id']
        x[1] = new_username.username.data
        session["id"] = x
        return redirect(url_for('user_profile'))
    return render_template('userprofileusername.html', form=new_username)


@app.route('/update:phone', methods=['GET', 'POST'])
def update_phone():
    new_phone = newphone(request.form)
    if request.method == 'POST' and new_phone.validate():
        x = session['id']
        x[5] = new_phone.phone.data
        session["id"] = x
        return redirect(url_for('user_profile'))
    return render_template('userprofilephone.html', form=new_phone)


@app.route('/update:password', methods=['GET', 'POST'])
def update_password():
    new_password = newpassword(request.form)
    if request.method == 'POST' and new_password.validate():
        return redirect(url_for('user_profile'))
    return render_template('userprofilepassword.html', form=new_password)


@app.route('/update:email', methods=['GET', 'POST'])
def update_email():
    new_email = newemail(request.form)
    if request.method == 'POST' and new_email.validate():
        x = session['id']
        x[2] = new_email.email.data
        session["id"] = x
        return redirect(url_for('user_profile'))
    return render_template('userprofileemail.html', form=new_email)


@app.route('/deleteaccount', methods=['GET', 'POST'])
def delete_account():
    delete = deleteaccount(request.form)
    if request.method == 'POST' and delete.validate():
        session.pop('id', None)
        return redirect(url_for('deleteconfirm'))
    return render_template('deleteaccount.html', form=delete)


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/deleteconfirm')
def deleteconfirm():
    return render_template('deleteconfirm.html')

@app.before_request
def func():
    session.modified = True

if __name__ == '__main__':
    app.run(debug=True)


if __name__== "__main__":
    app.run(debug=True)
