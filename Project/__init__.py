from flask import Flask, render_template,request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column
import shelve


db = SQLAlchemy()
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
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
    return send_from_directory('', 'delete_reviews.html')

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

@app.route('/')
def index():
    return send_from_directory('', 'index.html')

if __name__== "__main__":
    app.run(debug=True)
