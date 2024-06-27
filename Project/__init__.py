from flask import Flask, render_template, redirect, url_for, request
from forms import ItemForm
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os


app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:C7L6raph4wUha&R#GA5$@localhost/ASPJ_DB"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')

db = SQLAlchemy()
db.init_app(app)
csrf = CSRFProtect(app)

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

if __name__ == "__main__":
    app.run(debug=True)
