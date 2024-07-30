'''
from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, validators, PasswordField, ValidationError
from wtforms.fields import EmailField, DateField
import shelve
from flask import Flask


class CreateUserForm(Form):
    username = StringField('Username', [validators.Length(min=1, max=30), validators.DataRequired()])
    email = EmailField('Email Address', [validators.Length(min=1, max=50), validators.DataRequired(), validators.email("Please enter a valid email address")])
    password = PasswordField('Password', [validators.Length(min=8, max=30), validators.DataRequired(), validators.equal_to('confirm', "Passwords must match")])
    confirm = PasswordField('Confirm Password')
    mailing_address = StringField('Mailing Address', [validators.Length(min=1, max=150), validators.DataRequired()])
    phone = StringField('Phone Number', [validators.Length(min=8, max=8), validators.DataRequired()])
    def validate_phone(form, phone):
        try:
            int(phone.data)
        except ValueError:
            raise ValidationError('Please enter a valid phone number')


class UserLogin(Form):
    email_address_check = StringField('Email Address', [validators.DataRequired()])
    password_check = PasswordField('Password', [validators.DataRequired()])


class forgotpassword(Form):
    email_address_check = StringField('Email Address', [validators.DataRequired()])


class forgotreset(Form):
    security = StringField('Security Code', [validators.DataRequired()])
    password = PasswordField('New Password', [validators.Length(min=8, max=30), validators.DataRequired(), validators.equal_to('confirm', "Passwords must match")])
    confirm = PasswordField('Confirm Password')


class newaddress(Form):
    mailing_address = StringField('New Mailing Address', [validators.Length(min=1, max=150), validators.DataRequired()])


class newusername(Form):
    username = StringField('New Username', [validators.Length(min=1, max=20), validators.DataRequired()])


class newphone(Form):
    phone = StringField('New Phone Number', [validators.Length(min=8, max=8), validators.DataRequired()])
    def validate_phone(form, phone):
        try:
            int(phone.data)
        except ValueError:
            raise ValidationError('Please enter a valid phone number')


class newpassword(Form):
    password_check = PasswordField('Old Password', [validators.DataRequired()])
    password = PasswordField('New Password', [validators.Length(min=8, max=30), validators.DataRequired(), validators.equal_to('confirm', "Passwords must match")])
    confirm = PasswordField('Confirm Password')


class newemail(Form):
    password_check = PasswordField('Password', [validators.DataRequired()])
    email = EmailField('New Email Address', [validators.Length(min=1, max=50), validators.DataRequired(),
                                         validators.email("Please enter a valid email address")])


class deleteaccount(Form):
    password_check = PasswordField('Enter Password to confirm', [validators.DataRequired()])
    '''
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, DecimalField, TextAreaField, SelectField, RadioField, SubmitField, validators, EmailField, PasswordField
from wtforms.validators import DataRequired, Length, NumberRange, ValidationError
from flask_wtf.file import MultipleFileField
import re


def validate_category(form, field):
    if field.data == "Select a category":
        raise ValidationError("Please select a valid category.")

class ItemForm(FlaskForm):
    images = MultipleFileField("Images", validators=[DataRequired()])
    name = StringField("Listing Title", validators=[DataRequired(), Length(max=100)])
    category = SelectField("Category", choices=[("Select a category", "Select a category"),("Beauty & Personal Care", "Beauty & Personal Care"), ("Computers & Tech", "Computers & Tech"), ("Everything Else", "Everything Else"), ("Food & Drinks", "Food & Drinks"), ("Furniture & Home Living", "Furniture & Home Living"), ("Health & Nutrition", "Health & Nutrition"), ("Men's Fashion", "Men's Fashion"), ("Women's Fashion", "Women's Fashion")], validators=[DataRequired(), validate_category])
    condition = RadioField("Condition", choices=[("Brand new", "Brand new"), ("Like new", "Like new"), ("Lightly used", "Lightly used"), ("Well used", "Well used"), ("Heavily used", "Heavily used")], validators=[DataRequired()])
    price = DecimalField("Price of your listing", validators=[DataRequired(), NumberRange(min=0)])
    description = TextAreaField("Description", validators=[Length(max=500)])
    submit = SubmitField("Submit")


class CreateUserForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=1, max=30), validators.DataRequired()])
    email = EmailField('Email Address', [validators.Length(min=1, max=74), validators.DataRequired(), validators.email("Please enter a valid email address")])
    password = PasswordField('Password', [validators.Length(min=8, max=30), validators.DataRequired(), validators.equal_to('confirm', "Passwords must match")])
    def validate_password(form, password):
        special_characters = "!@#$%^&*()-+?_=,<>/"
        if not any(x.isdigit() for x in password.data):
            raise ValidationError(
                "Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
        if not any(x.isupper() for x in password.data):
            raise ValidationError(
                "Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
        if not any(x.islower() for x in password.data):
            raise ValidationError(
                "Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
        if not any(x in special_characters for x in password.data):
            raise ValidationError(
                "Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
    confirm = PasswordField('Confirm Password', [validators.Length(min=8, max=30)])
    mailing_address = StringField('Mailing Address', [validators.Length(min=1, max=150), validators.DataRequired()])
    phone = StringField('Phone Number', [validators.Length(min=8, max=8), validators.DataRequired()])
    def validate_phone(form, phone):
        try:
            int(phone.data)
        except ValueError:
            raise ValidationError('Please enter a valid phone number')
    recaptcha = RecaptchaField()


class UserLogin(FlaskForm):
    email_address_check = StringField('Email Address', [validators.DataRequired(), validators.Length(min=1, max=74)])
    password_check = PasswordField('Password', [validators.DataRequired(), validators.Length(min=1, max=30)])
    recaptcha = RecaptchaField()


class twofa_otp(FlaskForm):
    otpcheck = StringField('OTP', [validators.DataRequired(), validators.Length(min=6, max=6)])


class forgotpassword(FlaskForm):
    email_address_check = StringField('Email Address', [validators.DataRequired(), validators.Length(min=1, max=74)])
    recaptcha = RecaptchaField()


class forgotreset(FlaskForm):
    password = PasswordField('New Password', [validators.Length(min=8, max=30), validators.DataRequired(), validators.equal_to('confirm', "Passwords must match")])
    def validate_password(form, password):
        special_characters = "!@#$%^&*()-+?_=,<>/"
        if not any(x.isdigit() for x in password.data):
            raise ValidationError("Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
        if not any(x.isupper() for x in password.data):
            raise ValidationError("Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
        if not any(x.islower() for x in password.data):
            raise ValidationError("Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
        if not any(x in special_characters for x in password.data):
            raise ValidationError("Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
    confirm = PasswordField('Confirm Password', [validators.Length(min=8, max=30)])


class newaddress(FlaskForm):
    mailing_address = StringField('New Mailing Address', [validators.Length(min=1, max=150), validators.DataRequired()])


class newusername(FlaskForm):
    username = StringField('New Username', [validators.Length(min=1, max=20), validators.DataRequired()])


class newphone(FlaskForm):
    phone = StringField('New Phone Number', [validators.Length(min=8, max=8), validators.DataRequired()])
    def validate_phone(form, phone):
        try:
            int(phone.data)
        except ValueError:
            raise ValidationError('Please enter a valid phone number')


class newpassword(FlaskForm):
    password_check = PasswordField('Old Password', [validators.DataRequired(), validators.Length(min=1, max=30)])
    password = PasswordField('New Password', [validators.Length(min=8, max=30), validators.DataRequired(), validators.equal_to('confirm', "Passwords must match")])
    def validate_password(form, password):
        special_characters = "!@#$%^&*()-+?_=,<>/"
        if not any(x.isdigit() for x in password.data):
            raise ValidationError(
                "Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
        if not any(x.isupper() for x in password.data):
            raise ValidationError(
                "Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
        if not any(x.islower() for x in password.data):
            raise ValidationError(
                "Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
        if not any(x in special_characters for x in password.data):
            raise ValidationError(
                "Password must contain at least one digit, one lowercase letter, one uppercase letter and one symbol")
    confirm = PasswordField('Confirm Password', [validators.Length(min=1, max=30)])


class newemail(FlaskForm):
    password_check = PasswordField('Password', [validators.DataRequired(), validators.Length(min=1, max=30)])
    email = EmailField('New Email Address', [validators.Length(min=1, max=74), validators.DataRequired(),
                                         validators.email("Please enter a valid email address")])


class deleteaccount(FlaskForm):
    password_check = PasswordField('Enter Password to confirm', [validators.DataRequired(), validators.Length(min=1, max=30)])


class change2fa(FlaskForm):
    password_check = PasswordField('Password', [validators.DataRequired(), validators.Length(min=1, max=30)])

