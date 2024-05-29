from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, validators, PasswordField, ValidationError
from wtforms.fields import EmailField, DateField
import shelve
from flask import session


class CreateUserForm(Form):
    username = StringField('Username', [validators.Length(min=1, max=20), validators.DataRequired()])
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