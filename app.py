from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import input_required, length, ValidationError, Email, EqualTo
from flask_bcrypt import Bcrypt

app = Flask(__name__, static_url_path='/static')
bcrypt = Bcrypt(app)

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'Ne15@0813'
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User model for the database


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

# Registration form


class RegisterForm(FlaskForm):
    username = StringField(validators=[input_required(), length(
        min=4, max=25)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[input_required(), Email()], render_kw={
                        "placeholder": "Email"})
    password = PasswordField(validators=[input_required(), length(
        min=4, max=25)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[input_required(), EqualTo(
        'password', message='Passwords must match')], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField("Register")

    # Custom validation for username
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different username")

    # Custom validation for email
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                "That email address is already registered. Please use a different email address")

# Login form


class LoginForm(FlaskForm):
    username = StringField(validators=[input_required(), length(
        min=4, max=25)], render_kw={"Placeholder": "Username"})
    password = PasswordField(validators=[input_required(), length(
        min=4, max=25)], render_kw={"Placeholder": "Password"})
    submit = SubmitField("Login")

# Load user for Flask-Login


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Homepage route


@app.route('/')
def index():
    return render_template('/index.html')

# Login route


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_ins = User.query.filter_by(username=form.username.data).first()
        if user_ins:
            if bcrypt.check_password_hash(user_ins.password, form.password.data):
                login_user(user_ins)
                return redirect(url_for('dashboard'))
            flash('Invalid password', 'error')
        flash('User not found!!', 'error')
    return render_template('login.html', form=form)

# Logout route


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Dashboard route


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

# Registration route


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data,
                        email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
