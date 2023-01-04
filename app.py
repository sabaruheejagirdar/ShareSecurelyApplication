# https://www.youtube.com/watch?v=71EU8gnZqZQ
# https://betterprogramming.pub/a-detailed-guide-to-user-registration-login-and-logout-in-flask-e86535665c07
# https://stackoverflow.com/questions/34122949/working-outside-of-application-context-flask
# https://stackoverflow.com/questions/34548846/flask-bcrypt-valueerror-invalid-salt
# https://www.youtube.com/watch?v=NYWEf9bZhHQ
# https://www.youtube.com/watch?v=q7HVghYjwYo
# Login Admin
# https://www.youtube.com/watch?v=1j3k-_DqobU
# https://www.youtube.com/watch?v=bjcIAKuRiJw
# https://stackoverflow.com/questions/40696745/adding-a-favicon-to-a-flask-server-without-html


# Import flask
from flask import Flask, render_template, url_for, redirect, flash, abort, send_from_directory
# For database connection using SQLAlchemy that provides SQLite
from flask_sqlalchemy import SQLAlchemy
# UserMixin is used to provide implementation for is is_active, is_authenticated, get_id(), is_anonymous
# LoginManager, login_required, logout_user is used to create a distinction betweeen the authenticated and unauthenticated users
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
# flask_wtf provides forms with CSRF(Cross Site Request Forgery)
from flask_wtf import FlaskForm
# From wtforms will be using basics string field, password field and submit
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
# For password encryption using the Bcrypt encryption
from flask_bcrypt import Bcrypt
# Admin access
from flask_admin import Admin
# To display the model(Users)
from flask_admin.contrib.sqla import ModelView
import os
import urllib.parse 

params = urllib.parse.quote_plus("DRIVER={SQL Server};SERVER=shareit.database.windows.net;DATABASE=shareit;UID=saba;PWD=Secure@123")

# Create a flask app that will be used for end points and rest
app = Flask(__name__)

# Bcrypt will accept the created flask as the parameter
bcrypt = Bcrypt(app)

# Connect with the SQLAlchemy Database
# app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['SQLALCHEMY_DATABASE_URI'] = "mssql+pyodbc:///?odbc_connect=%s" % params
# Secret Key can be any and I have generated using - import secrets; secrets.token_hex(16)
app.config['SECRET_KEY'] = '6f62d24f1546130f5a75d1a9b84764af'
# https://stackoverflow.com/questions/34122949/working-outside-of-application-context-flask
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.app_context().push()
db = SQLAlchemy(app)

# LoginManager binds this application with the Flask-login
login_manager = LoginManager()
# Initialize the loginManager with the Flask app that is created
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader callback is used to reload the user object from the user id stored in the session
@login_manager.user_loader
def load_user(user_id):
    print("User ID",user_id)
    ## If not loaded it gives this Exception: Missing user_loader or request_loader
    return User.query.get(int(user_id))

# UserMixin is used to provide implementation for is is_active, is_authenticated, get_id(), is_anonymous
# Creates a User table with fields and stores in the backend
class User(db.Model, UserMixin):
    # create ID
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(22), nullable=False, unique=True)
    password = db.Column(db.String(110), nullable=False)
    is_admin = db.Column(db.Boolean, default = False)

# What can be controlled by Admin is defined in the following class
class Controller(ModelView):
    # access admin page only if you're logged-in
    def is_accessible(self):
        if current_user.is_admin == True:
            return current_user.is_authenticated
        else:
            return abort(404)
    # if user is not authenticated
    def not_auth(self):
        return "Not Authorized to use Admin Panel"

admin = Admin(app, name="Admin Panel")
admin.add_view(Controller(User, db.session))

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)])
    submit = SubmitField('Register')

    # Can be removed###########
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)])
    submit = SubmitField('Login')


@app.route('/')
def index():
    return render_template('index.html', pageTitle = "HomePage")

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico',mimetype='image/vnd.microsoft.icon')

@app.route('/about')
def about():
    return render_template('about.html', pageTitle = "About")

@ app.route('/register', methods=['GET', 'POST'])
def register():
    # create a variable of registerForm
    form = RegisterForm()
    # Once registered then add the user to the database
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form, pageTitle = "Register Page")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Check if user is present in the database or not
        user = User.query.filter_by(username=form.username.data).first()
        # If user is present then check the password hash
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('userProfile'))
        flash("Please enter valid details")

    return render_template('login.html', form=form, pageTitle = 'Login')


# Only a loggedIn user can view the userProfile
@app.route('/userProfile', methods=['GET', 'POST'])
@login_required
def userProfile():
    return render_template('userProfile.html', pageTitle = 'userProfile', current_user = current_user)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))





if __name__ == "__main__":
    # app.run(debug=True, port=8095)
    app.run(debug=True)

# python3
# from app import db
# db.create_all()

# sqlite3 database.db
# .tables
