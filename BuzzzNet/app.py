from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import os.path
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'

db_path = os.path.join(os.path.dirname(__file__),'database.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri


Bootstrap(app)


db = SQLAlchemy(app)
login_manager = LoginManager() 
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

class LoginForm(FlaskForm):
	username = StringField('username', validators=[InputRequired(), Length(min=4,max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8,max=80)])
	remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

@app.route('/',methods=['GET', 'POST'])
def login():
	form = LoginForm()
	
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			login_user(user, remember=form.remember.data)
			if check_password_hash(user.password, form.password.data):
				return redirect(url_for('welcome'))
		
		return "<h1>" + "Invalid Username or password" + "</h1>"
		# flash("Invalid Username or Password")

	return render_template('login.html',form = form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        # if User.query.filter_by(username=form.username.data).first() == form.username.data:
        #     flash("Username already exits!")
        # else:
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/welcome')
@login_required
def welcome():
    return render_template('hello.html')


@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))


if __name__=='__main__':
	app.run(debug=True)