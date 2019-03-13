from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,UserMixin,login_user, current_user, login_required, logout_user
import forms.login as loginForm
import forms.registration as sign_up
import requests
app = Flask(__name__)


app.config['SECRET_KEY'] = 'e5b77268080253f3673595ae57b273be11bbbdba8de63e0b2ba131694e7e7354'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['PSK_HASH_KEY'] = 'aa2e9120eacc28e9e434f291ee047e1084daf08c96edad59bb269e6d0d6b6eb6'
db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(32), nullable=False)
    def __repr__(self):
        return f"User('{self.id}','{self.email}','{self.password}')"


class NewPost(db.Model):
    #id = db.Column(db.Integer,primary_key = True)
    caption = db.Column(db.String(1000))
    photo = db.Column(db.String(100),primary_key = True)
    def __repr__(self):
        return f"NewPost('{self.id}','{self.caption}','{self.photo}')"
login_manager = LoginManager(app)
login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
@app.route("/feeds/")
def getFeeds():
    options = [
    {"name":"Login","selected":False,"link":url_for("login")},#this is just temporary
    {"name":"Feed","selected":True,"link":url_for("getFeeds")},
    {"name":"My Profile","selected":False,"link":url_for("getProfile")},
    {"name":"My Network","selected":False,"link":url_for("getFriends")},
    {"name":"New Post","selected":False,"link":url_for("newPost")}
    ]
    return render_template("feed.html",title="Feed", nav_options = options, newpost = NewPost.query.all())
@app.route("/signup/",methods=["GET","POST"])
def signup():
    options = [
    {"name":"Login","selected":False,"link":url_for("login")},
    {"name":"Feed","selected":False,"link":url_for("getFeeds")},
    {"name":"My Profile","selected":False,"link":url_for("getProfile")},
    {"name":"My Network","selected":False,"link":url_for("getFriends")},
    {"name":"New Post","selected":False,"link":url_for("newPost")}
    ]
    signup_form = sign_up.RegistrationForm()
    if signup_form.validate_on_submit():
        print("Checking signup form")
        if User.query.filter_by(email=signup_form.emails.data).first():
            flash("E-mail already in use")
            return redirect("/register")
        elif User.query.filter_by(username=signup_form.usernames.data).first():
            flash("Username already in use")
            return redirect("/register")
        elif signup_form.passwords.data != signup_form.confirm_passwords.data:
            flash("Password mismatch")
            return redirect("/register")
        else:
            db.session.add(User(id=len(User.query.all()), username=signup_form.usernames.data,email=signup_form.emails.data,password=hashlib.sha512(bytes(signup_form.passwords.data + app.config['PSK_HASH_KEY'],'utf8')).hexdigest()))
            db.session.commit()
            return redirect("/login")
    return render_template("signup.html",title="Login",nav_options= options,signup_form = signup_form)
@app.route("/login/",methods=["GET","POST"])
def login():
    options = [
    {"name":"Sign Up","selected":False,"link":url_for("signup")},
    {"name":"Feed","selected":False,"link":url_for("getFeeds")},
    {"name":"My Profile","selected":False,"link":url_for("getProfile")},
    {"name":"My Network","selected":False,"link":url_for("getFriends")},
    {"name":"New Post","selected":False,"link":url_for("newPost")}
    ]
    login_form = loginForm.LoginForm()

    if login_form.validate_on_submit():
            if User.query.filter_by(email=login_form.emaill.data).first():
                if hashlib.sha512(bytes(login_form.passwordl.data + app.config['PSK_HASH_KEY'],'utf8')).hexdigest() == User.query.filter_by(email=login_form.emaill.data).first().password:
                    login_user(User.query.filter_by(email=login_form.emaill.data).first())
                    return redirect(url_for(getFeeds))
                else:
                    return redirect(url_for(login))
    return render_template("authenticate.html",title="Login",nav_options= options,login_form = login_form)

@app.route("/friends/")
def getFriends():
    options = [
    {"name":"Feed","selected":False,"link":url_for("getFeeds")},
    {"name":"My Profile","selected":False,"link":url_for("getProfile")},
    {"name":"My Network","selected":True,"link":url_for("getFriends")},
    {"name":"New Post","selected":False,"link":url_for("newPost")}
    ]
    return render_template("friends.html",title="Friends",nav_options= options)
@app.route("/profile/")
def getProfile():
    options = [
    {"name":"Feed","selected":False,"link":url_for("getFeeds")},
    {"name":"My Profile","selected":True,"link":url_for("getProfile")},
    {"name":"My Network","selected":False,"link":url_for("getFriends")},
    {"name":"New Post","selected":False,"link":url_for("newPost")}
    ]
    return render_template("profile.html",title="Profile",nav_options= options)
@app.route("/post/new/",methods = ['GET','POST'])
def newPost():
    options = [
    {"name":"Feed","selected":False,"link":url_for("getFeeds")},
    {"name":"My Profile","selected":False,"link":url_for("getProfile")},
    {"name":"My Network","selected":False,"link":url_for("getFriends")},
    {"name":"New Post","selected":True,"link":url_for("newPost")}
    ]
    if request.method == 'POST':
        if not request.form['photo']:
            flash('Please enter all the fields','error')
        else:
            post = NewPost(request.form['photo'],request.form['caption'])

            db.session.add(post)
            db.session.commit()
            flash("You Buzz has been posted")
        return redirect(url_for("getFeeds"))
    return render_template("newpost.html",title="newpost",nav_options= options)

if __name__ == "__main__":
    #db.create_all()
    app.run(debug=True)
