from flask import Flask, request, jsonify, make_response, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))

class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(500), unique=True)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('x-access-token')
        if not token:
            return redirect(url_for('login'))

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            blacklisted_token = TokenBlacklist.query.filter_by(token=token).first()
            if blacklisted_token:
                return redirect(url_for('login'))

            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return redirect(url_for('login'))

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        auth = request.form
        if not auth or not auth.get('email') or not auth.get('password'):
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm ="Login required !!"'})

        user = User.query.filter_by(email=auth.get('email')).first()
        if not user:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'})

        if check_password_hash(user.password, auth.get('password')):
            token = jwt.encode({'public_id': user.public_id, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
            response = make_response(redirect(url_for('home')))
            response.set_cookie('x-access-token', token)
            return response

        return make_response('Could not verify', 403, {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'})

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.form
        name, email = data.get('name'), data.get('email')
        password = data.get('password')

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(public_id=str(uuid.uuid4()), name=name, email=email, password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            return make_response('User already exists. Please Log in.', 202)

    return render_template('signup.html')

@app.route('/home')
@token_required
def home(current_user):
    return render_template('home.html', user=current_user)

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('x-access-token')
    return response

def create_database():
    if not os.path.exists('Database.db'):
        with app.app_context():
            db.create_all()

if __name__ == "__main__":
    create_database()
    app.run(debug=True)
