from flask import Flask, request, jsonify, make_response, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import uuid
import jwt
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))

# Define TokenBlacklist model
class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(500), unique=True)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

# Function to require a valid token for certain routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Route to render the home page
@app.route('/')
def index():
    return render_template('index.html')

# Route to get all users (requires a valid token)
@app.route('/get_users', methods=['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    output = []
    for user in users:
        output.append({'public_id': user.public_id, 'name': user.name, 'email': user.email})
    return jsonify({'users': output})


# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        auth = request.form
        if not auth or not auth.get('email') or not auth.get('password'):
            flash('Please enter both email and password.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=auth.get('email')).first()
        if not user:
            flash('User does not exist. Please sign up.', 'warning')
            return redirect(url_for('login'))

        if check_password_hash(user.password, auth.get('password')):
            token = jwt.encode({'public_id': user.public_id, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
            response = make_response(render_template('home.html', user=user, token=token))
            response.set_cookie('x-access-token', token)
            return response

        flash('Wrong password. Please try again.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

# Route for user signup
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
            flash('Successfully registered. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('User already exists. Please log in.', 'warning')
            return redirect(url_for('login'))
    return render_template('signup.html')

# Route for user logout
@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('x-access-token')
    flash('You have been logged out.', 'info')
    return response

# Function to create the database if it doesn't exist
def create_database():
    if not os.path.exists('Database.db'):
        with app.app_context():
            db.create_all()

if __name__ == "__main__":
    create_database()
    app.run(debug=True)
