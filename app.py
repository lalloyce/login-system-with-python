import os
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_wtf.csrf import CSRFProtect
import jwt
import datetime
import uuid
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'mysql://username:password@localhost/dbname')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@example.com'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
csrf = CSRFProtect(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    avatar = db.Column(db.String(120))
    is_verified = db.Column(db.Boolean, default=False)


@app.route('/register', methods=['POST'])
@csrf.exempt
def register():
    data = request.get_json()

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(
        public_id=str(uuid.uuid4()),
        name=data['name'],
        email=data['email'],
        password=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()

    token = serializer.dumps(new_user.email, salt='email-verification')

    msg = Message('Verify Your Email',
                  recipients=[new_user.email])
    msg.body = f'Click the following link to verify your email: http://yourdomain.com/verify/{token}'
    mail.send(msg)

    return jsonify({'message': 'New user created! Please check your email to verify your account.'}), 201


@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification', max_age=3600)
    except:
        return jsonify({'message': 'The verification link is invalid or has expired.'}), 400

    user = User.query.filter_by(email=email).first()
    if user.is_verified:
        return jsonify({'message': 'Account already verified. Please login.'}), 200
    else:
        user.is_verified = True
        db.session.commit()
        return jsonify({'message': 'You have successfully verified your account. You can now login.'}), 200


@app.route('/login', methods=['POST'])
@csrf.exempt
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({'message': 'Could not verify', 'WWW-Authenticate': 'Basic realm="Login required!"'}), 401

    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return jsonify({'message': 'Could not verify', 'WWW-Authenticate': 'Basic realm="Login required!"'}), 401

    if not user.is_verified:
        return jsonify({'message': 'Please verify your email before logging in.'}), 401

    if check_password_hash(user.password, auth.password):
        session['user_id'] = user.id
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'token': token}), 200

    return jsonify({'message': 'Could not verify', 'WWW-Authenticate': 'Basic realm="Login required!"'}), 401


@app.route('/profile', methods=['GET'])
@csrf.exempt
def get_profile():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401

    user = User.query.filter_by(public_id=data['public_id']).first()

    if not user:
        return jsonify({'message': 'User not found!'}), 404

    user_data = {
        'name': user.name,
        'email': user.email,
        'avatar': user.avatar
    }

    return jsonify({'user': user_data}), 200


@app.route('/profile', methods=['PUT'])
@csrf.exempt
def update_profile():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    except:
        return jsonify({'message': 'Token is invalid!'}), 401

    user = User.query.filter_by(public_id=data['public_id']).first()

    if not user:
        return jsonify({'message': 'User not found!'}), 404

    user_data = request.get_json()

    if 'name' in user_data:
        user.name = user_data['name']
    if 'email' in user_data and user_data['email'] != user.email:
        if User.query.filter_by(email=user_data['email']).first():
            return jsonify({'message': 'Email already in use'}), 400
        user.email = user_data['email']
        user.is_verified = False
        token = serializer.dumps(user.email, salt='email-verification')
        msg = Message('Verify Your New Email',
                      recipients=[user.email])
        msg.body = f'Click the following link to verify your new email: http://yourdomain.com/verify/{token}'
        mail.send(msg)
    if 'password' in user_data:
        user.password = generate_password_hash(user_data['password'], method='sha256')
    if 'avatar' in user_data:
        user.avatar = user_data['avatar']

    db.session.commit()

    return jsonify({'message': 'Profile updated successfully'}), 200


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Successfully logged out'}), 200


if __name__ == '__main__':
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

    app.run(ssl_context='adhoc', debug=False)