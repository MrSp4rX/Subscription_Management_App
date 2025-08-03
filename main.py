from apscheduler.schedulers.background import BackgroundScheduler
from flask import *
from flask_pymongo import PyMongo
import os
from helper import *
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
from bson import ObjectId
from dotenv import load_dotenv
import atexit
from functools import wraps
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MONGO_URI'] = os.getenv('MONGO_DB_URI')
mongo = PyMongo(app)
db = mongo.db
plan_durations = {
    'Basic': {
        'price': 5.99,
        'features': ['7 days access', '10 calls per day'],
        'renewal_days': 7,
        'end_days': 7
    },
    'Starter': {
        'price': 15.99,
        'features': ['30 days access', '50 calls per day'],
        'renewal_days': 30,
        'end_days': 30
    },
    'Pro': {
        'price': 39.99,
        'features': ['90 days access', '200 calls per day'],
        'renewal_days': 90,
        'end_days': 90
    },
    'Business': {
        'price': 79.99,
        'features': ['180 days access', '500 calls per day'],
        'renewal_days': 180,
        'end_days': 180
    },
    'Enterprise': {
        'price': 149.99,
        'features': ['365 days access', 'Unlimited calls'],
        'renewal_days': 365,
        'end_days': 365
    }
}

def expire_subscriptions():
    now = datetime.utcnow()
    expired = db.subscriptions.update_many(
        {'status': 'active', 'end_date': {'$lte': now}},
        {'$set': {'status': 'deactivated'}}
    )
    print(f"[{now}] Subscriptions expired: {expired.modified_count}")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired! Please log in again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def token_not_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if token:
            try:
                jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                return jsonify({'error': 'You are already logged in.'}), 403
            except jwt.ExpiredSignatureError:
                pass
            except jwt.InvalidTokenError:
                pass
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST', 'GET'])
@token_not_required
def register():
    if request.method == 'POST':
        users = db.users
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400
        if not is_valid_email(email):
            return jsonify({'error': 'Invalid email address'}), 400

        if users.find_one({'email': email}):
            return jsonify({'error': 'Email already registered'}), 409
        hashed_password = generate_password_hash(password)
        user_id = users.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password
        }).inserted_id

        return jsonify({'message': 'User registered successfully', 'user_id': str(user_id)}), 201
    elif request.method == 'GET':
        return render_template('register.html')
    else:
        return jsonify({'error': 'Method not allowed'}), 405
    
@app.route('/subscriptions', defaults={'plan_id': None}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/subscriptions/<string:plan_id>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@token_required
def subscriptions(current_user, plan_id):
    if request.method == 'GET':
        subscriptions = list(db.subscriptions.find({'username': current_user}))
        for sub in subscriptions:
            sub['_id'] = str(sub['_id'])

        return render_template("subscriptions.html",subs = subscriptions, user=current_user)
    elif request.method == 'POST':
        try:
            data = request.get_json() or request.form
            name = data.get('name')
            plan = data.get('plan')

            if not name or not plan:
                return jsonify({'error': 'Missing required fields'}), 400
            start_date = datetime.utcnow()

            if plan not in plan_durations:
                return jsonify({'error': f'Unknown plan: {plan}'}), 400

            renewal_date = start_date + timedelta(days=plan_durations[plan]['renewal_days'])
            end_date = start_date + timedelta(days=plan_durations[plan]['end_days'])

            subscription = {
                'username': current_user,
                'name': name,
                'plan': plan,
                'price': plan_durations[plan]['price'],
                'features': plan_durations[plan]['features'],
                'start_date': start_date,
                'renewal_date': renewal_date,
                'end_date': end_date,
                'status': 'active'
            }

            inserted = db.subscriptions.insert_one(subscription)

            return jsonify({
                'message': 'Subscription registered successfully',
                'subscription_id': str(inserted.inserted_id)
            }), 201

        except Exception as e:
            return jsonify({'error': str(e)}), 500
        
    elif request.method == 'PUT':
        subscription = db.subscriptions.find_one({
            'username': current_user,
            'status': 'deactivated',
            '_id': ObjectId(plan_id)
        })
        if not subscription:
            return jsonify({'error': 'No deactivated subscription found'}), 404

        result = db.subscriptions.update_one(
            {'_id': subscription['_id']},
            {'$set': {'status': 'active', 'end_date': datetime.utcnow()}}
        )

        if result.modified_count == 1:
            return jsonify({'message': 'Subscription cancelled successfully'}), 200
        else:
            return jsonify({'message': 'Subscription already cancelled'}), 200
    
    elif request.method == 'DELETE':
        subscription = db.subscriptions.find_one({
            'username': current_user,
            'status': 'active',
            '_id': ObjectId(plan_id)
        })
        if not subscription:
            return jsonify({'error': 'No active subscription found'}), 404

        result = db.subscriptions.update_one(
            {'_id': subscription['_id']},
            {'$set': {'status': 'deactivated'}}
        )

        if result.modified_count == 1:
            return jsonify({'message': 'Subscription cancelled successfully'}), 200
        else:
            return jsonify({'message': 'Subscription already cancelled'}), 200
    else:
        return jsonify({'error': 'Unsupported HTTP method!'}), 405
    
@app.route('/plans', methods=['GET'])
@token_required
def plans(current_user):
    if request.method == 'GET':
        return render_template('register_subs.html')
    else:
        return jsonify({'error': 'Method not allowed'}), 405
    
@app.route('/login', methods=['POST', 'GET'])
@token_not_required
def login():
    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        user = db.users.find_one({'username': username})
        if not user or not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid username or password'}), 401
        token_payload = {
            'username': username,
            'exp': datetime.utcnow() + timedelta(days=2)
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        response = make_response(jsonify({'message': 'Logged in successfully'}))
        response.set_cookie('token', token, httponly=True, max_age=2*24*60*60)

        return response

@app.route('/logout', methods=['POST', 'GET'])
@token_required
def logout(current_user):
    response = make_response(jsonify({'message': 'Logged out successfully'}))
    response.set_cookie('token', '', expires=0)
    return response

@app.route('/profile')
@token_required
def profile(current_user):
    user = db.users.find_one({'username': current_user})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return render_template('profile.html', user=user)

if __name__ == "__main__":
    scheduler = BackgroundScheduler()
    scheduler.add_job(expire_subscriptions, 'interval', hours=1)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())
    if os.getenv('DEBUG') == 'True':
        app.run(debug=True, use_reloader=False, port=1001)
    elif os.getenv('DEBUG') == 'False':
        app.run(debug=False, port=1001)
    else:
        print("Please set DEBUG environment variable to True or False.")
        exit()
