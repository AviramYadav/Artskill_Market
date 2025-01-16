from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_cors import CORS
import razorpay
import hmac
import hashlib

app = Flask(__name__)
CORS(app)
CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:5500"}})

# MySQL configuration
app.config['MYSQL_USER'] = 'art_user'
app.config['MYSQL_PASSWORD'] = 'artistry@123'
app.config['MYSQL_DB'] = 'artistrymarket'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)
bcrypt = Bcrypt(app)

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    with mysql.connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        if result:
            return User(result['id'], result['username'])
        return None

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    user_name = data.get('userName')
    email = data.get('email')
    mobile_number = data.get('mobileNumber')
    password = data.get('password')

    # Check if the user already exists
    with mysql.connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

    if existing_user:
        return jsonify({'error': 'User already exists.'}), 409  # Conflict

    # Hash the password for security
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Insert the new user into the database
    with mysql.connection.cursor() as cursor:
        cursor.execute("INSERT INTO users (username, email, mobile_number, password) VALUES (%s, %s, %s, %s)", (user_name, email, mobile_number, hashed_password))
        mysql.connection.commit()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    with mysql.connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['password'], password):
            login_user(User(user['id'], user['username']))
            return jsonify({'message': 'Login successful'}), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

razorpay_client = razorpay.Client(auth=('rzp_test_4M8gTOYzFbLaHo', '2ZsVaBlQs8xFk8V7nEwKN0JL'))

@app.route('/feepayment.html')
def feepayment():
    # Render the feepayment.html template
    return render_template('feepayment.html')

@app.route('/create-order', methods=['POST'])
def create_order():
    data = request.get_json()
    amount = data['amount']
    currency = data['currency']

    options = {
        'amount': amount * 100,  # Convert to smallest currency unit
        'currency': currency,
    }

    try:
        order = razorpay_client.order.create(data=options)
        return jsonify(order)
    except razorpay.errors.BadRequestError as e:
        return jsonify({'error': str(e)}), 400
@app.route('/payment-verification', methods=['POST'])
def payment_verification():
    data = request.get_json()
    
    # Extract the Razorpay signature from the headers
    razorpay_signature = request.headers.get('X-Razorpay-Signature')
    
    # Compute the expected signature
    expected_signature = hmac.new(
        b'YOUR_KEY_SECRET',
        request.data,
        hashlib.sha256
    ).hexdigest()
    
    # Compare the computed signature with the received signature
    if razorpay_signature == expected_signature:
        # Payment is verified
        print("Payment verification successful.")
        return jsonify({'status': 'success'})
    else:
        # Payment verification failed
        print("Payment verification failed.")
        return jsonify({'status': 'failure'}), 400

if __name__ == '__main__':
    app.run(debug=True)



