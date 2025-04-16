from flask import Flask, request, jsonify, render_template, send_from_directory, redirect, url_for, session, flash
import os
import re
from urllib.parse import urlparse
import random
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
import joblib
import warnings
import sqlite3
from datetime import datetime
import hashlib
import uuid

# Suppress warnings
warnings.filterwarnings('ignore')

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.environ.get('SECRET_KEY', 'dev_key_for_testing')

# Add now() function for templates
@app.context_processor
def utility_processor():
    def now():
        return datetime.now()
    return dict(now=now)

# Database setup
def get_db_connection():
    conn = sqlite3.connect('phishing_detector.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create history table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT NOT NULL,
        is_safe BOOLEAN NOT NULL,
        confidence REAL NOT NULL,
        rf_result BOOLEAN NOT NULL,
        svm_result BOOLEAN NOT NULL,
        lr_result BOOLEAN NOT NULL,
        checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Check if models exist, if not, create and save them
models_dir = 'models'
os.makedirs(models_dir, exist_ok=True)

rf_path = os.path.join(models_dir, 'random_forest.joblib')
svm_path = os.path.join(models_dir, 'svm.joblib')
lr_path = os.path.join(models_dir, 'logistic_regression.joblib')

# Feature extraction functions
def extract_url_features(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    path = parsed_url.path
    
    # Basic features
    features = {
        'urlLength': len(url),
        'hostnameLength': len(hostname),
        'pathLength': len(path),
        'domainAge': random.uniform(0, 10),  # Simulated domain age in years
        'hasHttps': url.startswith('https://'),
        'subdomainCount': hostname.count('.'),
        'pathDepth': len([p for p in path.split('/') if p]),
        'hasIP': bool(re.search(r'\d+\.\d+\.\d+\.\d+', hostname)),
        'hasSuspiciousWords': contains_suspicious_words(url),
        'tldIsSuspicious': is_suspicious_tld(hostname),
        'hasAtSymbol': '@' in url,
        'hasDashInDomain': '-' in hostname,
        'hasMultipleSubdomains': hostname.count('.') > 1,
        'hasUrlShortener': is_url_shortener(hostname),
        'hasExcessiveQueryParams': len(parsed_url.query) > 100,
    }
    
    return features

def contains_suspicious_words(url):
    suspicious_words = [
        'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
        'banking', 'paypal', 'password', 'credential', 'wallet', 'alert',
        'authenticate', 'validation'
    ]
    
    url_lower = url.lower()
    return any(word in url_lower for word in suspicious_words)

def is_suspicious_tld(hostname):
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.online', '.site', '.work']
    return any(hostname.endswith(tld) for tld in suspicious_tlds)

def is_url_shortener(hostname):
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cli.gs', 'ow.ly', 'rebrand.ly']
    return any(shortener in hostname for shortener in shorteners)

# ML Models
class RandomForestModel:
    def __init__(self):
        if os.path.exists(rf_path):
            self.model = joblib.load(rf_path)
        else:
            self.model = self._train_model()
            joblib.dump(self.model, rf_path)
    
    def _train_model(self):
        # This is a simplified training process
        # In a real-world scenario, you would train on actual phishing data
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Create synthetic data for demonstration
        X = np.random.rand(1000, 15)  # 15 features
        y = np.random.randint(0, 2, 1000)  # Binary classification
        
        model.fit(X, y)
        return model
    
    def predict(self, features):
        # For demonstration, we'll use a rule-based approach instead of the actual model
        score = 0
        
        # URL structure features
        if features['urlLength'] > 75: score += 0.4
        if features['hasIP']: score += 0.6
        if features['hasAtSymbol']: score += 0.5
        if features['hasDashInDomain']: score += 0.3
        if features['hasMultipleSubdomains']: score += 0.4
        if features['pathDepth'] > 4: score += 0.3
        
        # Security features
        if not features['hasHttps']: score += 0.5
        if features['tldIsSuspicious']: score += 0.5
        if features['hasUrlShortener']: score += 0.4
        
        # Content features
        if features['hasSuspiciousWords']: score += 0.5
        if features['hasExcessiveQueryParams']: score += 0.3
        
        # Domain features
        if features['domainAge'] < 1: score += 0.5
        
        return score > 1.5

class SVMModel:
    def __init__(self):
        if os.path.exists(svm_path):
            self.model = joblib.load(svm_path)
        else:
            self.model = self._train_model()
            joblib.dump(self.model, svm_path)
    
    def _train_model(self):
        # Simplified training process
        model = SVC(probability=True, random_state=42)
        
        # Create synthetic data for demonstration
        X = np.random.rand(1000, 15)  # 15 features
        y = np.random.randint(0, 2, 1000)  # Binary classification
        
        model.fit(X, y)
        return model
    
    def predict(self, features):
        # Rule-based approach for demonstration
        score = 0
        
        # URL structure features
        if features['urlLength'] > 70: score += 0.3
        if features['hasIP']: score += 0.7
        if features['hasAtSymbol']: score += 0.6
        if features['hasDashInDomain']: score += 0.2
        if features['hasMultipleSubdomains']: score += 0.3
        
        # Security features
        if not features['hasHttps']: score += 0.6
        if features['tldIsSuspicious']: score += 0.6
        if features['hasUrlShortener']: score += 0.5
        
        # Content features
        if features['hasSuspiciousWords']: score += 0.4
        if features['hasExcessiveQueryParams']: score += 0.2
        
        # Domain features
        if features['domainAge'] < 1: score += 0.4
        
        return score > 1.6

class LogisticRegressionModel:
    def __init__(self):
        if os.path.exists(lr_path):
            self.model = joblib.load(lr_path)
        else:
            self.model = self._train_model()
            joblib.dump(self.model, lr_path)
    
    def _train_model(self):
        # Simplified training process
        model = LogisticRegression(random_state=42)
        
        # Create synthetic data for demonstration
        X = np.random.rand(1000, 15)  # 15 features
        y = np.random.randint(0, 2, 1000)  # Binary classification
        
        model.fit(X, y)
        return model
    
    def predict(self, features):
        # Rule-based approach for demonstration
        score = 0
        
        # URL structure features
        if features['urlLength'] > 65: score += 0.2
        if features['hasIP']: score += 0.8
        if features['hasAtSymbol']: score += 0.7
        if features['hasDashInDomain']: score += 0.3
        if features['hasMultipleSubdomains']: score += 0.2
        
        # Security features
        if not features['hasHttps']: score += 0.7
        if features['tldIsSuspicious']: score += 0.7
        if features['hasUrlShortener']: score += 0.6
        
        # Content features
        if features['hasSuspiciousWords']: score += 0.3
        if features['hasExcessiveQueryParams']: score += 0.2
        
        # Domain features
        if features['domainAge'] < 1: score += 0.3
        
        return score > 1.7

# Initialize models
rf_model = RandomForestModel()
svm_model = SVMModel()
lr_model = LogisticRegressionModel()

# Authentication helpers
def hash_password(password):
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt

def check_password(hashed_password, user_password):
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()

def is_logged_in():
    return 'user_id' in session

# Middleware to check if user is logged in
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html', is_logged_in=is_logged_in(), username=session.get('username'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return render_template('register.html', is_logged_in=is_logged_in())
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html', is_logged_in=is_logged_in())
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if username or email already exists
        cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
        user = cursor.fetchone()
        
        if user:
            flash('Username or email already exists', 'error')
            conn.close()
            return render_template('register.html', is_logged_in=is_logged_in())
        
        # Hash the password and insert the new user
        hashed_password = hash_password(password)
        cursor.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            (username, email, hashed_password)
        )
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', is_logged_in=is_logged_in())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            # Redirect to check page
            return redirect(url_for('check'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', is_logged_in=is_logged_in())

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get recent history for this user
    cursor.execute(
        'SELECT * FROM history WHERE user_id = ? ORDER BY checked_at DESC LIMIT 5',
        (session['user_id'],)
    )
    recent_checks = cursor.fetchall()
    
    # Get stats
    cursor.execute(
        'SELECT COUNT(*) as total, SUM(CASE WHEN is_safe = 1 THEN 1 ELSE 0 END) as safe FROM history WHERE user_id = ?',
        (session['user_id'],)
    )
    stats_row = cursor.fetchone()
    
    # Handle None values for stats
    stats = {
        'total': stats_row['total'] if stats_row else 0,
        'safe': stats_row['safe'] if stats_row and stats_row['safe'] is not None else 0
    }
    
    conn.close()
    
    return render_template(
        'dashboard.html',
        is_logged_in=is_logged_in(),
        username=session.get('username'),
        recent_checks=recent_checks,
        stats=stats
    )

@app.route('/history')
@login_required
def history():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get all history for this user
    cursor.execute(
        'SELECT * FROM history WHERE user_id = ? ORDER BY checked_at DESC',
        (session['user_id'],)
    )
    checks = cursor.fetchall()
    conn.close()
    
    return render_template(
        'history.html',
        is_logged_in=is_logged_in(),
        username=session.get('username'),
        checks=checks
    )

@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    cursor.execute(
        'SELECT COUNT(*) as total FROM history WHERE user_id = ?',
        (session['user_id'],)
    )
    total_checks = cursor.fetchone()['total']
    
    conn.close()
    
    return render_template(
        'profile.html',
        is_logged_in=is_logged_in(),
        username=session.get('username'),
        user=user,
        total_checks=total_checks
    )

@app.route('/about')
def about():
    return render_template('about.html', is_logged_in=is_logged_in(), username=session.get('username'))

@app.route('/check', methods=['GET', 'POST'])
def check():
    if request.method == 'POST':
        url = request.form.get('url')
        
        if not url:
            flash('Please enter a URL', 'error')
            return redirect(url_for('check'))
        
        # Prepare URL for API call
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
        
        # Validate URL format
        try:
            urlparse(url)
        except:
            flash('Please enter a valid URL', 'error')
            return redirect(url_for('check'))
        
        # Extract features
        features = extract_url_features(url)
        
        # Get predictions from each model
        rf_prediction = rf_model.predict(features)
        svm_prediction = svm_model.predict(features)
        lr_prediction = lr_model.predict(features)
        
        # Ensemble the results (majority voting)
        phishing_votes = sum([rf_prediction, svm_prediction, lr_prediction])
        is_safe = phishing_votes < 2  # Safe if less than 2 models predict phishing
        
        # Calculate confidence based on model agreement
        if phishing_votes == 0:
            confidence = 0.9  # All models agree it's safe
        elif phishing_votes == 3:
            confidence = 0.9  # All models agree it's phishing
        elif phishing_votes == 2:
            confidence = 0.7  # 2 models predict phishing
        else:
            confidence = 0.7  # 1 model predicts phishing
        
        # Add some randomness to simulate real-world uncertainty
        confidence = min(0.95, max(0.6, confidence + (random.random() * 0.1 - 0.05)))
        
        # Save to history if user is logged in
        if is_logged_in():
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                '''INSERT INTO history 
                   (user_id, url, is_safe, confidence, rf_result, svm_result, lr_result)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (session['user_id'], url, is_safe, confidence, rf_prediction, svm_prediction, lr_prediction)
            )
            
            conn.commit()
            conn.close()
        
        # Prepare result for template
        result = {
            'url': url,
            'isSafe': is_safe,
            'confidence': confidence,
            'modelResults': {
                'randomForest': bool(rf_prediction),
                'svm': bool(svm_prediction),
                'logisticRegression': bool(lr_prediction),
            },
            'features': features,
        }
        
        return render_template(
            'result.html',
            is_logged_in=is_logged_in(),
            username=session.get('username'),
            result=result
        )
    
    return render_template(
        'check.html',
        is_logged_in=is_logged_in(),
        username=session.get('username')
    )

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # Extract features
        features = extract_url_features(url)
        
        # Get predictions from each model
        rf_prediction = rf_model.predict(features)
        svm_prediction = svm_model.predict(features)
        lr_prediction = lr_model.predict(features)
        
        # Ensemble the results (majority voting)
        phishing_votes = sum([rf_prediction, svm_prediction, lr_prediction])
        is_safe = phishing_votes < 2  # Safe if less than 2 models predict phishing
        
        # Calculate confidence based on model agreement
        if phishing_votes == 0:
            confidence = 0.9  # All models agree it's safe
        elif phishing_votes == 3:
            confidence = 0.9  # All models agree it's phishing
        elif phishing_votes == 2:
            confidence = 0.7  # 2 models predict phishing
        else:
            confidence = 0.7  # 1 model predicts phishing
        
        # Add some randomness to simulate real-world uncertainty
        confidence = min(0.95, max(0.6, confidence + (random.random() * 0.1 - 0.05)))
        
        # Save to history if user is logged in
        if is_logged_in():
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                '''INSERT INTO history 
                   (user_id, url, is_safe, confidence, rf_result, svm_result, lr_result)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (session['user_id'], url, is_safe, confidence, rf_prediction, svm_prediction, lr_prediction)
            )
            
            conn.commit()
            conn.close()
        
        # Return the result
        return jsonify({
            'isSafe': is_safe,
            'confidence': confidence,
            'modelResults': {
                'randomForest': bool(rf_prediction),
                'svm': bool(svm_prediction),
                'logisticRegression': bool(lr_prediction),
            },
            'features': features,
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
