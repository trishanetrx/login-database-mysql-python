#!/bin/bash

# Exit on any error
set -e

echo "Starting deployment of Flask app..."

# Step 1: Update and Install Dependencies
echo "Updating system and installing dependencies..."
sudo apt update -y
sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv mysql-server nginx git gunicorn
sudo apt install -y python3-dev default-libmysqlclient-dev build-essential pkg-config

# Step 2: Configure MySQL
echo "Setting up MySQL database and user..."
sudo mysql -u root <<MYSQL_SCRIPT
CREATE DATABASE flask_app_db;
CREATE USER 'flask_user'@'localhost' IDENTIFIED BY 'Power231';
GRANT ALL PRIVILEGES ON flask_app_db.* TO 'flask_user'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT



# Step 3: Set up Project Directory
APP_DIR="/var/www/flaskapp"
TEMPLATE_DIR="$APP_DIR/templates"
STATIC_DIR="$APP_DIR/static"
echo "Creating project directory structure..."
sudo mkdir -p $APP_DIR $TEMPLATE_DIR $STATIC_DIR
sudo chown -R $USER:$USER $APP_DIR

# Step 4: Create Application Files
echo "Creating application files..."

# app.py
cat <<'EOF' > $APP_DIR/app.py
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = "870293100v"  # Explicitly set the secret key for sessions

# Configure the MySQL database
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://flask_user:Power231@localhost/flask_app_db'#
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URI', 'mysql://flask_user:Power231@localhost/flask_app_db')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))  # Redirect to the login page

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose a different one.", "error")
            return redirect(url_for('register'))

        # Add the new user to the database
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query the database for the user
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "error")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return render_template('dashboard.html', user=user)
        else:
            session.pop('user_id', None)
            flash("Invalid session. Please log in again.", "error")

    flash("Please log in to access the dashboard.", "error")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# Error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Main entry point
if __name__ == '__main__':
    # Ensure database is initialized
    with app.app_context():
        db.create_all()

    app.run(debug=True, host='0.0.0.0')  # Run the app on all network interfaces
EOF

# requirements.txt
cat <<'EOF' > $APP_DIR/requirements.txt
Flask
Flask-SQLAlchemy
Flask-Bcrypt
mysqlclient
EOF

# templates/404.html
cat <<'EOF' > $TEMPLATE_DIR/404.html
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Page Not Found</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 flex items-center justify-center h-screen">
    <div class="text-center">
        <h1 class="text-4xl font-bold text-red-600">404</h1>
        <p class="text-lg text-gray-700">Page Not Found</p>
        <a href="/" class="text-blue-600 underline mt-4">Go Home</a>
    </div>
</body>
</html>
EOF

# templates/dashboard.html
cat <<'EOF' > $TEMPLATE_DIR/dashboard.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-r from-purple-500 via-pink-500 to-red-500 min-h-screen flex items-center justify-center text-gray-800">

    <!-- Main Container -->
    <div class="bg-white rounded-lg shadow-lg w-full max-w-4xl p-6 mx-4">
        
        <!-- Header -->
        <header class="mb-6">
            <h1 class="text-4xl font-extrabold text-gray-800 text-center">Welcome, {{ user.username }}!</h1>
            <p class="text-center text-gray-600 mt-2">Here is your personalized dashboard</p>
        </header>

        <!-- Content Section -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
            <!-- Card 1 -->
            <div class="bg-gradient-to-r from-blue-400 to-blue-600 p-6 rounded-lg shadow-md text-white">
                <h2 class="text-2xl font-bold mb-2">Your Profile</h2>
                <p class="text-sm">View and edit your profile information to keep it up to date.</p>
                <a href="/profile" class="inline-block mt-4 bg-white text-blue-600 px-4 py-2 rounded-lg shadow-md hover:bg-blue-200">
                    Manage Profile
                </a>
            </div>

            <!-- Card 2 -->
            <div class="bg-gradient-to-r from-green-400 to-green-600 p-6 rounded-lg shadow-md text-white">
                <h2 class="text-2xl font-bold mb-2">Activity Logs</h2>
                <p class="text-sm">Check your recent activity logs and track your progress.</p>
                <a href="/logs" class="inline-block mt-4 bg-white text-green-600 px-4 py-2 rounded-lg shadow-md hover:bg-green-200">
                    View Logs
                </a>
            </div>

            <!-- Card 3 -->
            <div class="bg-gradient-to-r from-purple-400 to-purple-600 p-6 rounded-lg shadow-md text-white">
                <h2 class="text-2xl font-bold mb-2">Notifications</h2>
                <p class="text-sm">Stay updated with the latest notifications and updates.</p>
                <a href="/notifications" class="inline-block mt-4 bg-white text-purple-600 px-4 py-2 rounded-lg shadow-md hover:bg-purple-200">
                    View Notifications
                </a>
            </div>

            <!-- Card 4 -->
            <div class="bg-gradient-to-r from-yellow-400 to-yellow-600 p-6 rounded-lg shadow-md text-white">
                <h2 class="text-2xl font-bold mb-2">Settings</h2>
                <p class="text-sm">Adjust your preferences and settings to customize your experience.</p>
                <a href="/settings" class="inline-block mt-4 bg-white text-yellow-600 px-4 py-2 rounded-lg shadow-md hover:bg-yellow-200">
                    Go to Settings
                </a>
            </div>
        </div>

        <!-- Logout Section -->
        <div class="mt-8 text-center">
            <a href="/logout" class="bg-red-500 text-white px-6 py-2 rounded-lg shadow-lg hover:bg-red-600">
                Logout
            </a>
        </div>
    </div>
    
</body>
</html>

# templates/login.html
cat <<'EOF' > $TEMPLATE_DIR/login.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 flex items-center justify-center h-screen">
    <div class="bg-white p-6 rounded-lg shadow-lg w-96">
        <h2 class="text-2xl font-bold text-center mb-4 text-indigo-600">Login</h2>

        <!-- Flash Messages -->
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="mb-4">
                    {% for category, message in messages %}
                        <p class="p-2 rounded-md text-white 
                                   {% if category == 'success' %} bg-green-500 
                                   {% elif category == 'error' %} bg-red-500 
                                   {% else %} bg-gray-500 {% endif %}">
                            {{ message }}
                        </p>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}

        <form method="POST" action="/login" class="space-y-4">
            <div>
                <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                <input type="text" name="username" id="username" required
                       class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
            </div>
            <div>
                <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                <input type="password" name="password" id="password" required
                       class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
            </div>
            <button type="submit"
                    class="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700">
                Login
            </button>
        </form>

        <p class="mt-4 text-sm text-gray-600 text-center">
            Don't have an account?
            <a href="/register" class="text-indigo-600 hover:underline">Register</a>
        </p>
    </div>
</body>
</html>
EOF

# templates/register.html
cat <<'EOF' > $TEMPLATE_DIR/register.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <!-- Add Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 flex items-center justify-center h-screen">
    <div class="bg-white p-6 rounded-lg shadow-lg">
        <h2 class="text-2xl font-bold mb-4">Register</h2>
        <form method="POST" class="space-y-4">
            <div>
                <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                <input type="text" name="username" id="username" required
                    class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
            </div>
            <div>
                <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                <input type="password" name="password" id="password" required
                    class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
            </div>
            <button type="submit"
                class="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700">
                Register
            </button>
        </form>
        <p class="mt-4 text-sm text-gray-600">
            Already have an account? 
            <a href="/login" class="text-indigo-600 hover:underline">Login</a>
        </p>
    </div>
</body>
</html>
EOF

# Step 5: Set up Virtual Environment
echo "Creating Python virtual environment..."
cd $APP_DIR
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install gunicorn
pip install -r requirements.txt

deactivate

# Step 6: Initialize Database Tables
echo "Initializing database tables..."
source venv/bin/activate
python3 -c "
from app import app, db
with app.app_context():
    db.create_all()
"
deactivate


# Step 6: Set up Gunicorn
echo "Configuring Gunicorn..."
cat <<'EOF' | sudo tee /etc/systemd/system/flaskapp.service
[Unit]
Description=Gunicorn instance to serve Flask App
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/flaskapp
Environment="DB_URI=mysql://flask_user:Power231@localhost/flask_app_db"
ExecStart=/var/www/flaskapp/venv/bin/gunicorn --workers 3 --bind unix:/var/www/flaskapp/flaskapp.sock app:app
Restart=always
KillMode=mixed
TimeoutStopSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=flaskapp

[Install]
WantedBy=multi-user.target
EOF

#
sudo chown -R www-data:www-data /var/www/flaskapp
sudo chmod -R 750 /var/www/flaskapp

# Step 7: Start and Enable Gunicorn
echo "Starting Gunicorn service..."
sudo systemctl daemon-reload
sudo systemctl start flaskapp
sudo systemctl enable flaskapp

# Step 8: Configure Nginx
echo "Configuring Nginx..."
sudo apt install -y nginx 

git clone https://github.com/trishanetrx/docshare.git /tmp/docshare
sudo mkdir -p /etc/letsencrypt/live/negombotech.com/
sudo mkdir -p /etc/letsencrypt/

# Move the files
sudo mv /tmp/docshare/certificates/cert.pem /etc/letsencrypt/live/negombotech.com/fullchain.pem
sudo mv /tmp/docshare/certificates/privkey.pem /etc/letsencrypt/live/negombotech.com/privkey.pem
sudo mv /tmp/docshare/certificates/options-ssl-nginx.conf /etc/letsencrypt/options-ssl-nginx.conf
sudo mv /tmp/docshare/certificates/ssl-dhparams.pem /etc/letsencrypt/ssl-dhparams.pem

cat <<'EOF' | sudo tee /etc/nginx/sites-available/flaskapp
server {
    listen 80;
    server_name negombotech.com www.negombotech.com;
    return 301 https://$host$request_uri; # Redirect HTTP to HTTPS
}

server {
    listen 443 ssl;
    server_name negombotech.com www.negombotech.com;

    ssl_certificate /etc/letsencrypt/live/negombotech.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/negombotech.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # HSTS (HTTP Strict Transport Security)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/flaskapp/flaskapp.sock;

        # Forward headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Enable the Nginx configuration and reload
sudo ln -s /etc/nginx/sites-available/flaskapp /etc/nginx/sites-enabled
sudo nginx -t
sudo systemctl restart nginx

# Step 9: Finalize Setup
echo "Deployment completed successfully. Visit your app at http://localhost"
