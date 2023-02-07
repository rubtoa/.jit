from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__, static_folder='static', template_folder='templates')
auth = HTTPBasicAuth()



user = os.environ.get('USER')
password = os.environ.get('PASSWORD')
users = {
    user : generate_password_hash(password),
}

@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@app.route('/')
@auth.login_required
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=12345)