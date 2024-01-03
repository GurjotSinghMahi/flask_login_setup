from flask import Flask, render_template, request, jsonify
from flask_login import login_required, current_user
from flask_login import login_user
from flask import Blueprint
from .models import User
from .auth import auth
from . import db

#main = Flask(__name__, static_folder='static', template_folder='templates')
#main.debug = True
#main.register_blueprint(auth)

main = Blueprint('main', __name__)

@main.route('/',  methods=['GET', 'POST'])
def index():
    return render_template('main.html')

@main.route('/pricing',  methods=['GET', 'POST'])
def pricing():
    return render_template('pricing.html')

@main.route('/profile')
@login_required #The way Flask-Login protects a view function against anonymous users. Now User need to Log in to see the profile view
def profile():
    return render_template('profile.html', name=current_user.fname)

#if __name__ == '__main__':
 #   main.run(host='192.168.189.1', debug=True)