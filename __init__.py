from flask import Flask, flash, redirect, url_for
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

# init SQLAlchemy so that we can use it in our models
db = SQLAlchemy()

app = Flask(__name__, static_folder='static', template_folder='templates')
app.debug = True
app.config.from_pyfile('config.py')

db.init_app(app)

'''
login manager contains the code that lets your
application and Flask-Login work together,
such as how to load a user from an ID, where
to send users when they need to log in, and the like.
'''
login_manager = LoginManager() # Flask flask_login

'''
Flask-Login provides a very useful feature that forces users to
log in before they can view certain pages of the application.
If a user who is not logged in tries to view a protected page,
Flask-Login will automatically redirect the user to the login form,
and only redirect back to the page the user wanted
to view after the login process is complete.

The 'auth.signin' value below is the function (or endpoint) name for the login_view
'''
login_manager.login_view = 'auth.signin'
login_manager.init_app(app)

from .models import User

@login_manager.user_loader
def load_user(user_id):
    """Check if user is logged-in on every page load."""
    if user_id is not None:
        return User.query.get(user_id)
    return None

@login_manager.unauthorized_handler
def unauthorized():
    """Redirect unauthorized users to Login page."""
    flash('You must be logged in to view that page.')
    return redirect(url_for('auth.signin'))

# blueprint for auth rofrom flask_login import LoginManagerutes in our app
from .auth import auth as auth_blueprint
# auth_blueprint.debug = True
app.register_blueprint(auth_blueprint)

# blueprint for non-auth parts of app
from .main import main as main_blueprint
# main_blueprint.debug = True
app.register_blueprint(main_blueprint)


