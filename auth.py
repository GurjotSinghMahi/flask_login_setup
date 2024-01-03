from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from werkzeug.urls import url_parse
from flask_login import login_user, logout_user, login_required, current_user
from datetime import date
from .models import User
from . import db, app

auth = Blueprint('auth', __name__)

mail = Mail(app)
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)
    print("msg: ",msg)
    print('Mail sent!')


@auth.route('/signin', methods=['GET', 'POST'])
def signin():
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        # remember = True if request.form.get('remember') else False

        user = User.query.filter_by(email=email).first()

        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Invalid Email or Password.')
            return redirect(url_for('auth.signin'))  # if the user doesn't exist or password is wrong, reload the page

        if user.confirmed == 0:
            # if user is not confirmed, send the token on registered edmail id
            # Now we'll send the email confirmation link
            subject = "Welcome to The Paper Editors...!!! Kindly Confirm your email"

            # Make Token
            token = ts.dumps(email, salt='email-confirm')

            # Develop Link for Message and Message html
            confirm_url = url_for('auth.confirm_mail', token=token, _external=True)
            html = render_template('confirm.html', confirm_url=confirm_url)

            # We'll assume that send_email has been defined in myapp/util.py
            send_email(email, subject, html)
            flash('Your Email ID is not confirmed.\n Please confirm your id using token sent on your Email.')
            #flash('Email ID is not confirmed.')
            return redirect(url_for('auth.signin'))  # if the user doesn't exist or password is wrong, reload the page

        # if the above check passes, then we know the user has the right credentials
        login_user(user)
        next_page = request.args.get('next')
        #print("NEXT PAGE: ", next_page)
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.profile')
        #print("NEXT PAGE1: ", next_page)
        return redirect(next_page)
    else:
        return render_template('signin.html')


@auth.route('/signup')
def signup():
    return render_template('signup.html')


@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    fname = request.form.get('fname')
    lname = request.form.get('lname')
    password = request.form.get('password')
    cpassword = request.form.get('cpassword')

    try:
        # Validate.
        valid = validate_email(email)
        # Update with the normalized form.
        email = valid.email
    except EmailNotValidError as e:
        # email is not valid, exception message is human-readable
        flash(str(e), 'email_error')
        return redirect(url_for('auth.signup'))

    if password != cpassword:
        # print("password", password, " ,cpassword", cpassword)
        flash('Enter same Password', 'pswrd_error')
        # print("here")
        return redirect(url_for('auth.signup'))

    user = User.query.filter_by(
        email=email).first()  # if this returns a user, then the email already exists in database

    # if a user is found, we want to redirect back to signup page so user can try again
    if user:
        # FLASH MESSAGE IF USER ALREADY EXISTS
        flash('Email address already exists', 'mail_error')
        return redirect(url_for('auth.signup'))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(email=email,
                    fname=fname,
                    lname=lname,
                    password=generate_password_hash(password, method='sha256'),
                    confirmed=False,
                    registered_on=date.today(),
                    confirmed_on=date.today())

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    # Now we'll send the email confirmation link
    subject = "Welcome to The Paper Editors...!!! Kindly Confirm your email"

    # Make Token
    token = ts.dumps(email, salt='email-confirm')

    # Develop Link for Message and Message html
    confirm_url = url_for('auth.confirm_mail', token=token, _external=True)
    html = render_template('confirm.html', confirm_url=confirm_url)

    # We'll assume that send_email has been defined in myapp/util.py
    send_email(email, subject, html)

    flash('Email confirmation Mail has been sent to your registered Email. Kindly confirm Email.')
    return redirect(url_for("auth.signin"))

    # return '<h1> The email you have entered is {}, the token is {}'.format(email, token)
    # redirect(url_for('auth.signin'))


@auth.route('/confirm_email/<token>')
def confirm_mail(token):
    try:
        email = ts.loads(token, salt='email-confirm', max_age=11220)
    except:
        flash('Your Token has expired or invalid.')
        return redirect(url_for('auth.signin'))

    user = User.query.filter_by(email=email).first_or_404()

    user.confirmed = True

    db.session.add(user)
    db.session.commit()

    flash('Your Email is Confirmed. Kindly Sign In to continue.')
    return redirect(url_for('auth.signin'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out..!!!")
    return redirect(url_for('auth.signin'))

@auth.route('/forgot_pswrd', methods=['GET', 'POST'])
def forgot_pswrd():
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
    if request.method == 'POST':
        email = request.form.get('email')

        user = User.query.filter_by(email=email).first()
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user:
            flash('Email ID not registered.')
            return redirect(url_for('auth.forgot_pswrd'))  # if the user doesn't exist or password is wrong, reload the page

        if user.confirmed == 0:
            #if user is not confirmed, send the token on registered edmail id
            # Now we'll send the email confirmation link
            subject = "Welcome to The Paper Editors...!!! Kindly Confirm your email"

            # Make Token
            token = ts.dumps(email, salt='email-confirm')

            # Develop Link for Message and Message html
            confirm_url = url_for('auth.confirm_mail', token=token, _external=True)
            html = render_template('confirm.html', confirm_url=confirm_url)

            # We'll assume that send_email has been defined in myapp/util.py
            send_email(email, subject, html)
            flash('Your Email ID is not confirmed.\n Please confirm your id using token sent on your Email.')
            return redirect(url_for('auth.forgot_pswrd'))  # if the user doesn't exist or password is wrong, reload the page

        # Now we'll send the email confirmation link
        subject = "The Paper Editors...!!! Kindly Reset your Password"

        # Make Token
        token = ts.dumps(email, salt='recover-key')

        # Develop Link for Message and Message html
        confirm_url = url_for('auth.reset_pswrd', token=token, _external=True)
        html = render_template('reset_pswrd_mail.html', confirm_url=confirm_url, name=user.fname)

        # We'll assume that send_email has been defined in myapp/util.py
        send_email(email, subject, html)

        flash('Password reset link has been sent on your registered Email.')
        return redirect(url_for("auth.signin"))

    return render_template('forgot_pswrd.html')

@auth.route('/reset_pswrd/<token>', methods=['GET', 'POST'])
def reset_pswrd(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
    try:
        email = ts.loads(token, salt='recover-key', max_age=86400)
    except:
        flash('Your Token has expired or invalid.')
        return redirect(url_for('auth.signin'))
    if request.method == 'POST':
        print("WE ARE HERE CHANGING PASSWORD")

        password = request.form.get('password')
        cpassword = request.form.get('cpassword')

        if password != cpassword:
            flash('Enter same Password')
            return redirect(url_for('auth.reset_pswrd', token=token))

        user = User.query.filter_by(email=email).first_or_404()

        user.password = generate_password_hash(password, method='sha256')

        db.session.add(user)
        db.session.commit()

        flash('Your Password is changed. Kindly Signin to continue.')
        return redirect(url_for('auth.signin'))
    return render_template('reset_pswrd.html', token=token)