from datetime import datetime
from flask_login import current_user
import bcrypt
from flask import session
from flask import Flask, render_template, request, redirect, url_for, flash, session
import flask_bcrypt
from flask_login import current_user, UserMixin, LoginManager, login_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import Boolean
from wtforms import StringField, PasswordField, BooleanField, SubmitField, DateField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import logout_user

app = Flask(__name__)
app.secret_key = 'secretC'
login_manager = LoginManager()
login_manager.init_app(app)
#bcrypt = Bcrypt(app)

# Set up the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/travel'

db = SQLAlchemy(app)

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient',
                                        lazy='dynamic')

    ratings_received = db.relationship('Rating', foreign_keys='Rating.guide_id', backref='guide', lazy='dynamic')

    reservations_made = db.relationship('Reservation', foreign_keys='Reservation.user_id', backref='user',
                                        lazy='dynamic')
    tours_reserved = db.relationship('Reservation', foreign_keys='Reservation.guide_id', backref='guide',
                                     lazy='dynamic')
    is_guide = db.Column(Boolean, default=False)
    guideLat = db.Column(db.Float)
    guideLng = db.Column(db.Float)
    locationName = db.Column(db.String(250))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    guide_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    rating = db.Column(db.Integer, nullable=False)

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    guide_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.Date, nullable=False)


def create_tables():
    db.create_all()

# Define the forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    #username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Sign in')


class SignupForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    location = StringField('Location', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    submit = SubmitField('Sign up')
    is_guide = BooleanField('I am guide')
    guideLocationName = StringField('Guide Location Name', validators=[DataRequired()])

# Define additional forms
class MessageForm(FlaskForm):
    recipient = StringField('Recipient', validators=[DataRequired()])
    body = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

class RatingForm(FlaskForm):
    rating = IntegerField('Rating', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ReservationForm(FlaskForm):
    date = DateField('Date', validators=[DataRequired()])
    submit = SubmitField('Reserve')

class SearchForm(FlaskForm):
    location = StringField('Location', validators=[DataRequired()])
    submit = SubmitField('Search')

# Define additional routes
@app.route('/message', methods=['GET', 'POST'])
def message():
    form = MessageForm()
    if form.validate_on_submit():
        recipient = User.query.filter_by(name=form.recipient.data).first()
        if recipient:
            msg = Message(sender=current_user, recipient=recipient, body=form.body.data)
            db.session.add(msg)
            db.session.commit()
            flash('Message sent.')
            return redirect(url_for('dashboard'))
        else:
            flash('User not found.')
    return render_template('message.html', form=form)

@app.route('/rate/<int:guide_id>', methods=['GET', 'POST'])
def rate(guide_id):
    form = RatingForm()
    if form.validate_on_submit():
        rating = Rating(user=current_user, guide_id=guide_id, rating=form.rating.data)
        db.session.add(rating)
        db.session.commit()
        flash('Rating submitted.')
        return redirect(url_for('dashboard'))
    return render_template('rate.html', form=form)


@app.route('/reserve/<int:guide_id>', methods=['GET', 'POST'])
def reserve(guide_id):
    form = ReservationForm()
    if form.validate_on_submit():
        reservation = Reservation(user=current_user, guide_id=guide_id, date=form.date.data)
        db.session.add(reservation)
        db.session.commit()
        flash('Reservation made.')
        return redirect(url_for('dashboard'))
    return render_template('reserve.html', form=form)


@app.route('/')
def index():
    return render_template('index.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print("Form is valid!")  # Depanare pas 1

        user = User.query.filter_by(email=form.email.data).first()
        if user:
            print("User found in database!")  # Depanare pas 2

            if check_password_hash(user.password, form.password.data):
                print("Password is correct!")  # Depanare pas 3

                login_user(user, remember=form.remember.data)
                return redirect(url_for("dashboard"))
            else:
                print("Password is incorrect!")  # Depanare pas 3 (eroare)
        else:
            print("User not found in database!")  # Depanare pas 2 (eroare)

        flash("Autentificare nereușită. Verifică adresa de email și parola.", "danger")
    else:
        print("Form is not valid!")  # Depanare pas 1 (eroare)

    return render_template("login.html", title="Login", form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()  # Check if user already exists
        if existing_user:
            flash('Email already in use. Please choose a different one or log in.')
            return render_template('signup.html', form=form)

        user = User(
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            name=form.name.data,
            location=form.location.data,
            description=form.description.data,
            role='user',
            is_guide=form.is_guide.data,
            guideLat=request.form.get('guideLat'),
            guideLng = request.form.get('guideLng'),
            locationName=form.guideLocationName.data
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)  # Log the user in
        flash('Account created successfully.')
        return redirect(url_for('dashboard'))  # Modificare aici
    return render_template('signup.html', form=form)

@app.route('/dashboard')
def dashboard():
    if current_user.is_authenticated:
        guides = User.query.filter_by(is_guide=True).all()  # Selectează doar ghizii
        return render_template('dashboard.html', users=guides, current_user=current_user)
    else:
        flash('Please log in first.')
        return redirect(url_for('signup'))

@app.route('/search', methods=['GET', 'POST'])
def search():
    form = SearchForm()
    users = []
    if form.validate_on_submit():
        users = User.query.filter_by(location=form.location.data).all()
    return render_template('search.html', form=form, users=users)


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)