import datetime
from os import path, urandom
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import DateTime, Column
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + path.join(path.abspath(path.dirname(__file__)), 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):
    id = Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, index=True)
    username = Column(db.String(200), nullable=False)
    password_hash = Column(db.String(200), nullable=False)
    tasks = db.relationship('Task', backref='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    id = Column(db.Integer, primary_key=True)
    title = Column(db.String(60), nullable=True)
    description = Column(db.Text)
    date = Column(DateTime, default=datetime.datetime.utcnow)
    user_id = Column(db.Integer, db.ForeignKey('user.id'))


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    repeat_password = PasswordField('repeat_password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registration')


class TaskForm(FlaskForm):
    title = StringField('title', validators=[DataRequired()])
    description = StringField('description', validators=[DataRequired()])
    if SubmitField('add'):
        submit = SubmitField('add')
    elif SubmitField('update'):
        submit = SubmitField('update')
    elif SubmitField('delete'):
        submit = SubmitField('delete')


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            next = request.args.get("next")
            return redirect(next or url_for('dashboard'))
        flash('Invalid email address or Password.')
    return render_template('login.html', form=form)


@app.route('/registration', methods=['POST', 'GET'])
def registration():
    form = RegistrationForm()
    if db.session.query(db.session.query(User).filter_by(email=form.email.data).exists()).scalar():
        flash("This email is exists")
    elif form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('registration.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    user_id = current_user.get_id()
    task_list = Task.query.filter_by(user_id=user_id)
    if request.method == 'POST':
        task = Task(title=request.form['title'], description=request.form['description'], user_id=user_id)
        db.session.add(task)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', task_list=task_list)


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    task = Task.query.filter_by(id=id).first()
    cur_user = int(current_user.get_id())
    task_owner = task.user_id
    if cur_user == task_owner:
        db.session.delete(task)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return redirect(url_for('dashboard'))


@app.route('/edit/<int:id>', methods=['POST', 'GET'])
@login_required
def edit(id):
    task = Task.query.filter_by(id=id).first()
    cur_user = int(current_user.get_id())
    task_owner = task.user_id
    if cur_user == task_owner and request.method == 'POST':
        task.title = request.form['update-title']
        task.description = request.form['update-desc']
        db.session.commit()
        return redirect(url_for('dashboard'))
    return redirect(url_for('dashboard'))
