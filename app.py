from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, EmailField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, ValidationError
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'bekne'
db = SQLAlchemy(app)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image = db.Column(db.String(20), nullable=False, default='default.jpg')
    posts = db.relationship('Post', backref='group', lazy=True)
    
    def __repr__(self):
        return f"Group('{self.name}', Created by User ID: {self.admin_id})"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(256), unique=True, nullable=False)
    location = db.Column(db.String(20))
    image_profile = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    groups_admin = db.relationship('Group', backref='admin', lazy=True)
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_profile}')"
    
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    image = db.Column(db.String(20), nullable=False, default='default.jpg')
    
    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"
    
@app.route('/')
def index():
    return render_template('homepage.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            # Login successful
            return redirect(url_for('index'))
        else:
            # Login failed
            return render_template('login.html', error='Invalid username or password')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, message='Username must be at least 3 characters long')
    ])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    location = StringField('Location')
    image_profile = FileField('Profile Picture', validators=[
        FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Images only!')
    ])
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')
            
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different email.')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        image_file = 'default.jpg'
        if form.image_profile.data:
            file = form.image_profile.data
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_file = filename

        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            location=form.location.data,
            image_profile=image_file
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/account', methods=['GET', 'POST'])
def account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    form = UpdateAccountForm()
    user = User.query.get(session['user_id'])
    
    if form.validate_on_submit():
        if form.image_profile.data:
            file = form.image_profile.data
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.image_profile = filename
            
        if form.location.data:
            user.location = form.location.data
            
        db.session.commit()
        return redirect(url_for('account'))
        
    if user:
        return render_template('account.html', user=user, form=form)
    return redirect(url_for('login'))

@app.route('/account', methods=['GET', 'POST'])
class UpdateAccountForm(FlaskForm):
    location = StringField('Location')
    image_profile = FileField('Profile Picture', validators=[
        FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Images only!')
    ])
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')
            
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different email.')

@app.route('/users')
def users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    users = User.query.all()
    current_user = User.query.get(session['user_id'])
    return render_template('users.html', users=users, current_user=current_user)

class GroupForm(FlaskForm):
    name = StringField('Group Name', validators=[
        DataRequired(),
        Length(min=3, max=100, message='Group name must be between 3 and 100 characters')
    ])
    description = TextAreaField('Description', validators=[DataRequired()])
    image = FileField('Group Image', validators=[
        FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Images only!')
    ])

@app.route('/groups')
def groups():
    groups = Group.query.all()
    form = GroupForm()
    return render_template('groups.html', groups=groups, form=form)

@app.route('/create_group', methods=['POST'])
def create_group():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    form = GroupForm()
    if form.validate_on_submit():
        image_file = 'default.jpg'
        if form.image.data:
            file = form.image.data
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER_GROUPS'], filename))
            image_file = filename
            
        group = Group(
            name=form.name.data,
            description=form.description.data,
            image=image_file,
            admin_id=session['user_id']
        )
        db.session.add(group)
        db.session.commit()
        return redirect(url_for('groups'))
    return redirect(url_for('groups'))

@app.route('/group/<int:group_id>')
def group_page(group_id):
    group = Group.query.get_or_404(group_id)
    posts = Post.query.filter_by(group_id=group.id).order_by(Post.date_posted.desc()).all()
    is_member = False
    post_form = None
    
    if 'user_id' in session:
        # Check if user is a member of the group
        user = User.query.get(session['user_id'])
        is_member = user is not None
        if is_member:
            post_form = PostForm()
    
    return render_template('group_page.html', 
                         group=group, 
                         posts=posts, 
                         is_member=is_member, 
                         post_form=post_form)

UPLOAD_FOLDER = 'static/user_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

UPLOAD_FOLDER_GROUPS = 'static/group_images'
app.config['UPLOAD_FOLDER_GROUPS'] = UPLOAD_FOLDER_GROUPS

if __name__ == '__main__':
    app.run()