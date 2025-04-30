from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, EmailField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, ValidationError
from datetime import datetime
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'bekne'
db = SQLAlchemy(app)

group_members = db.Table('group_members',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image = db.Column(db.String(20), nullable=False, default='default.jpg')
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    posts = db.relationship('Post', backref='group', lazy=True)
    members = db.relationship('User', secondary=group_members, backref=db.backref('groups', lazy='dynamic'))
    
    def __repr__(self):
        return f"Group('{self.name}', Created by User ID: {self.admin_id})"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(256), unique=True, nullable=False)
    location = db.Column(db.String(20))
    image_profile = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    posts = db.relationship('Post', backref='author', lazy=True)
    groups_admin = db.relationship('Group', backref='admin', lazy=True)
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_profile}')"
    
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    image = db.Column(db.String(20), nullable=False, default='default.jpg')
    
    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"
    
@app.route('/')
def index():
    groups = Group.query.order_by(Group.date_created.desc()).limit(6).all()
    posts = Post.query.order_by(Post.date_posted.desc()).limit(8).all()
    return render_template('homepage.html', groups=groups, posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'info')
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
        flash('Your account has been created! You can now log in.', 'success')
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
        flash('Your account has been updated!', 'success')
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
    image = SelectField('Group Image', choices=[
        ('board-games.jpg', 'Board Games'),
        ('book.jpg', 'Books'),
        ('brony.jpg', 'Brony'),
        ('furry.jpg', 'Furry'),
        ('music.jpg', 'Music'),
        ('public_transport.jpg', 'Public Transport'),
        ('video_games.jpg', 'Video Games')
    ])
    custom_image = FileField('Or Upload Custom Image', validators=[
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
        image_file = form.image.data
        if form.custom_image.data:
            file = form.custom_image.data
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
        user = User.query.get(session['user_id'])
        is_member = user in group.members
        if is_member:
            post_form = PostForm()
    
    return render_template('group_page.html', 
                         group=group, 
                         posts=posts, 
                         is_member=is_member, 
                         post_form=post_form)

class PostForm(FlaskForm):
    title = StringField('Title', validators=[
        DataRequired(),
        Length(min=3, max=100, message='Title must be between 3 and 100 characters')
    ])
    content = TextAreaField('Content', validators=[DataRequired()])
    image = FileField('Post Image', validators=[
        FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Images only!')
    ])

UPLOAD_FOLDER = 'static/user_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

UPLOAD_FOLDER_GROUPS = 'static/group_images'
app.config['UPLOAD_FOLDER_GROUPS'] = UPLOAD_FOLDER_GROUPS

UPLOAD_FOLDER_POSTS = 'static/post_images'
app.config['UPLOAD_FOLDER_POSTS'] = UPLOAD_FOLDER_POSTS

@app.route('/group/<int:group_id>/post', methods=['POST'])
def create_group_post(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    form = PostForm()
    if form.validate_on_submit():
        image_file = 'default.jpg'
        if form.image.data:
            file = form.image.data
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER_POSTS'], filename))
            image_file = filename
            
        post = Post(
            title=form.title.data,
            content=form.content.data,
            date_posted=datetime.utcnow(),
            user_id=session['user_id'],
            group_id=group_id,
            image=image_file
        )
        db.session.add(post)
        db.session.commit()
        
    return redirect(url_for('group_page', group_id=group_id))

@app.route('/group/<int:group_id>/join', methods=['POST'])
def join_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    group = Group.query.get_or_404(group_id)
    user = User.query.get(session['user_id'])
    
    if user not in group.members:
        group.members.append(user)
        db.session.commit()
    
    return redirect(url_for('group_page', group_id=group_id))

@app.route('/group/<int:group_id>/leave', methods=['POST'])
def leave_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    group = Group.query.get_or_404(group_id)
    user = User.query.get(session['user_id'])
    
    if user in group.members:
        group.members.remove(user)
        db.session.commit()
    
    return redirect(url_for('group_page', group_id=group_id))

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/user/<int:user_id>')
def user_page(user_id):
    profile_user = User.query.get_or_404(user_id)
    return render_template('userpage.html', profile_user=profile_user)

if __name__ == '__main__':
    app.run(port='5001')