from flask import Flask,render_template,redirect,request,flash,url_for,session,send_from_directory
from flask_wtf import FlaskForm
from wtforms import IntegerField, SubmitField, StringField, PasswordField
from wtforms.validators import length, DataRequired, Email
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash,generate_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO,emit,join_room
from functools import wraps
import os,socket

app=Flask(__name__)
app.secret_key='my_secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['UPLOAD_FOLDER']='static/uploads'
socketio=SocketIO(app,cors_allowed_origins='*',async_mode='eventlet')
db=SQLAlchemy(app)
os.makedirs(app.config['UPLOAD_FOLDER'],exist_ok=True)

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(250),unique=True,nullable=False)
    email=db.Column(db.String(250),unique=True,nullable=False)
    password=db.Column(db.String(250),nullable=False)

class loginform(FlaskForm):
    email=StringField('Email', validators=[DataRequired(),Email()])
    password=PasswordField('Password', validators=[DataRequired(), length(min=2, max=32)])
    submit=SubmitField('login')

class signupform(FlaskForm):
        name=StringField('Name', validators=[DataRequired(),length(min=2, max=32)])
        email=StringField('Email', validators=[DataRequired(),Email()])
        password=PasswordField('Password', validators=[DataRequired(), length(min=2, max=32)])
        submit=SubmitField('Signup')
    
def login_required(f):
    @wraps(f)
    def dec_function(*args,**kwargs):
        if 'user_id' not in session:
            flash("please log in to access this page")
            return redirect(url_for('login'))
        return f(*args,**kwargs)
    return dec_function 

with app.app_context():
    db.create_all()



@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'));
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/Dashboard')
@login_required
def Dashboard():
     return "<h1>Dashboard (Under construction) </h1>"

@app.route('/Signup', methods=['GET', 'POST']) 
def Signup():
    form=signupform()
    if form.validate_on_submit():
        existing_user=User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered","error")
            return redirect(url_for('Signup'))
        password_hash=generate_password_hash(form.password.data)
        new_user=User(name=form.name.data, email=form.email.data, password=password_hash)
        db.session.add(new_user)
        db.session.commit()
        session['user_id']=new_user.id
        print(f"New signup -> Email: {form.email.data}, Password: {form.password.data}")
        flash('Email registered successfully','success')
        return redirect(url_for('login'))
    return render_template('Signup.html',form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form=loginform()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password,form.password.data):
            session['user_id']=user.id
            print(f"New signup -> Email: {form.email.data}, Password: {form.password.data}")
            flash("login successfull","success")
            return redirect(url_for('home'))
        else:
            flash("Invalid email or password! Try again","error")
    return render_template('login.html', form=form)

@app.route('/create_room', methods=['POST'])
@login_required
def create_room():
    room=request.form['room']
    video=request.files['video']
    username='host'
    if video:
        filename=secure_filename(f"{room}.mp4")
        video_path=os.path.join(app.config['UPLOAD_FOLDER'],filename)
        video.save(video_path)
        return redirect(url_for('room',room=room,username=username))
    return 'Video Upload failed',400

@app.route('/join/<room>')
@login_required
def join_room_by_link(room):
    username=request.args.get('username')
    if not username:
        user = User.query.get(session['user_id'])
        username = user.name if user else 'guest'
    return redirect(url_for('room',room=room,username=username))

@app.route('/room/<room>/<username>')
@login_required
def room(room,username):
    return render_template('room.html',room=room,username=username)

@app.route('/static/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],filename)

@socketio.on('join_event')
def handle_join_room(data):
    room=data['room']
    username=data['username']
    join_room(room)
    emit('user_joined',{'username':username},room=room)

@socketio.on('video_event')
def handle_video_event(data):
    emit('video_event',{
        'action': data['action'],
        'time': data['time']
    }, room=data['room'])

@socketio.on('speed_event')
def handle_speed_event(data):
    emit('speed_event', {
        'speed': data['speed']
    }, room=data['room'])
  
@socketio.on('chat_message')
def handle_chat_message(data):
    room = data['room']
    username = data['username']
    message = data['message']
    emit('chat_message', {'username': username, 'message': message}, room=room)


if __name__=='__main__':
    port=int(os.environ.get('PORT',5000))
    socketio.run(app,host='0.0.0.0', port=port)