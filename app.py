from flask import Flask,render_template,redirect,request,flash,url_for,session,send_from_directory,jsonify
from flask_wtf import FlaskForm,CSRFProtect
from wtforms import IntegerField, SubmitField, StringField, PasswordField
from wtforms.validators import Length, DataRequired, Email
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash,generate_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO,emit,join_room,leave_room
from functools import wraps
import os,socket,zipfile,io
from base64 import urlsafe_b64encode,urlsafe_b64decode
import boto3,mimetypes
from botocore.config import Config
from botocore.exceptions import ClientError
from datetime import datetime,timezone

app=Flask(__name__)
app.secret_key='my_secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['UPLOAD_FOLDER']='static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024 
socketio=SocketIO(app,cors_allowed_origins='*',async_mode='eventlet')
db=SQLAlchemy(app)
os.makedirs(app.config['UPLOAD_FOLDER'],exist_ok=True)
room_users={}
csrf=CSRFProtect(app)
R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_BUCKET = os.environ.get("R2_BUCKET")
R2_PUBLIC_DOMAIN = os.environ.get("R2_PUBLIC_DOMAIN") 
R2_ENDPOINT = os.environ.get("R2_ENDPOINT")

STORAGE_THRESHOLD_BYTES = 9 * 1024 * 1024 * 1024

def r2_client():
    if not all([R2_ENDPOINT,R2_ACCESS_KEY_ID,R2_BUCKET,R2_SECRET_ACCESS_KEY]):
        raise RuntimeError("R2 configuration missing. Set R2_* environment variables.")
    return boto3.client(
        's3',
        endpoint_url=R2_ENDPOINT,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        region_name="auto",
        config=Config(s3={"addressing_style": "virtual"})
    )
    
def r2_put_fileobj(key:str,fileobj):
    s3=r2_client()
    fileobj.seek(0)
    content_type, _ = mimetypes.guess_type(key)
    if content_type is None:
        content_type = "application/octet-stream"
    s3.put_object(Bucket=R2_BUCKET,Key=key,Body=fileobj,ContentType=content_type)
    
def r2_generate_presigned_get(key:str, expires: int=3600):
    if R2_PUBLIC_DOMAIN:
        return f"{R2_PUBLIC_DOMAIN.rstrip('/')}/{key}"
    s3=r2_client()
    content_type, _ = mimetypes.guess_type(key)
    if content_type is None:
        content_type = "application/octet-stream"
        
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket":R2_BUCKET,"Key":key,"ResponseContentType": content_type,},
        ExpiresIn=expires
    )
    
def r2_delete_prefix(prefix:str):
    s3=r2_client()
    paginator=s3.get_paginator("list_objects_v2")
    to_delete=[]
    for page in paginator.paginate(Bucket=R2_BUCKET,prefix=prefix):
        for obj in page.get("Contents",[]):
            to_delete.append({'Key':obj['Key']})
            if len(to_delete)==1000:
                s3.delete_objects(Bucket=R2_BUCKET,Delete={"Objects":to_delete})
                to_delete=[]
    if to_delete:
                s3.delete_objects(Bucket=R2_BUCKET,Delete={"Objects":to_delete})
                
def r2_total_bytes():
    s3=r2_client()
    paginator=s3.get_paginator('list_objects_v2')
    total=0
    for page in paginator.paginate(Bucket=R2_BUCKET):
        for obj in page.get('Contents',[]):
            total+=obj.get('Size',0)
    return total 

def within_capacity(adding_bytes: int = 0):
    try:
        return (r2_total_bytes() + max(0, int(adding_bytes))) < STORAGE_THRESHOLD_BYTES
    except Exception:
        return False
 
class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(250),nullable=False)
    email=db.Column(db.String(250),unique=True,nullable=False)
    password=db.Column(db.String(250),nullable=False)

class Room(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(250),unique=True,nullable=False)
    host_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    room_type = db.Column(db.String(20), nullable=False)
  
class RoomQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(20), default='queued') 
      
class loginform(FlaskForm):
    email=StringField('Email', validators=[DataRequired(),Email()])
    password=PasswordField('Password', validators=[DataRequired(), Length(min=6, max=32)])
    submit=SubmitField('login')

class signupform(FlaskForm):
        name=StringField('Name', validators=[DataRequired(),Length(min=6, max=32)])
        email=StringField('Email', validators=[DataRequired(),Email()])
        password=PasswordField('Password', validators=[DataRequired(), Length(min=6, max=32)])
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

@app.errorhandler(500)
def internal_error(error):
    import traceback
    print(traceback.format_exc())
    return "500 error", 500

def encrypt_username(username):
    return urlsafe_b64encode(username.encode()).decode()

def decrypt_username(encoded):
    return urlsafe_b64decode(encoded.encode()).decode()

@app.route("/encrypt-username/<username>")
@login_required
def encrypt_username_api(username):
    return jsonify({"encrypted": encrypt_username(username)})

def release_queue():
    queued=RoomQueue.query.filter_by(status='queued').order_by(RoomQueue.created_at.asc()).all()
    released_any=False
    for rq in queued:
        if not within_capacity(0):
            break
        new_room = Room(name=rq.name, host_id=rq.host_id, room_type=rq.room_type)
        db.session.add(new_room)
        db.session.delete(rq)
        db.session.commit()
        released_any=True
    return released_any

@app.route("/upload-url/<filename>")
def get_upload_url(filename):
    s3=r2_client()
    url=s3.generate_presigned_url(
        "put_object",
        Params={"Bucket":R2_BUCKET,"Key":filename},
        ExpiresIn=3600,
    )
    return jsonify({"upload_url":url})

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
        flash('Email registered successfully','success')
        return redirect(url_for('home'))
    return render_template('Signup.html',form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form=loginform()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password,form.password.data):
            session['user_id']=user.id
            flash("login successfull","success")
            return redirect(url_for('home'))
        else:
            flash("Invalid email or password! Try again","error")
    return render_template('login.html', form=form)

@csrf.exempt
@app.route('/create_room', methods=['POST'])
@login_required
def create_room():
    room=request.form['room']
    video=request.files.get('video')
    music_zip=request.files.get('music_zip')
    user=User.query.get(session['user_id'])
    if not user:
        return jsonify({"error": "User not found in session."}), 400
    existing=Room.query.filter_by(name=room).first()
    existing_q=RoomQueue.query.filter_by(name=room).first()
    if existing or existing_q:
        return jsonify({"error": "Room already exists. Choose another."}), 400
    room_type='video' if (video and video.filename) else 'music' if(music_zip and music_zip.filename) else None
    if not room_type:
        return jsonify({"error": "Please upload a video or a ZIP file with music tracks."}), 400
    incoming_bytes = 0
    upload_file = video if room_type == 'video' else music_zip
    if upload_file:
        if hasattr(upload_file, 'content_length') and upload_file.content_length:
            incoming_bytes = upload_file.content_length
        else:
            upload_file.stream.seek(0, os.SEEK_END)
            incoming_bytes = upload_file.stream.tell()
            upload_file.stream.seek(0)

    if not within_capacity(incoming_bytes):
        rq = RoomQueue(name=room, host_id=user.id, room_type=room_type)
        db.session.add(rq)
        db.session.commit()
        return jsonify({"error": "Storage almost full (≥ 9GB). Your room request is queued until space frees up."}), 400
    new_room=Room(name=room,host_id=user.id,room_type=room_type)
    db.session.add(new_room)
    db.session.commit()
    if room_type=='video':
        key=f"rooms/{room}/video.mp4"
        url=r2_client().generate_presigned_url(
            'put_object',
            Params={"Bucket":R2_BUCKET,"Key":key},
            ExpiresIn=3600
        )
        encrypted_username=encrypt_username(user.name)
        return jsonify({"room": room, "upload_url": url, "room_link": url_for('room', room=room, encrypted_username=encrypted_username)})
    elif room_type == 'music':
        try:
            with zipfile.ZipFile(music_zip.stream) as zip_ref:
                for member in zip_ref.infolist():
                    if member.is_dir():
                        continue
                    lower = member.filename.lower()
                    if lower.endswith(('.mp3', '.wav', '.ogg', '.flac')):
                        with zip_ref.open(member) as fsrc:
                            key = f"rooms/{room}/tracks/{secure_filename(os.path.basename(member.filename))}"
                            r2_put_fileobj(key, fsrc)
        except zipfile.BadZipFile:
            db.session.delete(new_room)
            db.session.commit()
            return jsonify({"error": "Invalid ZIP file uploaded."}), 400
        
        music_files = []
        s3 = r2_client()
        prefix = f"rooms/{room}/tracks/"
        paginator = s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=R2_BUCKET, Prefix=prefix):
            for obj in page.get('Contents', []):
                rel = obj['Key'][len(prefix):]
                if rel.lower().endswith(('.mp3', '.wav', '.ogg', '.flac')):
                    music_files.append(rel)
        
        if not music_files:
            db.session.delete(new_room)
            db.session.commit()
            return jsonify({"error": "No music files found in this room after upload."}), 400
        session['music_files_'+room]=music_files
        encrypted_username = encrypt_username(user.name)
        return jsonify({"redirect_url": url_for('music_room', room=room, encrypted_username=encrypted_username)})


@app.route('/join/<room>')
@login_required
def join_room_by_link(room):
    typed_name = request.args.get('username')
    if typed_name:
        encrypted_username = encrypt_username(typed_name)
    else:
        user = User.query.get(session['user_id'])
        encrypted_username = encrypt_username(user.name)
    room_obj=Room.query.filter_by(name=room).first()
    if not room_obj:
        flash("Room does not exist", "error")
        return redirect(url_for('home'))
    if room_obj.room_type=='video':
        return redirect(url_for('room', room=room, encrypted_username=encrypted_username))
    elif room_obj.room_type == 'music':
        files=session.get("music_files_"+room)
        if not files:
            try:
                s3=r2_client()
                paginator=s3.get_paginator('list_objects_v2')
                found=[]
                prefix=f"rooms/{room}/tracks/"
                for page in paginator.paginate(Bucket=R2_BUCKET,Prefix=prefix):
                    for obj in page.get('Contents',[]):
                        rel=obj['Key'][len(prefix):]
                        if rel.lower().endswith(('.mp3', '.wav', '.ogg', '.flac')):
                            found.append(rel)
                if found:
                    session['music_files_'+room]=found 
                files=found
            except Exception:
                files=None
        if files:
            return redirect(url_for('music_room', room=room, encrypted_username=encrypted_username))
        else:
            flash("No music files found in this room", "error")
            return redirect(url_for('home'))
    
    flash("Invalid room type", "error")
    return redirect(url_for('home'))
        

@app.route('/room/<room>/<encrypted_username>')
@login_required
def room(room,encrypted_username):
    try:
        actual_username=decrypt_username(encrypted_username)
    except Exception:
        flash("Invalid room link","error")
        return redirect(url_for("home"))
    user=User.query.get(session['user_id'])
    room_obj=Room.query.filter_by(name=room).first()
    if not room_obj:
        flash("Room does not exist",'error')
        return redirect(url_for("home"))
    is_host=room_obj.host_id==user.id
    video_key=f"rooms/{room}/video.mp4"
    try:
        video_url = r2_generate_presigned_get(video_key, expires=60 * 60)
    except ClientError:
        flash("Video not available.", "error")
        return redirect(url_for("home"))
    return render_template('room.html',room=room,username=actual_username,is_host=is_host,video_url=video_url)

@app.route('/music_room/<room>/<encrypted_username>')
@login_required
def music_room(room,encrypted_username):
    try:
        actual_username=decrypt_username(encrypted_username)
    except Exception:
        flash("Invalid room link","error")
        return redirect(url_for("home"))
    user=User.query.get(session['user_id'])
    room_obj=Room.query.filter_by(name=room).first()
    if not room_obj:
        flash("Room does not exist",'error')
        return redirect(url_for("home"))
    is_host=room_obj.host_id==user.id
    
    music_files=session.get('music_files_'+room)
    if not music_files:
        flash("No music files found in this room","error")
        return redirect(url_for("home"))
    presigned_tracks = []
    for relpath in music_files:
        key = f"rooms/{room}/tracks/{relpath}"
        try:
            url = r2_generate_presigned_get(key, expires=60 * 60)
            presigned_tracks.append({"name": relpath, "url": url})
        except ClientError:
            continue
    return render_template('music.html',room=room,username=actual_username,is_host=is_host,music_files=presigned_tracks)

@app.route('/static/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],filename)

@app.route('/static/uploads/<room>/<filename>')
@login_required
def uploaded_music_files(room,filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'],room),filename)

@socketio.on('join_event')
def handle_join_room(data):
    room=data['room']
    username=data['username']
    join_room(room)
    if room not in room_users:
        room_users[room]=set()
    room_users[room].add(username)
    emit('user_joined',{'username':username},room=room)
    room_obj = Room.query.filter_by(name=room).first()
    if room_obj and room_obj.room_type == 'music':
        host_user = User.query.get(room_obj.host_id)
        host_name = host_user.name if host_user else None
        if host_name and host_name in room_users[room]:
            emit('request_sync', {'target': username}, room=room, include_self=False)
    
@socketio.on('leave_room')
def handle_leave_room(data):
    room=data['room']
    username=data['username']
    leave_room(room)
    if room in room_users and username in room_users[room]:
        room_users[room].remove(username)
    emit('chat_message', {'username': 'System', 'message': f'{username} has left the room.'}, room=room)
    if room in room_users and len(room_users[room])==0:
        del room_users[room]
        
        session_key='music_files_'+room
        if session_key in session:
            session.pop(session_key)
            
        room_obj=Room.query.filter_by(name=room).first()
        if room_obj:
            try:
                r2_delete_prefix(f"rooms/{room}/")
            except Exception as e:
                print("R2 delete error:",e)
            db.session.delete(room_obj)
            db.session.commit() 
            release_queue()
        
@socketio.on('send_sync')
def handle_send_sync(data):
    target = data['target']  
    room = data['room']
    track = data['track']
    time_pos = data['time']
    is_playing = data['isPlaying']
    
    emit('sync_playback', {
        'track': track,
        'time': time_pos,
        'isPlaying': is_playing
    }, room=room)
    
@socketio.on('video_event')
def handle_video_event(data):
    emit('video_event',{
        'action': data['action'],
        'time': data['time']
    }, room=data['room'])
    
@socketio.on('seek_event')
def handle_seek_event(data):
    emit('seek_event', {
        'time': data['time'],
        'isPlaying': data['isPlaying'] 
    }, room=data['room'], include_self=False)
    
@socketio.on('music_event')
def handle_music_event(data):
    emit('music_event',{
        'action': data['action'],
        'time': data['time'],
        'track':data["track"]
    }, room=data['room'],include_self=False)

@socketio.on('track_change')
def handle_track_change(data):
    emit('track_change', {
        'track': data['track']
    }, room=data['room'])


@socketio.on('music_speed')
def handle_music_speed(data):
    emit('music_speed', {
        'speed': data['speed']
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

# =========================
# ADMIN (optional)
# =========================
@app.route('/admin/storage')
@login_required
def admin_storage():
    try:
        bytes_used = r2_total_bytes()
    except Exception:
        bytes_used = -1
    if bytes_used < 0:
        return "Unable to fetch R2 usage"
    mb = bytes_used / 1024 / 1024
    gb = mb / 1024
    if gb >= 1:
        return f"R2 used: {gb:.2f} GB"
    return f"R2 used: {mb:.2f} MB"

@app.route('/admin/queue')
@login_required
def admin_queue():
    q = RoomQueue.query.order_by(RoomQueue.created_at.asc()).all()
    return render_template("admin_queue.html", queue=q) 

@app.route('/admin/release-queue', methods=['POST'])
@login_required
def admin_release_queue():
    if release_queue():
        flash("queued rooms has been released.", "success")
    else:
        flash("No queued rooms released (either none in queue or capacity full).", "warning")
    return redirect(url_for('home'))

if __name__=='__main__':
    port=int(os.environ.get('PORT',5000))
    socketio.run(app,host='0.0.0.0', port=port)