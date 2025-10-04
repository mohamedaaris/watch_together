from flask import Flask,render_template,redirect,abort,request,flash,url_for,session,send_from_directory,jsonify
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
room_state={}
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
    for page in paginator.paginate(Bucket=R2_BUCKET,Prefix=prefix):
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
    role = db.Column(db.String(20), default="user") 

class Room(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(250),unique=True,nullable=False)
    host_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    room_type = db.Column(db.String(20), nullable=False)
    members = db.Column(db.Integer, default=0)
    file_name = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), default="active")
    
    memberships = db.relationship(
        "RoomMember",
        back_populates="room",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    access_requests = db.relationship(
        "RoomAccessRequest",
        back_populates="room",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    @property
    def members_count(self):
        return RoomMember.query.filter_by(room_id=self.id).count()
  
class RoomQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_type = db.Column(db.String(20), nullable=False)
    file_name = db.Column(db.String(255), nullable=True)
    size_bytes = db.Column(db.BigInteger, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(20), default='queued') 
    
class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    room = db.relationship("Room", back_populates="memberships")
    user = db.relationship("User", backref="rooms")
    
class RoomAccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("room.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending, approved, denied
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    room = db.relationship("Room", back_populates="access_requests")
    user = db.relationship("User", backref="access_requests")
    
class RoomGranted(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("room.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    granted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    room = db.relationship("Room", backref="granted_users")
    user = db.relationship("User", backref="granted_rooms")
    
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.String(250), nullable=False)
    username = db.Column(db.String(250), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

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
        required=rq.size_bytes
        if not within_capacity(required):
            break
        new_room = Room(name=rq.name, host_id=rq.host_id, room_type=rq.room_type,status="active")
        db.session.add(new_room)
        db.session.delete(rq)
        released_any=True
    if released_any:
        db.session.commit()
    return released_any

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user_id=session.get("user_id")
        if not user_id:
            abort(403)
        user=User.query.get(user_id)
        if not user or user.role!="admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

@csrf.exempt
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

@app.route('/admin/rooms')
@admin_required
def room_list():
    rooms=Room.query.all()
    queues=RoomQueue.query.all()
    return render_template("room_info.html",rooms=rooms,queues=queues)

@app.route("/api/rooms")
@admin_required
def api_rooms():
    rooms=Room.query.all()
    data=[]
    for r in rooms:
        data.append({
            "id": r.id,
            "name": r.name,
            "members": r.members_count,
            "type": r.room_type,
            "file": r.file_name,
            "status": r.status
        })
    return jsonify(data)

@app.route("/delete_room/<int:room_id>", methods=["POST"])
@admin_required
def delete_room(room_id):
    room=Room.query.get_or_404(room_id)
    try:
        try:
            r2_delete_prefix(f"rooms/{room.name}/")
        except Exception as e:
            print("R2 delete error:", e)
        db.session.delete(room)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting room: {str(e)}", "danger")
    return redirect(url_for("room_list"))

@app.route('/home')
@login_required
def home():
    user = User.query.get(session['user_id'])
    role = user.role if user else "user"
    return render_template('home.html',user_role=role)

def get_room_state(room):
    if room not in room_state:
        room_state[room] = {}
    return room_state[room]

@app.route('/landing')
def landing():
    image_folder = os.path.join(app.static_folder, "uploads")
    images = []
    if os.path.exists(image_folder):
        images = [
            f"uploads/{img}" for img in os.listdir(image_folder)
            if img.lower().endswith((".png", ".jpg", ".jpeg", ".gif"))
        ]
        images.sort()
    user_id = session.get('user_id')
    if user_id:
        user = db.session.get(User, user_id)  # SQLAlchemy 2.x style
        role = user.role if user else "user"
    else:
        user = None
        role = "user"
    return render_template("landing.html", images=images, user_role=role)

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
        return redirect(url_for('landing'))
    return render_template('Signup.html',form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form=loginform()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password,form.password.data):
            session['user_id']=user.id
            flash("login successfull","success")
            return redirect(url_for('landing'))
        else:
            flash("Invalid email or password! Try again","error")
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@csrf.exempt
@app.route('/create_room', methods=['POST'])
@login_required
def create_room():
    room=request.form['room']
    video=request.files.get('video')
    typed_name=request.form.get('username')
    music_zip=request.files.get('music_zip')
    user=User.query.get(session['user_id'])
    if not user:
        return jsonify({"error": "User not found in session."}), 400
    if not typed_name:
        typed_name = user.name
    encrypted_username = encrypt_username(typed_name)
    
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
        rq = RoomQueue(name=room, host_id=user.id, room_type=room_type,file_name=secure_filename(upload_file.filename),size_bytes=incoming_bytes,status="queued")
        db.session.add(rq)
        db.session.commit()
        return jsonify({"error": "Storage almost full (≥ 9GB). Your room request is queued until space frees up."}), 400
    new_room=Room(name=room,host_id=user.id,room_type=room_type,file_name=secure_filename(upload_file.filename),status="active",members=1)
    db.session.add(new_room)
    db.session.flush()
    if new_room.id is None:
        db.session.rollback()
        return jsonify({"error": "Room creation failed."}), 500
    room_member=RoomMember(room_id=new_room.id,user_id=user.id)
    db.session.add(room_member)
    db.session.flush()
    db.session.commit()
    
    if room_type=='video':
        key=f"rooms/{room}/video.mp4"
        url=r2_client().generate_presigned_url(
            'put_object',
            Params={"Bucket":R2_BUCKET,"Key":key},
            ExpiresIn=3600
        )
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
        encrypted_username = encrypt_username(typed_name)
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
    
    user=User.query.get(session['user_id'])
    existing_member=RoomMember.query.filter_by(room_id=room_obj.id, user_id=user.id).first()
    if not existing_member:
        room_member = RoomMember(room_id=room_obj.id, user_id=user.id)
        db.session.add(room_member)
        db.session.commit()
    room_obj.members = room_obj.members_count
    db.session.commit()
    
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

@socketio.on('request_control')
def handle_request_control(data):
    room_name = data['room']
    user = User.query.get(session['user_id'])
    room_obj = Room.query.filter_by(name=room_name).first()
    if not room_obj or not user:
        return
    existing = RoomAccessRequest.query.filter_by(room_id=room_obj.id, user_id=user.id).first()
    if not existing:
        req = RoomAccessRequest(room_id=room_obj.id, user_id=user.id)
        db.session.add(req)
        db.session.commit()

    # Notify host
    host_user = User.query.get(room_obj.host_id)
    if host_user:
        emit("control_request_received", {
            "username": user.name,
            "user_id": user.id,
            "room": room_name
        }, room=f"user_{host_user.id}")
        
@socketio.on('grant_control')
def handle_grant_control(data):
    room_name = data['room']
    user_id = data['user_id'] 
    room_obj = Room.query.filter_by(name=room_name).first()
    host_user = User.query.get(session['user_id'])

    if not room_obj or not host_user or room_obj.host_id != host_user.id:
        return
    req = RoomAccessRequest.query.filter_by(room_id=room_obj.id, user_id=user_id).first()
    if req:
        req.status = "approved"
    
    existing_grant = RoomGranted.query.filter_by(room_id=room_obj.id, user_id=user_id).first()
    if not existing_grant:
        grant = RoomGranted(room_id=room_obj.id, user_id=user_id)
        db.session.add(grant)
    db.session.commit()
    emit('control_granted', room=f"user_{user_id}")
    emit('new_granted_user', {
        "user_id": user_id,
        "username": User.query.get(user_id).name
    }, room=f"user_{host_user.id}")

@socketio.on("revoke_control")
def handle_revoke_control(data):
    room = data["room"]
    user_id = data["user_id"]
    typed_name = data.get("username")
    user = User.query.get(user_id)
    if not user:
        return
    RoomGranted.query.filter_by(user_id=user_id, room_id=Room.query.filter_by(name=room).first().id).delete()
    db.session.commit()
    username = typed_name if typed_name else user.name
    emit("control_revoked", {"user_id": user.id}, room=f"user_{user.id}")
    emit("chat_message", {
        "username": "System",
        "message": f"Host has revoked control from {username}."
    }, room=room)

@socketio.on('typing')
def typing(data):
    room = data['room']
    username = data['username']
    emit('typing', {'username': username}, to=room, include_self=False)

@socketio.on('stop_typing')
def stop_typing(data):
    room = data['room']
    emit('stop_typing', {}, to=room, include_self=False)


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
    emit('chat_message', {'username': 'System', 'message': f'{username} has joined the room.'}, room=room)
    
    previous_messages = ChatMessage.query.filter_by(room=room).order_by(ChatMessage.timestamp.asc()).all()
    history = [{'username': m.username, 'message': m.message, 'timestamp': m.timestamp.isoformat()} for m in previous_messages]
    emit('chat_history', {'messages': history}, room=request.sid)
    room_obj = Room.query.filter_by(name=room).first()
    if room_obj:
        user = User.query.filter_by(name=username).first()
        if user:
            # Check if already a member
            existing_member = RoomMember.query.filter_by(room_id=room_obj.id, user_id=user.id).first()
            if not existing_member:
                new_member = RoomMember(room_id=room_obj.id, user_id=user.id)
                db.session.add(new_member)
            # Update member count
            room_obj.members = RoomMember.query.filter_by(room_id=room_obj.id).count()
            db.session.commit()
        
        granted = RoomGranted.query.filter_by(room_id=room_obj.id).all()
        granted_list = [{"user_id": g.user_id, "username": room_users[room].get(g.user_id, g.user.name)} for g in granted]
        emit('current_granted_users', {"users": granted_list}, room=request.sid)
        if user and any(g.user_id == user.id for g in granted):
            emit('control_granted', room=request.sid)

    if room in room_state:
        emit('sync_playback', room_state[room], room=request.sid)
        
    if room_obj and room_obj.room_type == 'music':
        host_user = User.query.get(room_obj.host_id)
        if host_user:
            emit('request_sync', {'username': username}, room=f"user_{host_user.id}")
    
@socketio.on('connect')
def on_connect():
    if 'user_id' in session:
        join_room(f"user_{session['user_id']}")
        
@socketio.on('leave_room')
def handle_leave_room(data):
    room=data['room']
    username=data['username']
    leave_room(room)
    if room in room_users and username in room_users[room]:
        room_users[room].remove(username)
    emit('chat_message', {'username': 'System', 'message': f'{username} has left the room.'}, room=room)
    room_obj = Room.query.filter_by(name=room).first()
    if room_obj:
        user = User.query.filter_by(name=username).first()
        if user:
            RoomMember.query.filter_by(room_id=room_obj.id, user_id=user.id).delete()
            access_request = RoomAccessRequest.query.filter_by(room_id=room_obj.id, user_id=user.id).first()
            if access_request:
                access_request.status = "left"
        room_obj.members = RoomMember.query.filter_by(room_id=room_obj.id).count()
        db.session.commit()
        
    if room in room_users and len(room_users[room])==0:
        del room_users[room]
        if room in room_state:  
            del room_state[room]
        session_key='music_files_'+room
        if session_key in session:
            session.pop(session_key)
        if room_obj:
            try:
                r2_delete_prefix(f"rooms/{room}/")
            except Exception as e:
                print("R2 delete error:",e)
            db.session.delete(room_obj)
            db.session.commit() 
            release_queue()
            
@socketio.on('request_sync')
def handle_request_sync(data):
    room = data.get('room')
    username = data.get('username')

    if not room or not username:
        return

    room_obj = Room.query.filter_by(name=room).first()
    if not room_obj:
        return

    host_user = User.query.get(room_obj.host_id)
    if host_user:
        emit('request_sync', {'target_username': username}, room=f"user_{host_user.id}")

        
@socketio.on('send_sync')
def handle_send_sync(data):
    target = data['target']  
    room = data['room']
    time_pos = data['time']
    is_playing = data['isPlaying']
   
    payload = {
        'time': time_pos,
        'isPlaying': is_playing
    }
    if "speed" in data:
        payload['speed']=data['speed']
       
    if 'track' in data:
        payload['track']=data['track']
    emit('sync_playback', payload, room=target)
   
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
    chat_msg = ChatMessage(room=room, username=username, message=message)
    db.session.add(chat_msg)
    db.session.commit()
    emit('chat_message', {'username': username, 'message': message}, room=room)

# =========================
# ADMIN (optional)
# =========================
@app.route('/admin/storage')
@login_required
@admin_required
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



@app.route('/admin/release-queue', methods=['POST'])
@login_required
@admin_required
def admin_release_queue():
    if release_queue():
        flash("Queued rooms have been released.", "success")
    else:
        flash("No queued rooms released (either none in queue or capacity full).", "warning")
    return redirect(url_for('home'))

if __name__=='__main__':
    port=int(os.environ.get('PORT',5000))
    socketio.run(app,host='0.0.0.0', port=port)