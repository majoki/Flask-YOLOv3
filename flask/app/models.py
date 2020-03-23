from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login, photos
from time import time
from flask_login import UserMixin
from flask import current_app
from hashlib import md5
import jwt
import cv2
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar = db.Column(db.String(128), default='/_uploads/photos/default-avatar.jpg')
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    #打印此类的对象
    def __repr__(self):
        return '<User {}>'.format(self.username)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            current_app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def check_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)
 
class VideoCamera(object):
    def __init__(self, filepath):
        self.cap = cv2.VideoCapture(filepath) 
    
    def __del__(self):
        self.cap.release()
    
    def get_frame(self):
        success, image = self.cap.read()
        ret, jpeg = cv2.imencode('.jpg', image)
        return jpeg.tobytes()


@login.user_loader
def load_user(id):
    return User.query.get(int(id))