from Tools.scripts.texi2html import increment
from flask_login import UserMixin
from datetime import datetime
from app import db

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    # payload = db.Column(db.String(10000), nullable=True)

class MaliciousIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
