from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.ext.hybrid import hybrid_property
from bcrypt import hashpw, gensalt 
from config import app, db, CORS
import bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String, nullable=False)
    lname = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    phone_number = db.Column(db.String, nullable=False)
    street_address = db.Column(db.String, nullable=False)
    city = db.Column(db.String, nullable=False)
    state = db.Column(db.String, nullable=False)
    postal_code = db.Column(db.Integer, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)

    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    libraries = db.relationship('Library', backref='user')

    @property
    def password(self):
        return self._password_hash 

    @password.setter
    def password(self, password):
        self._password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def authenticate(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self._password_hash.encode('utf-8'))

    @validates('email')
    def validate_email(self, key, email):
        assert '@' in email, 'Invalid email address'
        return email

    def __repr__(self):
        return f"<Employee(id={self.id}, email='{self.email}')>"

    serialize_rules = ('-created_at', '-updated_at', '-libraries')

class Library(db.Model, SerializerMixin):
    __tablename__ = "libraries"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String, nullable=False)
    product_name = db.Column(db.String, nullable=False)
    product_description = db.Column(db.String, nullable=False)
    product_author = db.Column(db.String, nullable=False)
    product_genre = db.Column(db.String, nullable=False)
    product_logo = db.Column(db.String, nullable=False)
    product_cover = db.Column(db.String, nullable=False)
    product_images = db.Column(db.String, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    serialize_rules = ('-created_at', '-updated_at', '-user_id')