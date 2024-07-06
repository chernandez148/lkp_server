# Standard library imports

# Remote library imports
import os
from flask import Flask, jsonify
from flask_cors import CORS
from flask_migrate import Migrate
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from flask_jwt_extended import JWTManager

# Instantiate app, set attributes
app = Flask(__name__)

# Configure CORS with flask_cors
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

app.config['STRIPE_API_KEY'] = os.environ.get('STRIPE_API_KEY')
app.config['DOMAIN_URL'] = os.environ.get('DOMAIN_URL')

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
#     'connect_args': {
#         'connect_timeout': 28800
#     }
# }
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['CORS_HEADERS'] = 'Content-Type'
app.json.compact = False

# Define metadata, instantiate db
metadata = MetaData(naming_convention={
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
})
db = SQLAlchemy(metadata=metadata)
migrate = Migrate(app, db)
db.init_app(app)
jwt = JWTManager(app)

# Instantiate REST API
api = Api(app)

# Your other configurations and routes