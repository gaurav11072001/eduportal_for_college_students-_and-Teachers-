# config.py
import os

class Config:
    SECRET_KEY = 'your_secret_key'  # Replace with a secure key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///eduportal.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
