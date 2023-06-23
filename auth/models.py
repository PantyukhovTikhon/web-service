from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String
from werkzeug.security import generate_password_hash, check_password_hash


Base = declarative_base()


class User(Base):
    __tablename__ = 'Users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    role = Column(String(50))
    password_hash = Column(String(128))

    def __init__(self, username=None, role=None, password=None):
        self.username = username
        self.role = role
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)