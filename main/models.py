from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime


Base = declarative_base()


class Subject(Base):
    __tablename__ = 'Subjects'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True)
    quantity = Column(Integer)


class Customer(Base):
    __tablename__ = "Customers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(32), nullable=False)
    address = Column(String(32), nullable=False)
    passport_details = Column(String(32), nullable=False, unique=True)
    phone_number = Column(String(32), nullable=False)


class Order(Base):
    __tablename__ = "Orders"
    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, nullable=False)
    subject_name = Column(String(50), nullable=False)
    quantity = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Audit(Base):
    __tablename__ = "Audit"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
