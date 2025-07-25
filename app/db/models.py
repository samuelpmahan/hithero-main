from sqlalchemy import Column, Integer, String, LargeBinary
from app.db.base import Base

class School(Base):
    __tablename__ = "schools"
    id = Column(Integer, primary_key=True, index=True)
    school_name = Column(String)
    district = Column(String)
    county = Column(String)
    state = Column(String)

class NewUsers(Base):
    __tablename__ = "new_users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True, index=True)
    state = Column(String)
    county = Column(String)
    district = Column(String)
    school = Column(String)
    phone_number = Column(String)
    password = Column(String)
    role = Column(String)
    report = Column(Integer, default=0)
    emailed = Column(Integer, default=0)

class RegisteredUsers(Base):
    __tablename__ = "registered_users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    phone_number = Column(String)
    password = Column(String)
    role = Column(String)
    createCount = Column(Integer, default=0)

class TeacherList(Base):
    __tablename__ = "teacher_list"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    state = Column(String)
    county = Column(String)
    district = Column(String)
    school = Column(String)
    regUserID = Column(Integer)
    wishlist_url = Column(String)
    about_me = Column(String)
    image_data = Column(LargeBinary)
    url_id = Column(String, unique=True, index=True)

class Spotlight(Base):
    __tablename__ = "spotlight"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    name = Column(String)
    state = Column(String)
    county = Column(String)
    district = Column(String)
    school = Column(String)
    image_data = Column(LargeBinary)