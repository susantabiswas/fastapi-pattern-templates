from sqlalchemy import Column, Integer, String
from google_oauth.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    fullname = Column(String)
    google_sub = Column(String, unique=True, index=True)
