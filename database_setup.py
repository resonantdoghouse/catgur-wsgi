import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    @property
    def serialize(self):
        """Return object data in serialized format"""
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'picture': self.picture
        }


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(String(250))

    @property
    def serialize(self):
        """Return object data in serialized format"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description
        }


class Cat(Base):
    __tablename__ = 'cat'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(String(250))
    image = Column(String(250), nullable=False)
    category_id = Column(Integer, ForeignKey('category.id'), nullable=False)
    category_name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in serialized format"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'image': self.image,
            'category_id': self.category_id,
            'category_name': self.category_name,
            'user_id': self.user_id
        }


engine = create_engine('sqlite:///catgur.db')
Base.metadata.create_all(engine)
