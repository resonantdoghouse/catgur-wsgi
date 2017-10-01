from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category

engine = create_engine('sqlite:///catgur.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

category1 = Category(name="Blep", description="Mews with tongues out")
category2 = Category(name="Boop", description="Classic Nose Boop")
category3 = Category(name="Spaceship", description="Cats in boxes")
category4 = Category(name="Sunbeam", description="Recharging power cells")
category5 = Category(name="Grumpy", description="Only 18 hours of sleep")

session.add_all([category1, category2, category3, category4, category5])
session.commit()

print "added categories"
