from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category, Item

engine = create_engine('sqlite:///catalogitem.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

# add 9 different categories as dummy data into the newly created database_setup

category1 = Category(name="Soccer")
session.add(category1)
session.commit()


category2 = Category(name="Basketball")
session.add(category2)
session.commit()


category3 = Category(name="Baseball")
session.add(category3)
session.commit()


category4 = Category(name="Frisbee")
session.add(category4)
session.commit()


category5 = Category(name="Snowboarding")
session.add(category5)
session.commit()



category6 = Category(name="Rock Climbing")
session.add(category6)
session.commit()


category7 = Category(name="Football")
session.add(category7)
session.commit()


category8 = Category(name="Skating")
session.add(category8)
session.commit()


category9 = Category(name="Hockey")
session.add(category9)
session.commit()



print "added initial data for Catalog Category DB"

