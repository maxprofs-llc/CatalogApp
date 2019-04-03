
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sqlalchemy_utils import database_exists, drop_database, create_database

from database_setup import Category, CategoryItem, User, Base

engine = create_engine('sqlite:///catalog.db')

# clear database data
Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

session = DBSession()

# create sample user
user1 = User(name="Anurag Gupta", email="anurag@udacity.com",
             picture = 'https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')

session.add(user1)
session.commit()

# add category
category1 = Category(name="Foods", user_id=1)

session.add(category1)
session.commit()

# items for Foods
item1 = CategoryItem(name="pizza", user_id=1, description="one of the loved food which comes in category of fast foods.", category=category1)

session.add(item1)
session.commit()

item2 = CategoryItem(name="Burger", user_id=1, description="Its is a fast food and comes with non veg and veg also.", category=category1)

session.add(item2)
session.commit()

item3 = CategoryItem(name="Dosa", user_id=1, description="It is a south indian food.", category=category1)

session.add(item3)
session.commit()

# create second categoryu
category2 = Category(name="Ice creams", user_id=1)

session.add(category2)
session.commit()
#create item for category2
item1 = CategoryItem(name="Choco lava", user_id=1, description="Its a melted chocolate cup-cake", category=category2)

session.add(item1)
session.commit()

item2 = CategoryItem(name="Vanilla", user_id=1,  description="Its looks like white in color.", category=category2)

session.add(item2)
session.commit()

item3 = CategoryItem(name="kulfi", user_id=1,  description="Its comes with faluda.", category=category2)

session.add(item3)
session.commit()

# create category3

category3 = Category(name="Fruits", user_id=1)

session.add(category3)
session.commit()

item1 = CategoryItem(name="Apple", user_id=1, description="Its is sweet and red in color", category=category3)

session.add(item1)
session.commit()

item2 = CategoryItem(name="Orange", user_id=1, description="Its sour in taste and yellow in color.", category=category3)

session.add(item2)
session.commit()

item3 = CategoryItem(name="Banana", user_id=1, description="Yellow in color and sweet in taste.", category=category3)

session.add(item3)
session.commit()

# create category4
category4 = Category(name="Place", user_id=1)

session.add(category4)
session.commit()


categories = session.query(Category).all()
for category in categories:
    print "Category: " + category.name
