#!/usr/bin/env python
# import modules
from flask import Flask, render_template
from flask import request, redirect, jsonify, url_for, flash
from functools import wraps


from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CategoryItem, User

# new imports for anti-forgery token
from flask import session as login_session
import random
import string

# imports for this step

from oauth2client import client
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Fluffys App"

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

#################################

######################

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print
        "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps
                                 ('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius:' \
              ' 150px;-webkit-border-radius: 150px;' \
              '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print
    "done!"
    return output


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DISCONNECT

@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current'
                                            ' user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print
    'In gdisconnect access token is %s', access_token
    print
    'User name is: '
    print
    login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=' \
          '%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print
    'result is '
    print
    result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps
                                 ('Failed to revoke token '
                                  'for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# show category
@app.route('/')
@app.route('/category/')
def showCategories():
   # engine = create_engine('sqlite:///catalog.db')
   # Base.metadata.bind = engine

   DBSession = sessionmaker(bind=engine)
   session = DBSession()
    # Get all categories
   categories = session.query(Category).all()

   return render_template('category.html', categories=categories, )


# JSON api endpoint to showcategories
@app.route('/category/JSON')
def showCategoriesJSON():
    categories = session.query(Category).all()

    return jsonify(Categories=[i.serialize for i in categories])


# show category items by category id
@app.route('/category/<int:category_id> ')
@app.route('/category/<int:category_id>/items/')
def showCategory(category_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).first()
    categoryItems = session.query(CategoryItem).filter_by(
        category_id=category_id).all()

    return render_template('categorypage.html', category=category,
                           categoryItems=categoryItems)


# JSON api endpoint to show category items by category id

@app.route('/category/<int:category_id>/items/JSON')
def showCategoryJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).first()
    categoryItems = session.query(CategoryItem).filter_by(
        category_id=category_id).all()

    return jsonify(CategoryItems=[i.serialize for i in categoryItems])


# # show categoryitems by item id


@app.route('/category/<int:category_id>/items/<int:item_id>')
def showCategoryItem(category_id, item_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    showItems = session.query(CategoryItem).filter_by(id=item_id).first()

    return render_template('categoryitem.html', showItems=showItems, )


# JSON api endpoint to show category items by item id

@app.route('/category/<int:category_id>/items/<int:item_id>/JSON')
def showCategoryItemJSON(category_id, item_id):
    showItems = session.query(CategoryItem).filter_by(id=item_id).first()

    return jsonify(itemDescription=[showItems.serialize])


# add new category item

@app.route('/category/add/', methods=['GET', 'POST'])
def addCategoryItem():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        newCategoryItem = CategoryItem(name=request.form['name'],
                                       description=request.form['description'],
                                       category_id=request.form['category'],
                                       user_id=login_session['user_id'])
        session.add(newCategoryItem)
        session.commit()
        # flash message
        flash("new category Item created!")

        return redirect(url_for('showCategories'))
    else:
        categories = session.query(Category).all()

        return render_template('addcategory.html', categories=categories)


# # edit category items
@app.route('/category/<int:category_id>/items/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editCategory(category_id, item_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')

    categoryItem = session.query(CategoryItem).filter_by(id=item_id).one()

    creator = getUserInfo(categoryItem.user_id)

    category = session.query(Category).filter_by(id=category_id).one()
    categories = session.query(Category).all()

    if request.method == 'POST':
        if request.form['name']:
            categoryItem.name = request.form['name']
        if request.form['description']:
            categoryItem.description = request.form['description']
        if request.form['category']:
            categoryItem.category_id = request.form['category']
        session.add(categoryItem)
        session.commit()
        # flash message

        flash("category item has been edited!")

        return redirect(url_for('showCategoryItem',
                                category_id=categoryItem.category_id,
                                item_id=categoryItem.id, creator=creator))
    else:
        return render_template('editcategory.html', categoryItem=categoryItem,
                               category=category, categories=categories)


# delete category items
@app.route('/category/<int:category_id>/items/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    deleteItem = session.query(CategoryItem).filter_by(id=item_id).first()
    creator = getUserInfo(deleteItem.user_id)

    if request.method == 'POST':
        session.delete(deleteItem)
        session.commit()
        # flash message

        flash(" Item  has been deleted!")

        return redirect(url_for('showCategory',
                                category_id=deleteItem.category_id,
                                item_id=deleteItem.id))
    else:
        return render_template('deletecategory.html', deleteItem=deleteItem,
                               creator=creator)


# Disconnect based on provider
@app.route('/logout')
def logout():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']

        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
