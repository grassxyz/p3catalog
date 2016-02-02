from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import bleach



app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Full Stack Catalog Item"

engine = create_engine('sqlite:///catalogitem.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# handle oauth signin using google 
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')

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
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

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
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    flash("you are now logged in as %s" % login_session['username'])
    return "<html>Login Complete</html>"

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
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



@app.route('/disconnect')
def disconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['user_id']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# Return json object for catalog item
@app.route('/catalog.json')
def catalogItemJSON():
    categories= session.query(Category).all()
    if categories:
        catalog_json =[]

        for category in categories:
            tmpCatalog = {
                          'category_name' : category.name,
                          'category_id' : category.id,
            }
            tmpCatalog['items'] = []
            items = session.query(Item).filter_by(category=category)
            for item in items:
                tmpItems = {
                            'title' : item.title,
                            'item_id' : item.id,
                            'category_id' : item.category_id,
                            'description' : item.description,         
                }
                tmpCatalog['items'].append(tmpItems)
            catalog_json.append(tmpCatalog)
        data = {
                'category' : catalog_json
        }
    return jsonify(data)

# Show all categories and the latest added items
@app.route('/')
def showCategoriesAndLatestItems():
    # retrieve all categories 
    categories = session.query(Category).all()

    # return the 10 latest records
    items = session.query(Item).order_by("id desc").limit(10).all()

    if 'username' in login_session:
        return render_template('catalog.html', categories = categories, 
                                latestItems = items, creator= login_session['user_id'])
    else:
        # Create anti-forgery state token
        state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))
        login_session['state'] = state
        return render_template('catalog.html', categories = categories, 
                                latestItems = items, STATE=state)



# Show all items available for a selected category
@app.route('/catalog/<category_name>/Items')
def showAllCatalogItems(category_name):
    category = session.query(Category).filter_by(name = category_name).one()
    items = session.query(Item).filter_by(category = category)
    numItems = items.count()
    categories = session.query(Category).all()

    if 'username' in login_session:
        return render_template('catalog.html', categories = categories, selectedItems = items,
                                categoryName= category_name, numOfItems = numItems,
                                creator= login_session['user_id'])

    else:    
        return render_template('catalog.html', categories = categories, selectedItems = items,
                                categoryName= category_name, numOfItems = numItems )

   


# Show specific information about an item when selected
@app.route('/catalog/<category_name>/<item_title>')
def showCatalogItem(category_name, item_title):
    category = session.query(Category).filter_by(name = category_name).one()
    item = session.query(Item).filter_by(title = item_title).one()

    # allow edit or delete if the user is login user

    if 'username' in login_session:
        return render_template('catalogitem.html', category = category, item = item, 
                                creator= login_session['user_id'])
    else:
        return render_template('catalogitem.html', category = category, item = item)


# handle adding new catalog item
@app.route('/catalog/new', methods=['GET', 'POST'])
def addCatalogItem():
    if 'username' not in login_session:
        flash('Please login before making changes.')
        return redirect(url_for('showCategoriesAndLatestItems'))  
    if request.method == 'POST':
        # process the submitted data for addition
        category = session.query(Category).filter_by(name = request.form['category_name']).one()
        newCatalogItem = Item(
                              title=bleach.clean(request.form['title']),
                              description=bleach.clean(request.form['description']),
                              category=category,
                              user_id=login_session['user_id'])
        session.add(newCatalogItem)
        try:
            session.commit()
            flash('New Catalog %s Item Successfully Created' % (newCatalogItem.title))
        except Exception as e:
            # in case of duplicate records, roll back the changes
            session.rollback()
            if "IntegrityError" in e.message:
                flash('Duplicate Title.  Catalog item cannot be added')
        return redirect(url_for('showCategoriesAndLatestItems'))
    else:
        categories = session.query(Category).all()
        return render_template('newcatalogitem.html', categories=categories,
                                creator = login_session['user_id'])
    # return "This page will be for making a new restaurant"


# handle editting of catalog item
@app.route('/catalog/<item_title>/edit', methods=['GET', 'POST'])
def editCatalogItem(item_title):
    if 'username' not in login_session:
        flash('Please login before making changes.')
        return redirect(url_for('showCategoriesAndLatestItems'))
    catalogItem = session.query(Item).filter_by(title=item_title).one()
    if request.method == 'POST':
        # process the submitted data for update
        category = session.query(Category).filter_by(name = request.form['category_name']).one()
        if catalogItem.user_id != login_session['user_id']:
            flash('You are not allowed to edit this item')
            return redirect(url_for('showCategoriesAndLatestItems'))
        if request.form['title']:
            catalogItem.title =request.form['title']
        if request.form['description']:
            catalogItem.description=request.form['description']
        catalogItem.category=category
        session.add(catalogItem)
        try:
            session.commit()
            flash('Catalog Item Successfully Edited')
        except Exception as e:
            session.rollback()
            if "IntegrityError" in e.message:
                flash('Duplicate Title.  Catalog item cannot be edited')
        return redirect(url_for('showCategoriesAndLatestItems'))
    else:
        categories = session.query(Category).all()
        return render_template('editcatalogitem.html',item= catalogItem, categories=categories,
                                creator = login_session['user_id'])


# handle deletion of catalog item
@app.route('/catalog/<item_title>/delete', methods=['GET', 'POST'])
def deleteCatalogItem(item_title):
    if 'username' not in login_session:
        flash('Please login before making changes.')
        return redirect(url_for('showCategoriesAndLatestItems'))
    if request.method == 'POST':
        # process the submitted data for deletion
        catalogitem = session.query(Item).filter_by(title=item_title).one()
        if catalogitem.user_id != login_session['user_id']:
            flash('You are not allowed to delete this item')
            return redirect(url_for('showCategoriesAndLatestItems'))

        session.delete(catalogitem)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showCategoriesAndLatestItems'))
    else:
        return render_template('deletecatalogitem.html', item_title=item_title, 
                                creator = login_session['user_id'])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)


