from flask import Flask, flash, Markup, render_template, request, redirect, \
                  jsonify, url_for, make_response, \
                  session as login_session

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import distinct
from sqlalchemy import func

from sqlalchemy.engine import Engine
from sqlalchemy import event

from database_setup import Base, User, Category, Cat
from datetime import datetime
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests

import os
from flask import Flask, send_from_directory, request, redirect, url_for
from werkzeug.utils import secure_filename

import sys
import logging


# @event.listens_for(Engine, "connect")
# def set_sqlite_pragma(dbapi_connection, connection_record):
#     cursor = dbapi_connection.cursor()
#     cursor.execute("PRAGMA foreign_keys=ON")
#     cursor.close()


app = Flask(__name__)

app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.ERROR)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "UDC Item Catalog"

engine = create_engine('sqlite:///catgur.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

UPLOAD_FOLDER = 'static/img'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Setup site athor info for footer
# author url
@app.context_processor
def inject_authorUrl():
    return {'url': 'http://catkittycat.com'}


# copyright year
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    # strip expire tag from access token
    # token = result.split("&")[0]
    
    data = json.loads(result)

    token = 'access_token=' + data['access_token']

    url = 'https://graph.facebook.com/v2.8/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h5>Welcome, '
    output += login_session['username']

    output += '!</h5>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px;border-radius: 100px;-webkit-border-radius: 100px;-moz-border-radius: 100px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
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
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h4>Hello, '
    output += login_session['username']
    output += '!</h4>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px;border-radius: 100px;-webkit-border-radius: 100px;-moz-border-radius: 100px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session['email'],
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


@app.route('/profile')
def userProfile():
    if 'username' not in login_session:
        return redirect('/login')

    profile_id = login_session['user_id']
    mycats = session.query(Cat).filter_by(user_id=profile_id).all()

    print profile_id
    user = login_session

    return render_template('profile.html', mycats=mycats, user=user)


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Show all cats and categories
@app.route('/')
@app.route('/cats/')
def showCats():

    category_count = session.query(Category, func.count(Cat.category_id)).outerjoin(Cat).group_by(Category.id)
    cats = session.query(Cat).order_by((Cat.id).desc()).limit(9)

    return render_template('cats.html', cats=cats, category_count=category_count)


@app.route('/cats/new/', methods=['GET', 'POST'])
def newCat():
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        category_list = []
        category_request = request.form['category']
        category_list = category_request.split(',')

        category_id = int(category_list[0])
        category_name = str(category_list[1])

        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No image file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No image selected')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # populate database
            newCat = Cat(
                name=request.form['name'],
                description=request.form['description'],
                image=filename,
                category_id=category_id,
                category_name=category_name,
                user_id=login_session['user_id'])

            session.add(newCat)
            flash('New Cat %s Successfully Created' % newCat.name)
            session.commit()
        return redirect(url_for('showCats'))
    else:
        categories = session.query(Category).order_by((Category.name).asc())
        return render_template('newcat.html', categories=categories)


# Edit a restaurant
@app.route('/cats/<int:id>/edit/', methods=['GET', 'POST'])
def editCat(id):
    editedCat = session.query(Cat).filter_by(id=id).one()

    if 'username' not in login_session:
        return redirect('/login')

    if editedCat.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this Cat. Please add your own Cat in order to edit.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
        if request.form['name']:
            editedCat.name = request.form['name']
        if request.form['description']:
            editedCat.description = request.form['description']
            flash(Markup('Meow meow <strong>' + editedCat.name + \
                         '</strong> has been updated' ))
            return redirect(url_for('showCats'))
        else:
            # flash(Markup('Whoops, you need to enter a new value'))
            return render_template('editcat.html', editedCat=editedCat)
    else:
        return render_template('editcat.html', editedCat=editedCat)

@app.route('/cats/<int:id>/delete/', methods=['GET', 'POST'])
def deleteCat(id):
    # editedCat = session.query(Cat).filter_by(id=id).one()

    if 'username' not in login_session:
        return redirect('/login')

    catToDelete = session.query(Cat).filter_by(id=id).one()

    if catToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this Cat. Please add your own Cat in order to delete.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
        session.delete(catToDelete)
        session.commit()
        flash(Markup('Meow meow... <strong>' + catToDelete.name + \
                     '</strong> has been removed from existence :(' ))
        return redirect(url_for('showCats', id=id))
    else:
        return render_template('deletecat.html', cat=catToDelete)


@app.route('/cats/<int:id>/')
def showCat(id):
    cat = session.query(Cat).filter_by(id=id).one()
    creator = getUserInfo(cat.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicat.html', cat=cat)
    return render_template('cat.html', cat=cat)


@app.route('/cats/<int:id>/JSON')
def showCatJSON(id):
    cat = session.query(Cat).filter_by(id=id).one()
    return jsonify(Cat=cat.serialize)


@app.route('/category/<int:id>/')
def showCategory(id):
    category = session.query(Category).filter_by(id=id).one()
    category_cats = session.query(Cat, Category).outerjoin(Category).filter_by(id=id).all()
    return render_template('category.html', category=category, category_cats=category_cats)


@app.route('/category/<int:id>/JSON')
def showCategoryJSON(id):
    category = session.query(Category).filter_by(id=id).one()
    category_cats = session.query(Cat, Category).outerjoin(Category).filter_by(id=id).all()
    return jsonify(Category=category.serialize)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCats'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCats'))

app.secret_key = 'scully_cat'

if __name__ == '__main__':
    # app.config['SESSION_TYPE'] = 'filesystem'
    app.run(debug=True)
