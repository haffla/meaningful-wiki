import os
import re
import hashlib
import logging
from string import letters

import webapp2
import jinja2

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = False, extensions=['jinja2.ext.autoescape'])

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def hash_pw(username, pw):
    return hashlib.sha256(username + pw + SALT).hexdigest()

class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

SALT = "aksjdf323ASdssawfssat45667fddIs21ISDA"

class Signup(BaseHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        lookup_username = db.GqlQuery("SELECT * from User WHERE username=:1", username).get()
        # lookup_email = db.GqlQuery("SELECT * from User WHERE email=:1", email).get()

        params = dict(username = username,
                      email = email)

        if lookup_username:
            params['username_exists'] = "The username already exists"
            have_error = True

        # if lookup_email:
        #     params['email_exists'] = str(lookup_email)
        #     have_error = True

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            pwhash = hash_pw(username, password)
            u = User(username = username, password = pwhash, email = email)
            key = u.put()
            self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % str(str(key.id()) + "|" + pwhash))
            self.redirect('/')

def get_user(self):
    username = self.request.get('username')
    password = self.request.get('password')
    user = db.GqlQuery("SELECT * from User WHERE username=:1", username).get()
    return user, password

def authenticate_user(self, user, password_as_cookie):
    if user.password == hash_pw(user.username, password_as_cookie):
        self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % str(str(user.key().id()) + "|" + user.password))
        return True
    # forged cookie
    else:
        return False


class Login(BaseHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'coming_from=%s; Path=/' % self.request.referer)
        self.render("login-form.html")
    def post(self):
        user, password_as_cookie = get_user(self)
        if user and authenticate_user(self, user, password_as_cookie):
            coming_from = str(self.request.cookies.get('coming_from'))
            if coming_from[-6:] != "login":
                self.redirect(coming_from)
            else:
                self.redirect("/")
        else:
            self.render('login-form.html', error_login = "Invalid login")

class Logout(BaseHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user=""; Path=/')
        self.redirect(self.request.referer)

def user_authenticated(self):
    cookie = self.request.cookies.get('user')
    error = False, False
    if cookie:
        try:
            user_id = cookie.split("|")[0]
            user_hash = cookie.split("|")[1]
        except IndexError:
            return error
        try:
            user_id = int(user_id)
            user = User.get_by_id(user_id)
            return user and user_hash == user.password, user.username
        except ValueError:
            return error
    return error
    
class Wiki(BaseHandler):
    def get(self, hyperlink):
        wiki = db.GqlQuery("SELECT * from Wiki_Post WHERE link=:1", hyperlink).get()
        hyperlink = "/_edit/%s" % hyperlink
        auth = user_authenticated(self)
        if wiki:
            self.render("wiki_main.html", wiki = wiki.content, edit_link = hyperlink, is_authorized = auth[0], username = auth[1])
        else:
            self.redirect(hyperlink)

class NewWiki(BaseHandler):
    def get(self, hyperlink):
        auth = user_authenticated(self)
        wiki = db.GqlQuery("SELECT * from Wiki_Post WHERE link=:1", hyperlink).get()
        if wiki:
            content = wiki.content
        else:
            content = ""
        if auth[0]:
            self.render("new_wiki.html", is_authorized = auth[0], username = auth[1], old_content = content)
        else:
            self.redirect("/login")
    def post(self, hyperlink):
        wiki = db.GqlQuery("SELECT * from Wiki_Post WHERE link=:1", hyperlink).get()
        content = self.request.get('content')
        if wiki:
            wiki.content = content
        else:
            wiki = Wiki_Post(content = content, link = hyperlink)
        wiki.put()
        self.redirect("/%s" % hyperlink)

class Wiki_Post(db.Model):
    link = db.StringProperty(required = False)
    content = db.TextProperty(required = False)

class User(db.Model):
    username = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    password = db.StringProperty(required = True)

app = webapp2.WSGIApplication([('/login', Login),
                               ('/logout', Logout),
                               ('/signup', Signup),
                               ('/_edit/(\w+|)', NewWiki),
                               ('/(\w+|)', Wiki)],
                              debug=True)
