import os
import hashlib
import json
import random
import string
import jinja2
import webapp2
import re
from db_models import Post, Comment, User
from google.appengine.ext import db

# template stuff
template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))

# get the config file with the "secret" for hashing
# = os.path.join(os.path.dirname(__file__), "config.json")
#with open(config_filname) as config_file:
#    config = json.load(config_file)

secret_key = "shhhhhhhhh"

# --------------------- Blog Handler -------------------------------------------

class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # hashing
    def hash_str(self, s):
        """Hashes a string concatenated with secret"""

        return hashlib.sha256("{0}{1}".format(s, secret_key)).hexdigest()

    # making the salt
    def make_salt(self):
        return "".join(random.choice(string.letters) for x in xrange(10))

    # Hash the password from email, pass, and salt! Extra secure!
    def make_pw_hash(self, email, pw, salt=None):

        if not salt:
            salt = self.make_salt()
        hashed = self.hash_str("{0}{1}{2}".format(email, pw, salt))
        return "{0}|{1}".format(hashed, salt)

    # Make sure password is valid
    def valid_pw(self, email, pw, hash):

        salt = hash.split("|")[1]
        return hash == self.make_pw_hash(email, pw, salt)

    # set cookies
    def set_cookie(self, name, val, path, secure):
        # if secure cookie
        if secure:
            cookie_val = "{0}|{1}".format(self.hash_str(val), val)
        else: # not a secure cookie
            cookie_val = val
        self.response.headers.add_header(
            "Set-cookie",
            "{0}={1}; Path={2}".format(name, cookie_val, path)
        )

    # If cookies need to be read read_cookie will decrypt if necessary
    def read_cookie(self, name, secure):
        # get the value of the cookie
        cookie_val = self.request.cookies.get(name)
        #check if it is a hashed cookie
        if cookie_val and secure:
            return cookie_val.split("|")[1]
        else:
            return cookie_val

    # ensure cooke is valid
    def valid_cookie(self, cookie_val):
        # split the cookie and get the value. Access second index
        val = cookie_val.split("|")[1]
        return cookie_val == "{0}|{1}".format(self.hash_str(val), val)

    # Make sure the post was created by user
    def user_post(self, uid, pid):
        # get the user
        user = User.get_by_id(int(uid))
        # query table and select all posts with particular user
        user_posts = db.GqlQuery(
            "SELECT * FROM Post WHERE author = '{0}'".format(user.name)
        )
        for user_post in user_posts:
            if user_post.key().id() == int(pid):
                return True
        return False

    # Make sure a comment was created by a specified user
    def user_comment(self, uid, cid):
        # get users id
        user = User.get_by_id(int(uid))
        # query db to get the comments made by user
        user_comments = db.GqlQuery(
            "SELECT * FROM Comment WHERE author = '{0}'".format(user.name)
        )
        for user_comment in user_comments:
            if user_comment.key().id() == int(cid):
                return True
        return False

    # Make sure user is logged in and valid
    def valid_user(self):
        # get the cookie of user
        user_cookie = self.request.cookies.get("user")
        # if there isn't a cookie return False => not valid
        if not user_cookie:
            return False
        # if there is a cookie make sure it's valid
        if not self.valid_cookie(user_cookie):
            return False
        # get uid and then check length
        uid = self.read_cookie("user", True)
        if len(uid) == 0:
            return False
        return True

    # Functions to make sure DB items exists. Ex: Post and comment

# --------------------- Home Page Handler --------------------------------------
class FrontPage(BlogHandler):

    def get(self):
        uid = self.read_cookie("user", True)
        if uid:
            # Check that user is valid
            if not self.valid_user():
                self.set_cookie("user", "", "/", False)
                self.redirect("/")
            else:
                user = User.get_by_id(int(uid))
                posts = db.GqlQuery(
                    "SELECT * FROM Post ORDER BY created_time DESC"
                )
                self.render("home.html", user=user, posts=posts)
        else:
            self.render("index.html")

# --------------------- SignUp, LogIn, LogOut Classes --------------------------
class SignUpPage(BlogHandler):

    # get the html template
    def get(self):
        self.render("signup.html", error=None)

    # post to DB with respective signup info
    def post(self, error=None):
        email = self.request.get("email")
        name = self.request.get("name")
        password = self.request.get("password")
        confirm = self.request.get("confirm-password")
        salt = self.make_salt()

        # Ensure all required fields have been submitted
        if len(email) == 0 or len(password) == 0 or len(confirm) == 0:
            error = "Missing one or more required fields."
        # Ensure the password and confirm password fields match
        elif password != confirm:
            error = "Your passwords do not match."
        # Ensure the email is in a valid email format
        elif not (re.match(
                  r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                  email)):
            error = "You did not enter a valid email address."
        # Ensure the email does not match a current user
        elif User.get_by_email(email):
            error = "A user with that email already exists."
        # Register the new user
        else:
            pw_hash = self.make_pw_hash(email, password, salt)
            user = User(
                email=db.Email(email),
                name=name,
                pw_hash=pw_hash,
                salt=salt
            )
            user_key = user.put()
            uid = user_key.id()
            self.set_cookie("user", str(uid), "/", True)
            self.redirect("/")
        self.render("signup.html", error=error)


class LogInPage(BlogHandler):

    #get the login html template
    def get(self):
        self.render("login.html")

    # post login info the DB and check to see if a match
    def post(self, error=None):
        email = self.request.get("email")
        password = self.request.get("password")

        # Make sure they filled in the fields
        if len(email) == 0 or len(password) == 0:
            error = "Missing one or more required fields."
        user = User.get_by_email(email)
        if not user:
            error = "Found no user with email {0}.".format(email)
        elif self.valid_pw(email, password, user.pw_hash):
            uid = user.key().id()
            self.set_cookie("user", str(uid), "/", True)
            self.redirect("/")
        else:
            error = "Username and password do not match."
        self.render("login.html", error=error)


class LogOut(BlogHandler):

    # clear the cookie
    def get(self):
        self.set_cookie("user", "", "/", False)
        self.redirect("/")

# --------------------- Post Classes -------------------------------------------

class EditPostPage(BlogHandler):
    """Handler for the edit post and new post pages"""

    def get(self, pid=None):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            # If this is a current post, edit the current post
            if pid:
                # Check that user created this post
                uid = self.read_cookie("user", True)
                post = Post.get_by_id(int(pid))
                if self.user_post(uid, pid) and post:
                    # render the edit post page
                    self.render("edit-post.html", post=post)
                # just going to view the post with comments
                else:
                    user = User.get_by_id(int(uid))
                    comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                        {0}".format(pid))
                    # render the view post html and provide error message if
                    # non-authorized user attempts to edit post
                    self.render("view-post.html", post=post, user=user,
                                comments=comments,
                                error="You cannot edit a post you did not \
                                create")
            # Else create a new post
            else:
                self.render("edit-post.html")

    def post(self, pid=None):
        title = self.request.get("title")
        content = self.request.get("content")

        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            if pid:
                # Check that user created this post
                uid = self.read_cookie("user", True)
                post = Post.get_by_id(int(pid))
                if self.user_post(uid, pid):
                    # Check to ensure title and content are not blank
                    if len(title) == 0 or len(content) == 0:
                        self.render("edit-post.html", post=post,
                                    error="Missing one or more required \
                                    fields")
                    else:
                        post.title = title
                        post.content = content
                        post.put()
                        self.redirect("/post/{0}".format(pid))
                else:
                    user = User.get_by_id(int(uid))
                    comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                             {0}".format(pid))
                    self.render("view-post.html", post=post, user=user,
                                comments=comments,
                                error="You cannot edit a post you did not \
                                create")
            else:
                # Check to ensure title and content are not blank
                if len(title) == 0 or len(content) == 0:
                    self.render("edit-post.html",
                                error="Missing one or more required fields")
                else:
                    uid = self.read_cookie("user", True)
                    user = User.get_by_id(int(uid))
                    post = Post(title=title, content=content, author=user.name)
                    post_key = post.put()
                    pid = post_key.id()
                    self.redirect("/post/{0}".format(pid))


class ViewPostPage(BlogHandler):
    def get(self, pid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            # Check if post exists
            if not post:
                self.redirect("/")
            uid = self.read_cookie("user", True)
            user = User.get_by_id(int(uid))
            comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                {0}".format(pid))
            self.render("view-post.html", post=post, user=user,
                        comments=comments)

    def post(self, pid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            # Check if this is the user's post
            own = False
            uid = self.read_cookie("user", True)
            user = User.get_by_id(int(uid))
            comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                {0}".format(pid))
            if self.user_post(uid, pid):
                own = True
                self.render("view-post.html", post=post, user=user,
                            comments=comments,
                            error="You cannot like your own post")
            # Check if user has already liked this post
            liked = False
            for like in user.liked_posts:
                if like == int(pid):
                    liked = True
                    self.render("view-post.html", post=post, user=user,
                                comments=comments,
                                error="Sorry, you only get one vote per post.")
            # Must make sure users can't like own post
            if not liked and not own:
                post.likes += 1
                post.put()
                # Associate the post with user so we can keep track
                user.liked_posts.append(int(pid))
                user.put()
                self.render("view-post.html", post=post, user=user,
                            comments=comments)


class DeletePostPage(BlogHandler):
    def get(self, pid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            # Check post exists
            post = Post.get_by_id(int(pid))
            if not post:
                return self.redirect('/login')
            # Check that user created post
            # Must ensure users can only delete their own posts
            uid = self.read_cookie("user", True)
            if self.user_post(uid, pid):
                post = Post.get_by_id(int(pid))
                # delete the post
                post.delete()
                self.redirect("/")
            # They cannot delete the post
            else:
                user = User.get_by_id(int(uid))
                post = Post.get_by_id(int(pid))
                # get the comments for the post
                comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                    {0}".format(pid))
                # render the post page for viewing
                self.render("view-post.html", post=post, user=user,
                            comments=comments,
                            error="You can only delete posts you've made.")

# --------------------- Comment Classes ----------------------------------------

class CreateCommentPage(BlogHandler):
    def get(self, pid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            self.render("edit-comment.html", post=post)

    def post(self, pid):
        cont = self.request.get("content")
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            # Check that content is not empty
            if post:
                if len(cont) == 0:
                    self.render("edit-comment.html", post=post,
                                error="Comment can't be blank")
                else:
                    uid = self.read_cookie("user", True)
                    user = User.get_by_id(int(uid))
                    # set the comment attached with author
                    comment = Comment(content=cont, author=user.name,
                                      post_id=int(pid))
                    comment.put()
                    # get the comments after comment is put and render post page
                    comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                        {0}".format(pid))
                    self.render("view-post.html", post=post, user=user,
                                comments=comments)
            else:
                self.redirect('/login')


class EditCommentPage(BlogHandler):
    def get(self, pid, cid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            comment = Comment.get_by_id(int(cid))
            # make sure comment exists
            if comment:
                # Check that this comment was created by user
                uid = self.read_cookie("user", True)
                # if the user is author of comment render edit comment html page
                if self.user_comment(uid, cid):
                    self.render("edit-comment.html", post=post, comment=comment)
                else: # otherwise they can only view the comment
                    user = User.get_by_id(int(uid))
                    self.render("view-comment.html", post=post, user=user,
                                comment=comment,
                                error="Only the author can edit this.")
            else:
                self.redirect('/login')

    def post(self, pid, cid):
        content = self.request.get("content")

        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            comment = Comment.get_by_id(int(cid))
            # Check that user created this comment
            uid = self.read_cookie("user", True)
            user = User.get_by_id(int(uid))
            if self.user_comment(uid, cid):
                # Check that content is not blank
                if len(content) == 0:
                    self.render("edit-comment.html", post=post,
                                comment=comment,
                                error="Comment can't be blank.")
                else:
                    comment.content = content
                    comment.put()
                    self.render("view-comment.html", post=post, user=user,
                                comment=comment)
            else:
                self.render("view-comment.html", post=post, user=user,
                            comment=comment,
                            error="Only the author can edit this.")

# View a comment
class ViewCommentPage(BlogHandler):

    def get(self, pid, cid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            comment = Comment.get_by_id(int(cid))
            # Check if comment exists
            if not comment:
                self.redirect("/post/{0}".format(pid))
            # Otherwise it must exist and so render the apporpriate html
            post = Post.get_by_id(int(pid))
            uid = self.read_cookie("user", True)
            user = User.get_by_id(int(uid))
            self.render("view-comment.html", post=post, user=user,
                        comment=comment)


class DeleteCommentPage(BlogHandler):

    def get(self, pid, cid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            # Make sure the author is the one doing the deleting
            uid = self.read_cookie("user", True)
            comment = Comment.get_by_id(int(cid))
            if comment:
                if self.user_comment(uid, cid):
                    comment = Comment.get_by_id(int(cid))
                    # delete the comment
                    comment.delete()
                    self.redirect("/post/{0}".format(pid))
                else:
                    user = User.get_by_id(int(uid))
                    post = Post.get_by_id(int(pid))
                    comment = Comment.get_by_id(int(cid))
                    self.render("view-comment.html", post=post, user=user,
                                comment=comment,
                                error="Only the author can delete this.")
            else:
                self.redirect('/login')

app = webapp2.WSGIApplication([
    ("/", FrontPage),
    ("/signup", SignUpPage),
    ("/login", LogInPage),
    ("/logout", LogOut),
    ("/post", EditPostPage),
    ("/post/(.*)/comment/(.*)/edit", EditCommentPage),
    ("/post/(.*)/comment/(.*)/delete", DeleteCommentPage),
    ("/post/(.*)/edit", EditPostPage),
    ("/post/(.*)/delete", DeletePostPage),
    ("/post/(.*)/comment", CreateCommentPage),
    ("/post/(.*)/comment/(.*)", ViewCommentPage),
    ("/post/(.*)", ViewPostPage)
], debug=True)
