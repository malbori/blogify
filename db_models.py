from google.appengine.ext import db


class Post(db.Model):

    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created_time = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(default=0)

# Model for comments, each has an ID which is associated with an author
class Comment(db.Model):
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created_time = db.DateTimeProperty(auto_now_add=True)
    post_id = db.IntegerProperty(required=True)


class User(db.Model):
    email = db.EmailProperty(required=True)
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    salt = db.StringProperty(required=True)
    liked_posts = db.ListProperty(int, default=None)

    @classmethod
    def get_by_email(cls, email):
        return User.all().filter("email =", email).get()
