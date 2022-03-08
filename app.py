import os
import uuid
import logging
import jwt
import datetime

from flask import Flask, request, jsonify, make_response
from pathlib import Path
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from logging.handlers import RotatingFileHandler
from functools import wraps

from config import Config

app = Flask(__name__)
app.config.from_object(Config())

db = SQLAlchemy(app)
migrate = Migrate(app, db)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]

        if not token:
            return jsonify({"message": "Token is missing."}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms="HS256")
            print(data)
            current_user = User.query.filter_by(public_id=data["public_id"]).first()
        except:
            return jsonify({"message": "Token is invalid."}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/user", methods=["GET"])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({"message": "Cannot perform that function!"})

    users = User.query.all()
    output = list(map(lambda u: u.as_dict(), users))
    print(output)
    return jsonify({"users": output})


@app.route("/user/<public_id>", methods=["GET"])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "Cannot perform that function!"})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found."})

    return jsonify(user.as_dict())


@app.route("/user", methods=["POST"])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({"message": "Cannot perform that function!"})

    data = request.get_json()
    hashed_password = generate_password_hash(data["password"], method="sha256")

    new_user = User(
        public_id=str(uuid.uuid4()),
        name=data["name"],
        username=data["username"],
        password=hashed_password,
        admin=False,
    )
    db.session.add(new_user)
    db.session.commit()
    app.logger.info(
        "Created user:",
        new_user,
    )
    return jsonify({"message": "New user created.", "user": new_user.as_dict()})


@app.route("/user/<public_id>", methods=["PUT"])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "Cannot perform that function!"})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found."})

    user.admin = True
    db.session.commit()

    return jsonify({"message:": "The user %s has been promoted." % user.name})


@app.route("/user/<public_id>", methods=["DELETE"])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "Cannot perform that function!"})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found."})

    name = user.name
    db.session.delete(user)
    db.session.commit()

    return jsonify({"message:": "The %s has been deleted." % name})


@app.route("/login")
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response(
            "Could not verify",
            401,
            {"WWW-Authenticate": 'Basic realm="Login required!"'},
        )

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response(
            "Could not verify",
            401,
            {"WWW-Authenticate": 'Basic realm="Login required!"'},
        )

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {
                "public_id": user.public_id,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            },
            app.config["SECRET_KEY"],
        )

        return jsonify({"token": token})

    return make_response(
        "Could not verify",
        401,
        {"WWW-Authenticate": 'Basic realm="Login required!"'},
    )


@app.route("/page", methods=["GET"])
@token_required
def get_all_pages(current_user):
    pages = Page.query.filter_by(user_id=current_user.id).all()
    output = list(map(lambda p: p.as_dict(), pages))
    return jsonify({"pages": output})


@app.route("/page/<page_id>", methods=["GET"])
@token_required
def get_one_page(current_user, page_id):
    page = Page.query.filter_by(public_id=page_id).first()
    if not page:
        return jsonify({"message": "Page not found."})
    elif page.user_id != current_user.id:
        return jsonify({"message": "Page doesn't belong to current user."})

    return jsonify({"page": page.as_dict()})


@app.route("/page/shared/<public_id>", methods=["GET"])
def shared_pages(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "User not found."})

    pages = Page.query.filter_by(user_id=user.id, shared=True).all()
    output = list(map(lambda p: p.as_dict(), pages))
    return jsonify({"pages": output})


@app.route("/page", methods=["POST"])
@token_required
def create_page(current_user):
    data = request.get_json()

    new_page = Page(
        public_id=str(uuid.uuid4()),
        title=data["title"],
        text=data["text"],
        created_at=datetime.datetime.utcnow(),
        user_id=current_user.id,
        shared=data["shared"],
    )

    db.session.add(new_page)
    db.session.commit()

    return jsonify(
        {
            "message": "The page '%s' has been created." % new_page.title,
            "page": new_page.as_dict(),
        }
    )


@app.route("/page/<page_id>", methods=["PUT"])
@token_required
def edit_page(current_user, page_id):
    page = Page.query.filter_by(public_id=page_id).first()
    if not page:
        return jsonify({"message": "Page not found."})
    elif page.user_id != current_user.id:
        return jsonify({"message": "Page doesn't belong to current user."})

    data = request.get_json()

    if "shared" in data:
        page.shared = data["shared"]
    if "title" in data and data["title"] != "":
        page.title = data["title"]
    if "text" in data and data["text"] != "":
        page.text = data["text"]

    db.session.commit()

    return jsonify(
        {
            "message": "The page '%s' has been modified." % page.title,
            "page": page.as_dict(),
        }
    )


@app.route("/page/<page_id>", methods=["DELETE"])
@token_required
def delete_page(current_user, page_id):
    page = Page.query.filter_by(public_id=page_id).first()
    if not page:
        return jsonify({"message": "Page not found."})
    elif page.user_id != current_user.id:
        return jsonify({"message": "Page doesn't belong to current user."})

    title = page.title
    db.session.delete(page)
    db.session.commit()
    return jsonify({"message": "The page '%s' has been deleted." % title})


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50), nullable=False)
    admin = db.Column(db.Boolean, nullable=False)
    pages = db.relationship("Page", backref="user", lazy=True)

    def as_dict(self):
        return {
            "public_id": self.public_id,
            "username": self.username,
            "name": self.name,
            "admin": self.admin,
        }


class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    title = db.Column(db.String(50))
    text = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=False))
    shared = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def as_dict(self):
        return {
            "public_id": self.public_id,
            "title": self.title,
            "text": self.text,
            "shared": self.shared,
            "user_id": self.user_id,
            "created_at": self.created_at,
        }


if __name__ == "__main__":
    host = os.getenv("IP", "0.0.0.0")
    port = int(os.getenv("PORT", 5001))
    app.debug = True

    app.run(host=host, port=port)
