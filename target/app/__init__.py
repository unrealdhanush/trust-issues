from flask import Flask

from . import admin, db, users


def create_app(db_path="shop.sqlite"):
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path
    db.init_db(db_path)
    app.register_blueprint(users.bp)
    app.register_blueprint(admin.bp)
    return app
