from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os
from werkzeug.security import generate_password_hash

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)

    # Absolute path to the DB file
    base_dir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(base_dir, 'ids.db')

    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'views.login'

    # Import models after db is initialized
    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Import and register routes
    from .routes import views
    app.register_blueprint(views)

    # Create DB and default admin user (if db doesn't exist)
    if not os.path.exists(db_path):
        with app.app_context():
            db.create_all()
            print("[INFO] Database 'ids.db' created.")

            if not User.query.first():
                admin = User(
                    username='admin',
                    password=generate_password_hash('admin123')  # default password
                )
                db.session.add(admin)
                db.session.commit()
                print("[INFO] Default admin user created: username='admin', password='admin123'")

    return app
