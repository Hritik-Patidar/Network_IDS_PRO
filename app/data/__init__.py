from app import db, create_app
from app.models import User  # adjust if your User model is in another file

app = create_app()

with app.app_context():
    db.create_all()
    # Optional: Add default admin user
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='admin')  # hash your password in real usage
        db.session.add(admin)
        db.session.commit()
