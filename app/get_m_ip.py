# app/save_malicious_ips.py

from app import create_app
from app.models import MaliciousIP

def save_malicious_ips_to_file():
    app = create_app()
    with app.app_context():
        ips = MaliciousIP.query.all()
        ip_dict = {ip.ip_address: ip.description for ip in ips}
    return ip_dict
