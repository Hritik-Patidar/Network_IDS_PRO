from flask import Blueprint, render_template, redirect, request, url_for, flash, jsonify
from flask_login import login_user, login_required, logout_user
from app.models import User, Alert, MaliciousIP
from werkzeug.security import check_password_hash
import datetime
import psutil
import time
from flask import Response
from app.pack_cap import live_packet_queue  # Queue containing live packet summaries

from app.capture_controller import start_capture, stop_capture
from app import db

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('views.dashboard'))
        flash("Invalid credentials")
    return render_template("login.html")

@views.route('/dashboard', endpoint='dashboard')
@login_required
def dashboard():
    interfaces = get_interfaces_with_ips()
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    malicious_ips = MaliciousIP.query.all()
    return render_template("dashboard.html", alerts=alerts, malicious_ips=malicious_ips, interfaces=interfaces)

@views.route('/add-ip', methods=['POST'])
@login_required
def add_ip():
    ip = request.form['ip']
    desc = request.form['desc']
    db.session.add(MaliciousIP(ip_address=ip, description=desc))
    db.session.commit()
    return redirect(url_for('views.dashboard'))

@views.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('views.login'))

@views.route('/simulate-alert')
def simulate_alert():
    alert = Alert(timestamp=str(datetime.datetime.now()), message="Possible intrusion detected!")
    db.session.add(alert)
    db.session.commit()
    return redirect(url_for('views.dashboard'))

@views.route('/start-capture', methods=['POST'])
def start_capture_route():
    selected_interfaces = request.form.getlist('interfaces')
    if not selected_interfaces:
        flash('Please select at least one interface.')
        return redirect(url_for('dashboard'))

    start_capture(selected_interfaces)
    flash('Packet capturing started.')
    return redirect(url_for('views.dashboard'))

@views.route('/stop-capture', methods=['POST'])
def stop_capture_route():
    stop_capture()
    flash('Packet capturing stopped.')
    return redirect(url_for('views.dashboard'))

def get_interfaces_with_ips():
    interfaces = []
    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        ip = "No IP"
        for addr in iface_addrs:
            if addr.family.name == 'AF_INET':
                ip = addr.address
        interfaces.append({
            'name': iface_name,
            'label': f"{iface_name} ({ip})"
        })
    return interfaces

@views.route('/get-alerts')
@login_required
def get_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    alert_data = [{'timestamp': alert.timestamp, 'message': alert.message} for alert in alerts]
    return jsonify(alert_data)

@views.route('/get-all-alerts')
@login_required
def get_all_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    alert_data = [{'timestamp': alert.timestamp, 'message': alert.message} for alert in alerts]
    return jsonify(alert_data)



@views.route('/stream-packets')
@login_required
def stream_packets():
    def generate():
        while True:
            try:
                message = live_packet_queue.get(timeout=5)
                yield f"data: {message}\n\n"
            except:
                time.sleep(1)

    return Response(generate(), mimetype='text/event-stream')


@views.route('/delete-ip/<int:ip_id>', methods=['POST'])
@login_required
def delete_ip(ip_id):
    ip_entry = MaliciousIP.query.get(ip_id)
    if ip_entry:
        db.session.delete(ip_entry)
        db.session.commit()
        flash('IP deleted successfully.')
    else:
        flash('IP not found.')
    return redirect(url_for('views.dashboard'))

@views.route('/delete-all-alerts', methods=['POST'])
def delete_all_alerts():
    try:
        Alert.query.delete()  # DELETE FROM alerts
        db.session.commit()
        return jsonify({"status": "success", "message": "All alerts deleted."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500