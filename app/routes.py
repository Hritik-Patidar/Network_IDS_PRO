from flask import Blueprint, render_template, redirect, request, url_for, flash, jsonify, Response
from flask_login import login_user, login_required, logout_user
from app.data.models import User, Alert, MaliciousIP, DetectionRule
from werkzeug.security import check_password_hash
import psutil
import time
from app.detection_engine import live_packet_queue
from app.capture_controller import start_capture, stop_capture
from app import db

views = Blueprint('views', __name__)

# GLOBAL VARIABLE - isko functions ke andar use karne ke liye 'global' keyword chahiye
is_capturing = False

@views.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('views.dashboard'))
        flash("Invalid credentials")
    return render_template("login.html")

@views.route('/dashboard')
@login_required
def dashboard():
    interfaces = get_interfaces_with_ips()
    # Alerts limit hatayi hai taaki frontend handle kare
    alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    malicious_ips = MaliciousIP.query.all()
    detection_rules = DetectionRule.query.order_by(DetectionRule.id.desc()).all()
    return render_template("dashboard.html", 
                           capturing=is_capturing, 
                           alerts=alerts, 
                           malicious_ips=malicious_ips, 
                           detection_rules=detection_rules,
                           interfaces=interfaces)

@views.route('/start-capture', methods=['POST'])
@login_required
def start_capture_route():
    global is_capturing
    selected_interfaces = request.form.getlist('interfaces')
    if not selected_interfaces:
        flash('Please select at least one interface.')
        return redirect(url_for('views.dashboard'))

    start_capture(selected_interfaces)
    is_capturing = True  # Status updated globally
    flash('NIDS Security Shield Activated.')
    return redirect(url_for('views.dashboard'))

@views.route('/stop-capture', methods=['POST'])
@login_required
def stop_capture_route():
    global is_capturing
    stop_capture()
    is_capturing = False
    flash('NIDS Security Shield Deactivated.')
    return redirect(url_for('views.dashboard'))

@views.route('/stream-packets')
@login_required
def stream_packets():
    def generate():
        while True:
            # Agar queue empty nahi hai toh message bh
            if not live_packet_queue.empty():
                message = live_packet_queue.get()
                yield f"data: {message}\n\n"
            else:
                time.sleep(0.5) # CPU usage kam rakhne ke liye
    return Response(generate(), mimetype='text/event-stream')

@views.route('/delete-all-alerts', methods=['POST'])
@login_required
def delete_all_alerts():
    try:
        db.session.query(Alert).delete()
        db.session.commit()
        return jsonify({"status": "success", "message": "Logs wiped."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

# Baki Add-IP aur Delete-IP routes pehle jaise hi rahenge
@views.route('/add-ip', methods=['POST'])
@login_required
def add_ip():
    ip = request.form['ip']
    desc = request.form['desc']
    db.session.add(MaliciousIP(ip_address=ip, description=desc))
    db.session.commit()
    return redirect(url_for('views.dashboard'))

def normalize_rule_field(value):
    value = (value or "").strip()
    return value if value else "*"

def refresh_detection_rules():
    from app.detection_engine import reload_rules_from_db
    reload_rules_from_db()

@views.route('/add-rule', methods=['POST'])
@login_required
def add_rule():
    protocol = normalize_rule_field(request.form.get('protocol')).lower()
    message = (request.form.get('message') or "").strip()

    if protocol not in ("tcp", "udp"):
        flash("Please select TCP or UDP for the rule.")
        return redirect(url_for('views.dashboard'))

    if not message:
        flash("Rule message is required.")
        return redirect(url_for('views.dashboard'))

    detection_rule = DetectionRule(
        protocol=protocol,
        src_ip=normalize_rule_field(request.form.get('src_ip')),
        dst_ip=normalize_rule_field(request.form.get('dst_ip')),
        src_port=normalize_rule_field(request.form.get('src_port')),
        dst_port=normalize_rule_field(request.form.get('dst_port')),
        tcp_flags=normalize_rule_field(request.form.get('tcp_flags')) if protocol == "tcp" else "*",
        message=message
    )
    db.session.add(detection_rule)
    db.session.commit()
    refresh_detection_rules()
    return redirect(url_for('views.dashboard'))

@views.route('/delete-rule/<int:rule_id>', methods=['POST'])
@login_required
def delete_rule(rule_id):
    detection_rule = DetectionRule.query.get(rule_id)
    if detection_rule:
        db.session.delete(detection_rule)
        db.session.commit()
        refresh_detection_rules()
    return redirect(url_for('views.dashboard'))

@views.route('/delete-ip/<int:ip_id>', methods=['POST'])
@login_required
def delete_ip(ip_id):
    ip_entry = MaliciousIP.query.get(ip_id)
    if ip_entry:
        db.session.delete(ip_entry)
        db.session.commit()
    return redirect(url_for('views.dashboard'))

@views.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('views.login'))

def get_interfaces_with_ips():
    interfaces = []
    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        ip = "No IP"
        for addr in iface_addrs:
            if addr.family.name == 'AF_INET':
                ip = addr.address
        interfaces.append({'name': iface_name, 'label': f"{iface_name} ({ip})"})
    return interfaces

@views.route('/get-alerts') # Iske upar @login_required bhi ho sakta hai
@login_required
def get_alerts(): # Function name should be exactly this
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    alert_data = [{'timestamp': alert.timestamp, 'message': alert.message} for alert in alerts]
    return jsonify(alert_data)
