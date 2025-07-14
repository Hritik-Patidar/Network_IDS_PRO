# capture_controller.py
from threading import Thread, Event
from scapy.all import sniff
import psutil
from scapy.all import get_if_list

capture_thread = None
stop_event = Event()

# def get_malicious_ips():
#     from flask import current_app
#     from app.models import MaliciousIP
#     with current_app.app_context():
#         print({ip.ip_address: ip.description for ip in MaliciousIP.query.all()})# ✅ This ensures correct context
#         return {ip.ip_address: ip.description for ip in MaliciousIP.query.all()}



def start_capture(user_selected_labels):
    from app.pack_cap import process_packet
    # Step 1: Map user-friendly labels to actual interface names
    def convert_labels_to_interfaces(labels):
        system_interfaces = psutil.net_if_addrs()
        interface_names = list(system_interfaces.keys())

        # If user passed exact interface names (which is usually the case), filter only valid ones
        return [iface for iface in labels if iface in interface_names]

    # Step 2: Sniff packets on the resolved interfaces
    def sniff_packets():
        real_interfaces = convert_labels_to_interfaces(user_selected_labels)
        print(real_interfaces)
        print(user_selected_labels)
        if not real_interfaces:
            print("[ERROR] No valid interfaces selected!")
            return
        # iface=['\\Device\\NPF_{52F4584F-BE2D-4E86-ABA1-309686B35F46}', '\\Device\\NPF_{20F8FBDD-8495-4693-B41C-F79FF40637ED}', '\\Device\\NPF_{85B91764-AA8B-445E-9F26-4DC26D416AD6}', '\\Device\\NPF_{ED81A4E9-A6C5-4AD6-9B1E-43A16783395E}', '\\Device\\NPF_{1C90D410-3FB6-43DF-95C0-91027B3243FF}', '\\Device\\NPF_{BF5A0F0A-0714-415E-ACB9-D526C63652E7}', '\\Device\\NPF_{4DBCEC39-328B-453D-AE50-F324F8C7EF3B}', '\\Device\\NPF_Loopback', '\\Device\\NPF_{0E572C0D-8330-4E8F-A310-AE0DF394B677}', '\\Device\\NPF_{60C9B6C4-8E12-4980-8245-9C5902D99132}']
        sniff(iface=real_interfaces, prn=process_packet, store=0, stop_filter=lambda x: stop_event.is_set())

    # Step 3: Start the thread
    global capture_thread
    stop_event.clear()
    capture_thread = Thread(target=sniff_packets)
    capture_thread.start()

def stop_capture():
    stop_event.set()



def save_alert_to_db(message):
    from app import db, create_app
    from app.models import Alert
    import datetime

    app = create_app()
    with app.app_context():
        alert = Alert(timestamp=str(datetime.datetime.now()), message=message)
        db.session.add(alert)
        db.session.commit()