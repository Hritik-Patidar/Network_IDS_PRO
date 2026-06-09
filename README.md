# Network IDS Pro

Network IDS Pro is a Python-based Network Intrusion Detection System (IDS) designed to monitor network traffic, analyze packets in real time, and generate alerts for suspicious activities. The project combines packet capturing, attack detection, database-driven threat management, and a web-based dashboard for monitoring network security events.

## Features

- Real-time packet capturing using Scapy
- Intrusion detection and traffic analysis
- Detection of suspicious and malicious activities
- Database-driven malicious IP management
- Live security alerts
- Flask-based web dashboard
- SQLite database integration
- Multi-interface packet monitoring
- Alert logging and history tracking
- Easy-to-use web interface

## Project Structure

```
Network_IDS_PRO/
│
├── main.py                 # Application entry point
├── pack_cap.py             # Packet capture and analysis
├── database.py             # Database operations
├── app.py                  # Flask application
├── templates/              # HTML templates
├── static/                 # CSS, JS, Images
├── alerts.db               # SQLite database
├── requirements.txt        # Python dependencies
└── README.md
```

## Technologies Used

- Python 3.x
- Flask
- Scapy
- SQLite
- HTML5
- CSS3
- JavaScript

## Detection Capabilities

The system can be extended to detect:

- Port Scanning
- SYN Flood Attacks
- ICMP Flood Attacks
- Suspicious IP Activity
- Brute Force Attempts
- Custom Rule-Based Attacks

## Installation

### Clone Repository

```bash
git clone https://github.com/Hritik-Patidar/Network_IDS_PRO.git
cd Network_IDS_PRO
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Virtual Environment

Windows:

```bash
venv\Scripts\activate
```

Linux:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

## Running the Project

Start the IDS:

```bash
python main.py
```

Start the Flask Dashboard:

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

## Dashboard Features

- View live alerts
- Monitor detected attacks
- Manage malicious IP addresses
- Analyze traffic statistics
- Review alert history
- Interface selection support

## Database

The project uses SQLite for:

- Alert storage
- Malicious IP management
- Event history
- Dashboard data

## Future Enhancements

- Machine Learning-based anomaly detection
- Email notifications
- Telegram alerts
- PDF report generation
- User authentication
- Advanced attack signatures
- GeoIP tracking
- Threat intelligence integration

## Screenshots

Add screenshots of:

1. Login Page
2. Dashboard
3. Live Alerts
4. Malicious IP Management
5. Packet Monitoring

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a new branch
3. Commit your changes
4. Push the branch
5. Open a Pull Request

## License

This project is intended for educational and research purposes.

## Author

**Hritik Patidar**

GitHub: https://github.com/Hritik-Patidar
