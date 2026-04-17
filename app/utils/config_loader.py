# config_loader.py

import os

# ✅ Default config values (used if config.txt doesn't exist)
DEFAULT_CONFIG = {
    "MAC_FLOOD_WINDOW": 10,
    "MAC_FLOOD_THRESHOLD": 50,
    "ICMP_SMURF_THRESHOLD": 10,
    "ICMP_SMURF_WINDOW": 5,
    "FRAG_THRESHOLD": 10,
    "FRAG_WINDOW": 5,
    "RST_FLOOD_THRESHOLD": 100,
    "RST_WINDOW_SECONDS": 1,
    "UDP_THRESHOLD": 100,
    "UDP_TIME_WINDOW": 5,
    "QUERY_RATE_THRESHOLD": 20,
    "TIME_WINDOW_DNS": 60,
    "ICMP_LARGE_THRESHOLD": 1000,
    "ICMP_ALERT_LIMIT": 5,
    "ICMP_ALERT_WINDOW": 7,
    "THRESHOLD": 30,
    "TIME_WINDOW": 6,
    "MAX_PACKETS_PER_SECOND": 5,
    "PACKET_RATE_THRESHOLD_DOS": 200,
    "RATE_TIME_WINDOW_DOS": 1
}

def create_default_config(path):
    """Creates a default config.txt file if missing."""
    with open(path, "w") as f:
        for key, val in DEFAULT_CONFIG.items():
            f.write(f"{key}={val}\n")
    print(f"[INFO] Created default '{path}'.")

def load_config(path="config.txt"):
    """
    Load thresholds from config file or create one if it doesn't exist.
    """
    if not os.path.exists(path):
        create_default_config(path)

    config = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                try:
                    config[key.strip()] = int(val.strip())
                except ValueError:
                    print(f"[WARNING] Invalid int for {key.strip()}: {val.strip()}")

    # Fill missing values with defaults
    for key, val in DEFAULT_CONFIG.items():
        config.setdefault(key, val)

    return config
