import time

class AlertDeduplicator:
    def __init__(self, expiry_seconds):
        self.expiry = expiry_seconds
        self.active_alerts = {}  # {alert: expiry_time}

    def process(self, alert):
        current = time.time()

        # is alert already there
        if alert in self.active_alerts:
            if self.active_alerts[alert] > current:
                return False  # duplicate → skip
            else:
                del self.active_alerts[alert]  # expired → remove

        # add new
        self.active_alerts[alert] = current + self.expiry
        return True