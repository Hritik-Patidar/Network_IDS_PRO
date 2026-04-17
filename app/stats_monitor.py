import json

class IDSStats:
    def __init__(self):
        self.total_packets = 0
        self.total_alerts = 0
        self.attack_counts = {}
        self.protocols = {}

    def log_packet(self, proto):
        self.total_packets += 1
        self.protocols[proto] = self.protocols.get(proto, 0) + 1
        # print("Protocol Count",self.protocols[proto])
        self.save()

    def log_alert(self, attack):
        self.total_alerts += 1
        self.attack_counts[attack] = self.attack_counts.get(attack, 0) + 1
        self.save()

    def save(self):
        data = {
            "total_packets": self.total_packets,
            "total_alerts": self.total_alerts,
            "attack_counts": self.attack_counts,
            "protocols": self.protocols
        }
        with open("stats.json", "w") as f:
            json.dump(data, f)

    def get_stats(self):
        return {
            "total_packets": self.total_packets,
            "total_alerts": self.total_alerts,
            "attack_counts": dict(self.attack_counts),
            "protocols": dict(self.protocols)
        }
stats = IDSStats()