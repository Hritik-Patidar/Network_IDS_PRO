# required packages: matplotlib, textwrap
#  use -> pip install matplotlib textwrap


import json
import os
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import textwrap

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILE_PATH = os.path.join(BASE_DIR, "stats.json")


def load_data():
    try:
        with open(FILE_PATH) as f:
            return json.load(f)
    except:
        return {
            "attack_counts": {},
            "protocols": {},
            "ground_truth": {}
        }


def normalize(d):
    return {k.lower().strip(): v for k, v in d.items()}


def calculate_metrics(data):
    detected = normalize(data.get("attack_counts", {}))
    actual = normalize(data.get("ground_truth", {}))

    TP = FP = FN = 0

    for attack in set(detected) | set(actual):
        a = actual.get(attack, 0)
        d = detected.get(attack, 0)

        TP += min(a, d)
        FP += max(d - a, 0)
        FN += max(a - d, 0)

    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0
    event_acc = TP / (TP + FP + FN) if (TP + FP + FN) else 0

    return TP, FP, FN, precision, recall, f1, event_acc


def add_labels(ax, bars):
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h,
                f'{int(h)}',
                ha='center', va='bottom', fontsize=8)


def wrap_labels(labels):
    return ['\n'.join(textwrap.wrap(label, 10)) for label in labels]


plt.style.use('seaborn-v0_8-darkgrid')
fig, axs = plt.subplots(2, 2, figsize=(14, 9),
                        gridspec_kw={'width_ratios': [1, 1.4]})


def update(frame):
    data = load_data()

    for ax in axs.flat:
        ax.clear()

    attacks = data.get("attack_counts", {})
    ground_truth = data.get("ground_truth", {})

    # ---------------- Top Left ----------------
    if attacks:
        labels = wrap_labels(list(attacks.keys()))
        bars = axs[0, 0].bar(labels, attacks.values())
        add_labels(axs[0, 0], bars)
        axs[0, 0].set_title("Detected Attacks", fontsize=12, weight='bold')
        axs[0, 0].tick_params(axis='x', rotation=25)

    # ---------------- Top Right ----------------
    labels_raw = list(set(ground_truth) | set(attacks))
    labels = wrap_labels(labels_raw)

    gt = [ground_truth.get(k, 0) for k in labels_raw]
    det = [attacks.get(k, 0) for k in labels_raw]

    x = range(len(labels))

    bars1 = axs[0, 1].bar(x, gt, width=0.4, label="Actual")
    bars2 = axs[0, 1].bar([i+0.4 for i in x], det, width=0.4, label="Detected")

    add_labels(axs[0, 1], bars1)
    add_labels(axs[0, 1], bars2)

    axs[0, 1].set_xticks([i+0.2 for i in x])
    axs[0, 1].set_xticklabels(labels, rotation=20)
    axs[0, 1].legend()
    axs[0, 1].set_title("Actual vs Detected", fontsize=12, weight='bold')

    # ---------------- Bottom Left ----------------
    protocols = data.get("protocols", {})
    if protocols:
        axs[1, 0].pie(protocols.values(),
                      labels=protocols.keys(),
                      autopct='%1.1f%%',
                      textprops={'fontsize': 9})
        axs[1, 0].set_title("Protocol Distribution", fontsize=12, weight='bold')

    # ---------------- Bottom Right ----------------
    TP, FP, FN, precision, recall, f1, event_acc = calculate_metrics(data)

    metrics_names = ["Precision", "Recall", "F1", "Event Acc"]
    metrics_values = [precision, recall, f1, event_acc]

    bars = axs[1, 1].bar(metrics_names, metrics_values)

    for bar in bars:
        h = bar.get_height()
        axs[1, 1].text(bar.get_x() + bar.get_width()/2, h + 0.02,
                       f'{h:.2f}', ha='center', va='bottom', fontsize=9)

    axs[1, 1].set_ylim(0, 1.1)
    axs[1, 1].set_title("IDS Event-Based Evaluation", fontsize=12, weight='bold')

    # ---------------- TEXT INFO ----------------
    total_attacks = sum(ground_truth.values())

    info_text = (
        f"Total Attacks Simulated: {total_attacks}\n"
        f"TP: {TP}    FP: {FP}    FN: {FN}\n"
        f"Precision: {precision:.2f} | Recall: {recall:.2f}\n"
        f"F1 Score: {f1:.2f} | Event Accuracy: {event_acc:.2f}"
    )

    axs[1, 1].text(
        0.5, -0.35,
        info_text,
        transform=axs[1, 1].transAxes,
        ha='center',
        fontsize=10,
        bbox=dict(facecolor='white', alpha=0.85)
    )


ani = FuncAnimation(fig, update, interval=2000, cache_frame_data=False)

plt.subplots_adjust(
    left=0.0,
    right=0.999,
    top=0.95,
    bottom=0.14,
    wspace=0.025,
    hspace=0.34
)

plt.show()