# Hassaan Mudassar — 23i-0536 — CS3002 Information Security — Assignment 2
# Roll: 23i-0536   Section: G
# Part D: Generate performance benchmark chart for report

import matplotlib.pyplot as plt
import numpy as np

# Data from benchmark runs on host machine
categories = ['Handshake Latency\n(ms - lower is better)', '1 KiB Throughput\n(MB/s - higher is better)']
v1_means = [0.60, 208.2]
v2_means = [4.94, 211.5]
v1_errs = [0.69, 15.1]
v2_errs = [1.18, 14.4]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.5))

# Plot 1: Handshake Latency
x1 = np.arange(1)
width = 0.35
ax1.bar(x1 - width/2, [v1_means[0]], width, yerr=[v1_errs[0]], capsize=5, label='v1 (Baseline)', color='#e74c3c', alpha=0.85)
ax1.bar(x1 + width/2, [v2_means[0]], width, yerr=[v2_errs[0]], capsize=5, label='v2 (Hardened)', color='#2ecc71', alpha=0.85)
ax1.set_ylabel('Milliseconds (ms)')
ax1.set_title('Handshake Latency (30+ runs)')
ax1.set_xticks(x1)
ax1.set_xticklabels(['Handshake Time'])
ax1.legend()
ax1.grid(axis='y', linestyle='--', alpha=0.7)

# Add text labels on top of bars
ax1.text(-width/2, v1_means[0] + 0.3, f"{v1_means[0]:.2f} ms\n(±{v1_errs[0]:.2f})", ha='center', fontsize=9)
ax1.text(width/2, v2_means[0] + 0.3, f"{v2_means[0]:.2f} ms\n(±{v2_errs[0]:.2f})", ha='center', fontsize=9)
ax1.set_ylim(0, 7.0)

# Plot 2: Steady-State Throughput
x2 = np.arange(1)
ax2.bar(x2 - width/2, [v1_means[1]], width, yerr=[v1_errs[1]], capsize=5, label='v1 (Baseline)', color='#e74c3c', alpha=0.85)
ax2.bar(x2 + width/2, [v2_means[1]], width, yerr=[v2_errs[1]], capsize=5, label='v2 (Hardened)', color='#2ecc71', alpha=0.85)
ax2.set_ylabel('Throughput (MB/s)')
ax2.set_title('Record Throughput (1 KiB records)')
ax2.set_xticks(x2)
ax2.set_xticklabels(['Steady-State AES-GCM'])
ax2.legend()
ax2.grid(axis='y', linestyle='--', alpha=0.7)

# Add text labels
ax2.text(-width/2, v1_means[1] + 8, f"{v1_means[1]:.1f} MB/s", ha='center', fontsize=9)
ax2.text(width/2, v2_means[1] + 8, f"{v2_means[1]:.1f} MB/s", ha='center', fontsize=9)
ax2.set_ylim(0, 260)

plt.suptitle('SmartLock Performance Comparison: v1 (Insecure) vs v2 (Hardened)\nHassaan Mudassar — 23i-0536 — CS3002 Assignment 2', fontsize=11, fontweight='bold')
plt.tight_layout()
plt.savefig('performance/benchmark_chart.png', dpi=300)
print('Saved chart to performance/benchmark_chart.png')

