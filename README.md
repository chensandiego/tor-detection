 # 🧅 Tor Traffic Detector (PCAP Analyzer)

This tool analyzes a `.pcap` file and detects whether any of its network packets communicate with known **Tor relays**.  
It automatically downloads the latest list of Tor relay IPs from the [Tor Project's Onionoo API](https://onionoo.torproject.org/), then compares them against your packet capture.

---

## 🚀 Features

- Fetches **live Tor relay IPs** from Onionoo.
- Parses `.pcap` files using **Scapy** (or PyShark).
- Detects any packet whose source or destination IP matches a Tor node.
- Exports matches as a JSON report (`tor_hits.json`).
- Works on macOS, Linux, and Windows.

---

## 🧰 Requirements

Install dependencies (Python 3.8+ recommended):

```bash
pip install scapy requests tqdm


Save your capture file (e.g. capture.pcap) in the same directory.

Run the script:

python detect_tor_traffic.py


The script will:

Fetch the current Tor relay IPs from Onionoo.

Analyze all packets in capture.pcap.

Save the results to tor_hits.json.
