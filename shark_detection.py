import pyshark
import requests

def get_tor_ips():
    url = "https://onionoo.torproject.org/details?running=true"
    data = requests.get(url).json()
    return {addr.split(':')[0] for r in data['relays'] for addr in r['or_addresses']}

def analyze_pcap(pcap_path, tor_ips):
    cap = pyshark.FileCapture(pcap_path, display_filter="ip")
    hits = []
    for pkt in cap:
        try:
            src, dst = pkt.ip.src, pkt.ip.dst
            if src in tor_ips or dst in tor_ips:
                hits.append((src, dst, pkt.highest_layer))
        except AttributeError:
            continue
    cap.close()
    return hits

if __name__ == "__main__":
    tor_ips = get_tor_ips()
    hits = analyze_pcap("capture.pcap", tor_ips)
    print(f"Found {len(hits)} Tor-related packets")
