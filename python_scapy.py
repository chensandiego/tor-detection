import requests
from scapy.all import rdpcap, IP
from tqdm import tqdm

# Step 1. Fetch live Tor relay IPs
def get_tor_ips():
    print("Fetching Tor relay list from Onionoo...")
    url = "https://onionoo.torproject.org/details?running=true"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    data = r.json()
    ips = set()
    for relay in data.get("relays", []):
        for addr in relay.get("or_addresses", []):
            ip = addr.split(":")[0]
            ips.add(ip)
    print(f"✅ Retrieved {len(ips)} Tor IPs")
    return ips

# Step 2. Analyze a pcap
def analyze_pcap(pcap_path, tor_ips):
    print(f"Analyzing {pcap_path}...")
    packets = rdpcap(pcap_path)
    hits = []

    for pkt in tqdm(packets, desc="Scanning packets"):
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if src in tor_ips or dst in tor_ips:
                hits.append({
                    "src": src,
                    "dst": dst,
                    "protocol": pkt[IP].proto
                })
    print(f"🔍 Found {len(hits)} Tor-related packets")
    return hits

if __name__ == "__main__":
    tor_ips = get_tor_ips()
    hits = analyze_pcap("capture.pcap", tor_ips)

    # Save results
    import json
    with open("tor_hits.json", "w") as f:
        json.dump(hits, f, indent=2)
    print("Results saved to tor_hits.json")
