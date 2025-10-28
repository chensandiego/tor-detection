import json, collections
data = json.load(open("tor_hits.json"))
counter = collections.Counter([x['dst'] for x in data])
print("Top Tor relay destinations:")
for ip, count in counter.most_common(10):
    print(ip, count)
