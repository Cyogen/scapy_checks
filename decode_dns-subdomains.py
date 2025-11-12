#!/usr/bin/env python3
import os
import base64
import binascii
import sys

if len(sys.argv) < 2:
    print("Usage: decode_dns_subdomains.py <dns_queries.tsv>")
    sys.exit(1)

dns_file = sys.argv[1]
out_dir = os.path.join(os.path.dirname(dns_file), "decoded_dns")
os.makedirs(out_dir, exist_ok=True)

def try_decode(data):
    decoded = []
    for method in ['base64', 'base32', 'hex']:
        try:
            if method == 'base64':
                decoded_bytes = base64.b64decode(data, validate=True)
            elif method == 'base32':
                decoded_bytes = base64.b32decode(data, casefold=True)
            elif method == 'hex':
                decoded_bytes = binascii.unhexlify(data)
            decoded.append((method, decoded_bytes))
        except Exception:
            continue
    return decoded

print(f"[*] Reading DNS queries from {dns_file} ...")
with open(dns_file, 'r') as f:
    lines = f.readlines()

for idx, line in enumerate(lines):
    parts = line.strip().split('\t')
    if len(parts) < 4:
        continue
    qname = parts[3].replace('.', '')  # remove dots
    if len(qname) < 20:  # skip short names
        continue
    decodes = try_decode(qname)
    for method, data in decodes:
        out_file = os.path.join(out_dir, f"dns_{idx}_{method}.bin")
        with open(out_file, 'wb') as outf:
            outf.write(data)
        print(f"[+] Decoded DNS subdomain line {idx} using {method} -> {out_file}")

print(f"[*] Done. Decoded artifacts saved in {out_dir}")
