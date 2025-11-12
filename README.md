# scapy_checks
PCAP heuristics - VERY basic automated detection

```
python3 scapy_checks.py sample.pcap
```
## Output
- A 'results' directory will be created.  Within will be a directory with the name of the PCAP analyzed.

Following is a summary of each file and how to interpret the results.  
*** This is very much a work in progress ***

## Interpreting Results
1. Open results/<pcap>/summary_report.txt — get the top protocols and endpoints.
- If you see unexpected protocol → pivot to conversations.

2. Open results/<pcap>/conn_log.csv and sort by time/bytes. Look for: persistent small flows (beacons), large uploads (exfil).

3. Open results/<pcap>/summaries/http_requests.tsv — inspect any POSTs, content-types. If POSTs contain hex/base64, save the payloads for decoding.

4. check results/<pcap>/summaries/dns_long_qnames.txt — if present, decode (base32/base64/hex) the subdomain to see content.

5. check results/<pcap>/files/ for any reconstructed binaries or DOCX; run them in a safe sandbox.

6. check results/<pcap>/summaries/suricata_logs for IDS hits (if Suricata was run) — confirm matches by opening the matching packets in Wireshark.

7. combine findings: e.g., Host A → unusual subdomains → small periodic connections → Suricata alert for known malware → likely infected.

###  Wireshark Triage
- ```tcp.flags.syn==1 && tcp.flags.ack==0``` --> finds scans
- ```http.request.method == "POST"``` and ```http.content_length >0``` --< candidate exfil POSTs
- ```dns.qry.name contains "."``` and ```dns.qry.name matches "[A-Za-z0-9+/=]{20,}"```
- Use coloring rules: color DNS TXT traffic and HTTP POSTs specially to spot them visually.

# decode_dns_subdomains.py

```python3 decode_dns_subdomains.py results/sample_pcap/summaries/dns_queries.tsc```

This script will parse DNS queries from tshark output (dns_queries.tsv).
- It will try to detect suspicious long subdomains (likely encoded data).
- Attempt Base64/32, and hex decoding.
- Results will be saved in ```results/<pcap>/decoded_dns/```.
  
# Generate HTML Report
```python3 generate_report.py```

This scripts will combine all your main  outputs into one clickable HTML page:
- Summary stats
- Top protocols, endpoints, conversations
- HTTP requests/responses
- DNS queries (with decoded links)
- TLS info
- Recovered files and decoded DNS artifacts
