#!/bin/bash
# matrix_pcap_analyzer.sh
# Usage: ./matrix_pcap_analyzer.sh <file.pcap>

set -euo pipefail
PCAP="$1"
BASE=$(basename "$PCAP" .pcap)
OUT="results/$BASE"
mkdir -p "$OUT"/{pcap,txt,files,summaries}

cp "$PCAP" "$OUT/pcap/"

echo "[*] Starting analysis for $PCAP -> $OUT"

# 1) quick summary (wireshark/tshark stats)
echo "[*] Running protocol hierarchy and top endpoints..."
tshark -r "$PCAP" -q -z io,phs > "$OUT/summaries/protocol_hierarchy.txt" 2>&1 || true
tshark -r "$PCAP" -q -z endpoints,ip > "$OUT/summaries/endpoints.txt" 2>&1 || true
tshark -r "$PCAP" -q -z conv,ip > "$OUT/summaries/conversations.txt" 2>&1 || true

# 2) top talkers (by bytes/packets)
echo "[*] Top talkers (packets/bytes)..."
tshark -r "$PCAP" -T fields -e ip.src -e ip.dst -e frame.len \
  | awk '{print $1}' | sort | uniq -c | sort -rn > "$OUT/summaries/top_srcs.txt"
tshark -r "$PCAP" -T fields -e ip.src -e ip.dst -e frame.len \
  | awk '{print $2}' | sort | uniq -c | sort -rn > "$OUT/summaries/top_dsts.txt"

# 3) connections log (like Zeek conn.log)
echo "[*] Generating connection log..."
tshark -r "$PCAP" -T fields -E separator=, \
  -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e udp.srcport -e udp.dstport -e frame.len \
  > "$OUT/conn_log.csv"

# 4) HTTP/DNS/SSL highlights
echo "[*] Extracting HTTP requests and responses..."
tshark -r "$PCAP" -Y http -T fields -e frame.number -e ip.src -e ip.dst -e http.request.method \
  -e http.request.uri -e http.host -e http.response.code -E header=y > "$OUT/summaries/http_requests.tsv" || true

echo "[*] Extracting DNS queries..."
tshark -r "$PCAP" -Y "dns" -T fields -e frame.number -e ip.src -e ip.dst -e dns.qry.name -e dns.count.answers \
  > "$OUT/summaries/dns_queries.tsv" || true

echo "[*] Extracting TLS Server Names and cert subjects..."
tshark -r "$PCAP" -Y ssl -T fields -e frame.number -e ip.src -e ip.dst -e tls.handshake.extensions_server_name \
  -e x509sat.printableString > "$OUT/summaries/tls_info.tsv" || true

# 5) Extract files from HTTP (and other protocols) using tshark
echo "[*] Extracting HTTP objects (files)..."
mkdir -p "$OUT/files/http_objects"
tshark -r "$PCAP" --export-objects "http,$OUT/files/http_objects" || true

# 6) TCP stream extraction via tcpflow
echo "[*] Running tcpflow to reassemble flows..."
mkdir -p "$OUT/files/tcpflow"
tcpflow -r "$PCAP" -o "$OUT/files/tcpflow" || true

# 7) carve files with foremost (generic carving)
echo "[*] Carving files with foremost..."
foremost -i "$PCAP" -o "$OUT/files/foremost" || true

# 8) run Suricata if installed (IDS alerts)
if command -v suricata >/dev/null 2>&1; then
  echo "[*] Running Suricata IDS on pcap..."
  sudo suricata -r "$PCAP" -l "$OUT/summaries/suricata_logs" || true
fi

# 9) heuristics: DNS long labels, many subdomains, suspicious ports
echo "[*] Heuristics: detect long/encoded DNS qnames..."
awk -F'\t' 'length($4)>60 { print NR ": " $0 }' "$OUT/summaries/dns_queries.tsv" > "$OUT/summaries/dns_long_qnames.txt" || true

echo "[*] Heuristics: find frequent small-packet flows (possible exfil/bruteforce)..."
awk -F, '{ if ($9<200) print $0 }' "$OUT/conn_log.csv" > "$OUT/summaries/small_packet_flows.csv" || true

# 10) quick checks for credentials (HTTP basic auth, cleartext)
echo "[*] Searching for basic auth headers and common credential patterns..."
tshark -r "$PCAP" -Y 'http.authbasic || http.request.line contains "Authorization:"' -T fields -e http.authbasic \
  > "$OUT/summaries/http_basic_auth.txt" || true
strings -a "$PCAP" | egrep -i "pass(word|wd)|pwd=|username|user=|Authorization: Basic" > "$OUT/summaries/strings_creds.txt" || true

# 11) small summary report
echo "[*] Writing summary report..."
{
  echo "PCAP: $PCAP"
  echo "Date: $(date -u)"
  echo
  echo "Top protocols (protocol_hierarchy):"
  head -n 20 "$OUT/summaries/protocol_hierarchy.txt" || true
  echo
  echo "Top endpoints (first 20):"
  head -n 20 "$OUT/summaries/endpoints.txt" || true
  echo
  echo "HTTP requests (first 30 lines):"
  head -n 30 "$OUT/summaries/http_requests.tsv" || true
  echo
  echo "DNS queries (first 30 lines):"
  head -n 30 "$OUT/summaries/dns_queries.tsv" || true
  echo
  echo "Files carved by foremost (if any):"
  ls -la "$OUT/files/foremost" 2>/dev/null || true
} > "$OUT/summary_report.txt"

echo "[*] Done. Results in $OUT"
