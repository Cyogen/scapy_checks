#!/usr/bin/env python3
import os
import sys
from pathlib import Path
import html

if len(sys.argv) < 2:
    print("Usage: generate_html_report.py <results_dir>")
    sys.exit(1)

results_dir = Path(sys.argv[1])
html_file = results_dir / "full_report.html"

def add_section(title, file_path):
    content = ""
    if file_path.exists():
        with open(file_path, 'r', errors='ignore') as f:
            lines = f.readlines()
            # escape HTML
            lines = [html.escape(line) for line in lines]
            content = "<br>".join(lines[:100])  # first 100 lines
    return f"<h2>{title}</h2>\n<pre>{content}</pre>\n"

def list_folder(title, folder_path):
    items_html = ""
    if folder_path.exists():
        for file in folder_path.iterdir():
            if file.is_file():
                items_html += f'<li><a href="{file.name}" target="_blank">{file.name}</a></li>'
    return f"<h2>{title}</h2><ul>{items_html}</ul>\n"

with open(html_file, 'w') as f:
    f.write("<html><head><meta charset='utf-8'><title>PCAP Analysis Report</title></head><body>")
    f.write(f"<h1>PCAP Analysis Report: {results_dir.name}</h1>")

    # Summary report
    summary_report = results_dir / "summary_report.txt"
    f.write(add_section("Summary Report", summary_report))

    # Protocol hierarchy
    f.write(add_section("Protocol Hierarchy", results_dir / "summaries/protocol_hierarchy.txt"))

    # Top endpoints
    f.write(add_section("Top Endpoints", results_dir / "summaries/endpoints.txt"))

    # Conversations
    f.write(add_section("Conversations", results_dir / "summaries/conversations.txt"))

    # HTTP requests
    f.write(add_section("HTTP Requests", results_dir / "summaries/http_requests.tsv"))

    # DNS queries
    f.write(add_section("DNS Queries", results_dir / "summaries/dns_queries.tsv"))

    # TLS info
    f.write(add_section("TLS Info", results_dir / "summaries/tls_info.tsv"))

    # Suricata logs if exist
    f.write(add_section("Suricata Alerts", results_dir / "summaries/suricata_logs/fast.log"))

    # Files folder
    f.write(list_folder("Recovered HTTP/TCP/Foremost Files", results_dir / "files"))

    # Decoded DNS artifacts
    f.write(list_folder("Decoded DNS Artifacts", results_dir / "decoded_dns"))

    f.write("</body></html>")

print(f"[*] HTML report generated: {html_file}")
