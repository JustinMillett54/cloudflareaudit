# cloudflareaudit
This tool will fetch all Enterprise Zones and compare against best practice criteria. It will output a report for each zone, as well as a summary report. 
Overview
This script audits Cloudflare zones for security configurations. It checks things like TLS versions, bot management, WAF settings, DNSSEC, and more. For each zone, it generates reports in HTML, PDF, and DOCX formats with findings, IP access rules, and DNS records. It also creates a summary report across all zones, including charts for severity distributions.
It's designed for security audits, like what Optiv might do. Logs everything to cloudflare_audit.log and console.
Requirements

Python 3.12+ (but should work on 3.8+)
Cloudflare API token with read permissions for zones, settings, DNS, firewall, etc.
Environment variables:

CLOUDFLARE_API_TOKEN: Your Bearer token.
CLOUDFLARE_API_EMAIL: Your Cloudflare account email.


Installed libraries (pip install them):

requests
reportlab (for PDFs)
pypandoc (for DOCX conversion; requires pandoc installed on your system - download from https://pandoc.org/)
matplotlib (for charts)
jinja2 (for HTML templating)
Other stdlib stuff like logging, os, etc.


No internet access beyond Cloudflare API calls.

How to Run

Set your env vars:
textexport CLOUDFLARE_API_TOKEN="your_token_here"
export CLOUDFLARE_API_EMAIL="your@email.com"

Run the script:
python CfAudit.py

Outputs go to cloudflare_audit_reports/ directory:

Per-zone: HTML, PDF, DOCX files named like domain_com_zoneid_audit_report.ext
Summary: summary_audit_report.html, .pdf, .docx


Check the log file for details or errors.

What It Checks

Min TLS version (wants 1.2+)
True Client IP header
Bot management
Security level (not too low)
HTTP/3
DNSSEC
Always Use HTTPS
Legacy WAF (flags if enabled)
Firewall rules
Managed rulesets
Rate limiting
IP access rules (with details)

It fetches all DNS records too, paginating if needed.
Notes

API calls are logged with debug info.
Reports use colors for severity: Critical (red), High (orange), etc.
Charts in summary: Pie for overall severities, bar for critical/high per zone.
If something fails (e.g., API error), it logs and adds to findings as High severity.
No data is sent anywhere; all local.

Limitations

Assumes you have access to all zones.
PDF generation uses reportlab; might wrap text funny on long descriptions.
DOCX via pypandoc - make sure pandoc is installed or it won't work.
No config options yet; hardcoded checks.

TODO

Add args for specific zones or output dir.
More checks? Like custom rules details.
Better error handling for charts.

If you spot bugs, fix 'em or let me know!
