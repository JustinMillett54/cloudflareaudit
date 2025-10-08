import requests
import json
import logging
import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import pypandoc
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for PDF generation
import matplotlib.pyplot as plt
import io
import jinja2
import time
import base64
from datetime import datetime  # Added this for date formatting in reports

# Logging setup - good for debugging API calls and errors
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cloudflare_audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# API configuration - pull from env vars for security
CLOUDFLARE_API_TOKEN = os.getenv('CLOUDFLARE_API_TOKEN')
CLOUDFLARE_API_EMAIL = os.getenv('CLOUDFLARE_API_EMAIL')
BASE_URL = "https://api.cloudflare.com/client/v4"

# Headers for API requests - auth stuff here
headers = {
    "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
    "X-Auth-Email": CLOUDFLARE_API_EMAIL,
    "Content-Type": "application/json"
}

# Jinja2 environment setup - using this for HTML templates
env = jinja2.Environment()

# HTML template for zone and summary reports - this is the base structure for reports
template_string = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloudflare Security Audit Report - {{ title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { font-size: 24px; font-weight: bold; margin-bottom: 16px; }
        h2 { font-size: 20px; font-weight: bold; margin-top: 24px; margin-bottom: 8px; }
        p { margin-bottom: 8px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
        th, td { border: 1px solid #000; padding: 8px; text-align: left; }
        th { background-color: #d3d3d3; font-weight: bold; }
        .critical { background-color: #CC3333; color: #000000; }
        .high { background-color: #CC6633; color: #000000; }
        .medium { background-color: #CCCC33; color: #000000; }
        .low { background-color: #33CC33; color: #000000; }
        .compliant { background-color: #3366CC; color: #000000; }
        .break-words { word-wrap: break-word; max-width: 0; }
        img { max-width: 50%; height: auto; }
    </style>
</head>
<body>
    <h1>Cloudflare Security Audit Report - {{ title }}</h1>
    <p>Prepared by: Optiv Security</p>
    <p>Date: {{ date }}</p>

    {% if zone_name %}
    <p>Domain: {{ zone_name }}</p>
    <p>Zone ID: {{ zone_id }}</p>

    <h2>Findings</h2>
    {% if findings %}
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Description</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>
            {% for finding in findings %}
            <tr class="{{ finding.severity.lower() }}">
                <td>{{ finding.severity }}</td>
                <td class="break-words">{{ finding.description }}</td>
                <td class="break-words">{{ finding.recommendation }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p>No findings available.</p>
    {% endif %}

    <h2>IP Access Rules</h2>
    {% if ip_access_rules %}
    <table>
        <thead>
            <tr>
                <th>Target</th>
                <th>Value</th>
                <th>Action</th>
                <th>Notes</th>
            </tr>
        </thead>
        <tbody>
            {% for rule in ip_access_rules %}
            <tr>
                <td class="break-words">{{ rule.target }}</td>
                <td class="break-words">{{ rule.value }}</td>
                <td>{{ rule.action }}</td>
                <td class="break-words">{{ rule.notes }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p>No IP Access Rules configured.</p>
    {% endif %}

    <h2>DNS Records</h2>
    {% if dns_records %}
    <table>
        <thead>
            <tr>
                <th>Record Name</th>
                <th>Type</th>
                <th>Content</th>
                <th>Proxied</th>
                <th>TTL</th>
                <th>Comment</th>
            </tr>
        </thead>
        <tbody>
            {% for record in dns_records %}
            <tr>
                <td class="break-words">{{ record.name }}</td>
                <td>{{ record.type }}</td>
                <td class="break-words">{{ record.content }}</td>
                <td>{{ record.proxied }}</td>
                <td>{{ record.ttl }}</td>
                <td class="break-words">{{ record.comment }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p>{{ dns_records_message }}</p>
    {% endif %}
    {% endif %}

    {% if zones_data %}
    <h2>Summary</h2>
    <table>
        <thead>
            <tr>
                <th>Zone Name</th>
                <th>Critical</th>
                <th>High</th>
                <th>Medium</th>
                <th>Low</th>
                <th>Info</th>
                <th>Compliant</th>
                <th>IP Access Rules</th>
                <th>Old WAF</th>
            </tr>
        </thead>
        <tbody>
            {% for zone in zones_data %}
            <tr>
                <td class="break-words">{{ zone.name }}</td>
                <td>{{ zone.critical }}</td>
                <td>{{ zone.high }}</td>
                <td>{{ zone.medium }}</td>
                <td>{{ zone.low }}</td>
                <td>{{ zone.info }}</td>
                <td>{{ zone.compliant }}</td>
                <td>{{ zone.ip_access_rules }}</td>
                <td>{{ zone.old_waf }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <h2>Severity Distribution</h2>
    <img src="{{ pie_chart }}" alt="Severity Distribution Pie Chart">

    <h2>Critical and High Findings by Zone</h2>
    <img src="{{ bar_chart }}" alt="Critical and High Findings Bar Chart">
    {% endif %}
</body>
</html>
"""

# Paragraph style for table cells (PDF) - tweaking this for better wrapping in PDFs
styles = getSampleStyleSheet()
cell_style = ParagraphStyle(
    name='CellStyle',
    parent=styles['BodyText'],
    fontSize=8,
    leading=10,
    wordWrap='CJK'
)

def check_min_tls_version(zone_id, zone_name):
    # Checking if TLS is at least 1.2 - old versions are a big no-no
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/min_tls_version"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            tls_version = data['result']['value']
            if tls_version in ["1.0", "1.1"]:
                findings.append({
                    'severity': 'Critical',
                    'description': f"{zone_name}: Minimum TLS version is {tls_version}.",
                    'recommendation': "Set minimum TLS version to 1.2 or higher."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Minimum TLS version is {tls_version}.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve TLS version: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching TLS version for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching TLS version: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_true_client_ip_header(zone_id, zone_name):
    # Make sure we're getting the real client IP - important for logging and security
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/true_client_ip_header"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: True Client IP Header is disabled.",
                    'recommendation': "Enable True Client IP Header."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: True Client IP Header is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve True Client IP: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching True Client IP for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching True Client IP: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_bot_management(zone_id, zone_name):
    # Bot management - nice to have, but not critical unless you're getting hammered by bots
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/bot_management"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'Low',
                    'description': f"{zone_name}: Bot Management is disabled.",
                    'recommendation': "Consider enabling Bot Management."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Bot Management is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'Low',
                'description': f"{zone_name}: Bot Management unavailable: {response.status_code} {response.reason}",
                'recommendation': "Consider upgrading plan."
            })
    except Exception as e:
        logger.error(f"Error fetching Bot Management for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'Low',
            'description': f"{zone_name}: Error fetching Bot Management: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_security_level(zone_id, zone_name):
    # Security level - don't want it too lax
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/security_level"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            level = data['result']['value']
            if level in ["low", "essentially_off"]:
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: Security level is {level}.",
                    'recommendation': "Set security level to 'medium' or higher."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Security level is {level}.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve security level: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching security level for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching security level: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_http3(zone_id, zone_name):
    # HTTP/3 - performance thing, but good to enable if possible
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/http3"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'Low',
                    'description': f"{zone_name}: HTTP/3 with QUIC is disabled.",
                    'recommendation': "Consider enabling HTTP/3."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: HTTP/3 with QUIC is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve HTTP/3: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching HTTP/3 for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching HTTP/3: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_dnssec(zone_id, zone_name):
    # DNSSEC - really should be on to prevent spoofing
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/dnssec"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            status = data['result']['status']
            if status == "disabled":
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: DNSSEC is disabled.",
                    'recommendation': "Enable DNSSEC."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: DNSSEC is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve DNSSEC: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching DNSSEC for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching DNSSEC: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_always_use_https(zone_id, zone_name):
    # Force HTTPS - no excuses for not having this on
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/always_use_https"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "off":
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: Always Use HTTPS is disabled.",
                    'recommendation': "Enable Always Use HTTPS."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Always Use HTTPS is enabled.",
                    'recommendation': "No action needed."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve Always Use HTTPS: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching Always Use HTTPS for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching Always Use HTTPS: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_waf(zone_id, zone_name):
    # Legacy WAF - if this is on, time to migrate
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/settings/waf"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if value == "on":
                findings.append({
                    'severity': 'Critical',
                    'description': f"{zone_name}: Legacy WAF is enabled.",
                    'recommendation': "Migrate to new WAF rulesets."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: Legacy WAF is disabled.",
                    'recommendation': "Ensure modern WAF rulesets are configured."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve WAF: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching WAF for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching WAF: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_ip_access_rules(zone_id, zone_name):
    # Pulling IP rules - these can be allow/block, flag if none or issues
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/firewall/access_rules/rules"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            rules = data.get('result', [])
            if not rules:
                findings.append({
                    'severity': 'Medium',
                    'description': f"{zone_name}: No IP Access Rules configured.",
                    'recommendation': "Consider configuring IP Access Rules."
                })
            for rule in rules:
                target = rule.get('configuration', {}).get('target', 'N/A')
                value = rule.get('configuration', {}).get('value', 'N/A')
                mode = rule.get('mode', 'N/A')
                notes = rule.get('notes', 'None')
                severity = 'Compliant' if mode == 'allow' else 'High' if mode == 'block' else 'Medium'
                findings.append({
                    'severity': severity,
                    'description': f"{zone_name}: IP Access Rule - Target: {target}, Value: {value}, Action: {mode}, Notes: {notes}",
                    'recommendation': "Review rule alignment with security policies."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve IP Access Rules: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching IP Access Rules for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching IP Access Rules: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_firewall_rules(zone_id, zone_name):
    # Firewall rules - at least make sure some exist
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/rulesets"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            rulesets = data.get('result', [])
            if not rulesets:
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: No firewall rules found.",
                    'recommendation': "Configure firewall rules."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: {len(rulesets)} firewall rulesets found.",
                    'recommendation': "Review rulesets."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve firewall rules: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching firewall rules for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching firewall rules: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_managed_rules(zone_id, zone_name):
    # Managed rules - Cloudflare's pre-built ones, should be using them
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/rulesets"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            rulesets = data.get('result', [])
            managed_rulesets = [r for r in rulesets if r.get('kind') == 'managed']
            if not managed_rulesets:
                findings.append({
                    'severity': 'High',
                    'description': f"{zone_name}: No managed rulesets found.",
                    'recommendation': "Enable managed rulesets."
                })
            else:
                for ruleset in managed_rulesets:
                    ruleset_id = ruleset.get('id', 'N/A')
                    status = ruleset.get('phase', 'N/A')
                    findings.append({
                        'severity': 'Compliant' if status != 'disabled' else 'High',
                        'description': f"{zone_name}: Managed ruleset {ruleset_id} is {status}.",
                        'recommendation': "Ensure managed rulesets are enabled."
                    })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve managed rules: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching managed rules for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching managed rules: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def check_rate_limiting(zone_id, zone_name):
    # Rate limiting - optional but useful for DDoS protection
    findings = []
    try:
        url = f"{BASE_URL}/zones/{zone_id}/rulesets?phase=http_ratelimit"
        response = requests.get(url, headers=headers)
        logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            rulesets = data.get('result', [])
            if not rulesets:
                findings.append({
                    'severity': 'Low',
                    'description': f"{zone_name}: No rate limiting rules configured.",
                    'recommendation': "Consider configuring rate limiting rules."
                })
            else:
                findings.append({
                    'severity': 'Compliant',
                    'description': f"{zone_name}: {len(rulesets)} rate limiting rulesets found.",
                    'recommendation': "Review rate limiting rules."
                })
        else:
            findings.append({
                'severity': 'High',
                'description': f"{zone_name}: Failed to retrieve rate limiting rules: {response.status_code} {response.reason}",
                'recommendation': "Check API token permissions."
            })
    except Exception as e:
        logger.error(f"Error fetching rate limiting rules for {zone_id}: {str(e)}")
        findings.append({
            'severity': 'High',
            'description': f"{zone_name}: Error fetching rate limiting rules: {str(e)}",
            'recommendation': "Verify API token and connectivity."
        })
    return findings

def fetch_all_dns_records(zone_id, zone_name):
    # Grab all DNS records, paging through if there's a lot
    dns_records = []
    page = 1
    per_page = 100
    try:
        while True:
            url = f"{BASE_URL}/zones/{zone_id}/dns_records?page={page}&per_page={per_page}"
            response = requests.get(url, headers=headers)
            logger.debug(f"API call: {url}, Status: {response.status_code}, Content: {response.text}")
            if response.status_code == 200:
                data = response.json()
                records = data.get('result', [])
                for record in records:
                    logger.debug(f"DNS Record: Type={record.get('type', 'N/A')}, Name={record.get('name', 'N/A')}, Content={record.get('content', 'N/A')}, Proxied={record.get('proxied', 'N/A')}, TTL={record.get('ttl', 'N/A')}, Comment={record.get('comment', 'None')}")
                dns_records.extend(records)
                result_info = data.get('result_info', {})
                total_pages = result_info.get('total_pages', 1)
                total_count = result_info.get('total_count', len(records))
                logger.info(f"Retrieved {len(records)} DNS records for {zone_name}, page {page}/{total_pages}, total: {total_count}")
                if page >= total_pages:
                    break
                page += 1
            else:
                logger.error(f"Failed to retrieve DNS records for {zone_name}: {response.status_code} {response.reason}")
                return f"Failed to retrieve DNS records: {response.status_code} {response.reason}"
    except Exception as e:
        logger.error(f"Error fetching DNS records for {zone_id}: {str(e)}")
        return f"Error fetching DNS records: {str(e)}"
    return dns_records

def generate_zone_pdf(zone_id, zone_name, findings, dns_records):
    # Building the PDF for a single zone - using reportlab for tables and text
    html_file = f"cloudflare_audit_reports/{zone_name.replace('.', '_')}_{zone_id}_audit_report.html"
    pdf_file = f"cloudflare_audit_reports/{zone_name.replace('.', '_')}_{zone_id}_audit_report.pdf"
    logger.info(f"Generating HTML and PDF for {zone_name}: {html_file}, {pdf_file}")

    try:
        # Prepare IP Access Rules data
        ip_access_rules = []
        for rule in [f for f in findings if "IP Access Rule - Target:" in f['description']]:
            try:
                parts = rule['description'].split(' - ')[1].split(', ')
                if len(parts) >= 4:
                    ip_access_rules.append({
                        'target': parts[0].split(': ')[1],
                        'value': parts[1].split(': ')[1],
                        'action': parts[2].split(': ')[1],
                        'notes': parts[3].split(': ')[1]
                    })
                else:
                    logger.warning(f"Skipping malformed IP Access Rule for {zone_name}: {rule['description']}")
            except (IndexError, KeyError) as e:
                logger.warning(f"Error parsing IP Access Rule for {zone_name}: {rule['description']}, Error: {str(e)}")

        # Prepare DNS Records data
        dns_records_data = []
        dns_records_message = "No DNS records found."
        if isinstance(dns_records, list):
            if dns_records:
                for record in dns_records:
                    content = record.get('content', 'N/A')
                    ttl = record.get('ttl', 'N/A')
                    if ttl == 1:
                        ttl = 'Auto'
                    if record.get('type') == 'MX':
                        content = f"{record.get('priority', 'N/A')} {content}"
                    elif record.get('type') == 'SRV':
                        content = f"{record.get('data', {}).get('priority', 'N/A')} {record.get('data', {}).get('target', 'N/A')}"
                    elif record.get('type') == 'NS':
                        content = record.get('content', 'N/A')
                    dns_records_data.append({
                        'name': record.get('name', 'N/A'),
                        'type': record.get('type', 'N/A'),
                        'content': content,
                        'proxied': str(record.get('proxied', False)),
                        'ttl': str(ttl),
                        'comment': str(record.get('comment', 'None'))
                    })
            else:
                dns_records_message = "No DNS records found."
        else:
            dns_records_message = dns_records

        # Render HTML
        template = env.from_string(template_string)
        rendered_html = template.render(
            title=zone_name,
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            zone_name=zone_name,
            zone_id=zone_id,
            findings=findings,
            ip_access_rules=ip_access_rules,
            dns_records=dns_records_data,
            dns_records_message=dns_records_message
        )

        # Save HTML
        with open(html_file, 'w') as f:
            f.write(rendered_html)
        if os.path.exists(html_file):
            logger.info(f"HTML generated successfully for {zone_name}: {html_file}")
        else:
            logger.error(f"HTML file not found after generation for {zone_name}: {html_file}")

        # Generate PDF with reportlab
        doc = SimpleDocTemplate(pdf_file, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        title_style = styles['Heading1']
        body_style = styles['BodyText']
        pdf_severity_colors = {
            'Critical': colors.Color(0.8, 0.2, 0.2),
            'High': colors.Color(0.8, 0.4, 0.2),
            'Medium': colors.Color(0.8, 0.8, 0.2),
            'Low': colors.Color(0.2, 0.8, 0.2),
            'Compliant': colors.Color(0.2, 0.4, 0.8),
            'Info': colors.grey
        }

        elements.append(Paragraph("Cloudflare Security Audit Report", title_style))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"Domain: {zone_name}", body_style))
        elements.append(Paragraph(f"Zone ID: {zone_id}", body_style))
        elements.append(Paragraph(f"Prepared by: Optiv Security", body_style))
        elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
        elements.append(Spacer(1, 24))

        elements.append(Paragraph("Findings", title_style))
        if findings:
            data = [['Severity', 'Description', 'Recommendation']]
            for finding in findings:
                severity = finding['severity']
                description = Paragraph(finding['description'], cell_style)
                recommendation = Paragraph(finding['recommendation'], cell_style)
                data.append([Paragraph(severity, cell_style), description, recommendation])
            
            col_widths = [100, 200, 200]
            table = Table(data, colWidths=col_widths, splitByRow=True)
            table_styles = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('WORDWRAP', (0, 0), (-1, -1), 'CJK')
            ]
            for i, finding in enumerate(findings, 1):
                table_styles.append((
                    'BACKGROUND', (0, i), (-1, i),
                    pdf_severity_colors.get(finding['severity'], colors.beige)
                ))
            table.setStyle(TableStyle(table_styles))
            elements.append(table)
        else:
            elements.append(Paragraph("No findings available.", body_style))
        elements.append(Spacer(1, 24))

        elements.append(Paragraph("IP Access Rules", title_style))
        if ip_access_rules:
            data = [['Target', 'Value', 'Action', 'Notes']]
            for rule in ip_access_rules:
                data.append([
                    Paragraph(rule['target'], cell_style),
                    Paragraph(rule['value'], cell_style),
                    Paragraph(rule['action'], cell_style),
                    Paragraph(rule['notes'], cell_style)
                ])
            col_widths = [100, 100, 100, 100]
            table = Table(data, colWidths=col_widths, splitByRow=True)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('WORDWRAP', (0, 0), (-1, -1), 'CJK')
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph("No IP Access Rules configured.", body_style))
        elements.append(Spacer(1, 24))

        elements.append(Paragraph("DNS Records", title_style))
        if isinstance(dns_records, list):
            if dns_records:
                data = [['Record Name', 'Type', 'Content', 'Proxied', 'TTL', 'Comment']]
                for record in dns_records_data:
                    data.append([
                        Paragraph(record['name'], cell_style),
                        Paragraph(record['type'], cell_style),
                        Paragraph(record['content'], cell_style),
                        Paragraph(record['proxied'], cell_style),
                        Paragraph(record['ttl'], cell_style),
                        Paragraph(record['comment'], cell_style)
                    ])
                col_widths = [100, 80, 100, 80, 50, 100]
                table = Table(data, colWidths=col_widths, splitByRow=True)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 4),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                    ('WORDWRAP', (0, 0), (-1, -1), 'CJK')
                ]))
                elements.append(table)
            else:
                elements.append(Paragraph("No DNS records found.", body_style))
        else:
            elements.append(Paragraph(f"DNS Records: {dns_records}", body_style))
        elements.append(Spacer(1, 24))

        doc.build(elements)
        if os.path.exists(pdf_file):
            logger.info(f"PDF generated successfully for {zone_name}: {pdf_file}")
        else:
            logger.error(f"PDF file not found after generation for {zone_name}: {pdf_file}")

        return html_file, pdf_file
    except Exception as e:
        logger.error(f"Error generating HTML/PDF for {zone_name} ({zone_id}): {str(e)}")
        return None, None

def generate_zone_docx(zone_id, zone_name, findings, dns_records):
    # Convert HTML to DOCX - relies on pypandoc and pandoc
    html_file = f"cloudflare_audit_reports/{zone_name.replace('.', '_')}_{zone_id}_audit_report.html"
    docx_file = f"cloudflare_audit_reports/{zone_name.replace('.', '_')}_{zone_id}_audit_report.docx"
    logger.info(f"Generating DOCX for {zone_name}: {docx_file}")

    try:
        if not os.path.exists(html_file):
            logger.error(f"HTML file not found for {zone_name}: {html_file}")
            return None

        # Convert HTML to DOCX using pypandoc
        pypandoc.convert_file(
            html_file,
            'docx',
            outputfile=docx_file,
            extra_args=['--standalone']
        )

        if os.path.exists(docx_file):
            logger.info(f"DOCX generated successfully for {zone_name}: {docx_file}")
        else:
            logger.error(f"DOCX file not found after generation for {zone_name}: {docx_file}")
        
        return docx_file
    except Exception as e:
        logger.error(f"Error generating DOCX for {zone_name} ({zone_id}): {str(e)}")
        return None

def generate_pie_chart(zones_data):
    # Quick pie chart for severity counts across zones
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Compliant': 0}
    for zone in zones_data:
        for finding in zone['findings']:
            severity_counts[finding['severity']] += 1
    
    labels = [k for k, v in severity_counts.items() if v > 0]
    sizes = [v for k, v in severity_counts.items() if v > 0]
    colors_list = ['#CC3333', '#CC6633', '#3366CC', '#CCCC33', '#cccccc', '#33CC33']
    colors_list = colors_list[:len(labels)]
    
    plt.figure(figsize=(4, 4))
    plt.pie(sizes, labels=labels, colors=colors_list, autopct='%1.1f%%', startangle=90)
    plt.title('Severity Distribution Across All Zones')
    plt.axis('equal')
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close()
    buf.seek(0)
    return buf.getvalue()

def generate_bar_chart(zones_data):
    # Bar chart for critical/high per zone - helps spot problem areas
    zone_names = [zone['name'] for zone in zones_data]
    critical_counts = []
    high_counts = []
    for zone in zones_data:
        severity_counts = {'Critical': 0, 'High': 0}
        for finding in zone['findings']:
            if finding['severity'] in severity_counts:
                severity_counts[finding['severity']] += 1
        critical_counts.append(severity_counts['Critical'])
        high_counts.append(severity_counts['High'])
    
    fig, ax = plt.subplots(figsize=(6, 4))
    bar_width = 0.35
    x = range(len(zone_names))
    ax.bar([i - bar_width/2 for i in x], critical_counts, bar_width, label='Critical', color='#CC3333')
    ax.bar([i + bar_width/2 for i in x], high_counts, bar_width, label='High', color='#CC6633')
    ax.set_xlabel('Zones')
    ax.set_ylabel('Number of Findings')
    ax.set_title('Critical and High Findings by Zone')
    ax.set_xticks(x)
    ax.set_xticklabels(zone_names, rotation=45, ha='right')
    ax.legend()
    plt.tight_layout()
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close()
    buf.seek(0)
    return buf.getvalue()

def generate_summary_docx(zones_data):
    # Summary DOCX from HTML
    html_file = "cloudflare_audit_reports/summary_audit_report.html"
    docx_file = "cloudflare_audit_reports/summary_audit_report.docx"
    logger.info(f"Generating summary DOCX: {docx_file}")
    
    try:
        if not os.path.exists(html_file):
            logger.error(f"Summary HTML file not found: {html_file}")
            return None

        # Convert HTML to DOCX using pypandoc
        pypandoc.convert_file(
            html_file,
            'docx',
            outputfile=docx_file,
            extra_args=['--standalone']
        )

        if os.path.exists(docx_file):
            logger.info(f"Summary DOCX generated successfully: {docx_file}")
        else:
            logger.error(f"Summary DOCX file not found after generation: {docx_file}")
        
        return docx_file
    except Exception as e:
        logger.error(f"Error generating summary DOCX: {str(e)}")
        return None

def generate_summary_pdf(zones_data):
    # Summary PDF with charts embedded
    html_file = "cloudflare_audit_reports/summary_audit_report.html"
    pdf_file = "cloudflare_audit_reports/summary_audit_report.pdf"
    logger.info(f"Generating summary HTML and PDF: {html_file}, {pdf_file}")

    try:
        # Prepare summary data
        summary_data = []
        for zone in zones_data:
            zone_name = zone['name']
            findings = zone['findings']
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Compliant': 0}
            ip_access_count = len([f for f in findings if "IP Access Rule - Target:" in f['description']])
            if any("Failed to retrieve IP Access Rules" in f['description'] for f in findings):
                ip_access_count = "Failed"
            elif ip_access_count == 0:
                ip_access_count = "None"
            old_waf_status = "Enabled" if any("Legacy WAF is enabled" in f['description'] for f in findings) else "Disabled"
            if any("Failed to retrieve WAF" in f['description'] for f in findings):
                old_waf_status = "Failed"
            for finding in findings:
                severity_counts[finding['severity']] += 1
            summary_data.append({
                'name': zone_name,
                'critical': severity_counts['Critical'],
                'high': severity_counts['High'],
                'medium': severity_counts['Medium'],
                'low': severity_counts['Low'],
                'info': severity_counts['Info'],
                'compliant': severity_counts['Compliant'],
                'ip_access_rules': ip_access_count,
                'old_waf': old_waf_status
            })

        # Generate charts
        pie_chart_bytes = generate_pie_chart(zones_data)
        bar_chart_bytes = generate_bar_chart(zones_data)
        pie_chart_data = base64.b64encode(pie_chart_bytes).decode('utf-8')
        bar_chart_data = base64.b64encode(bar_chart_bytes).decode('utf-8')

        # Render HTML
        template = env.from_string(template_string)
        rendered_html = template.render(
            title="Summary",
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            zones_data=summary_data,
            pie_chart=f"data:image/png;base64,{pie_chart_data}",
            bar_chart=f"data:image/png;base64,{bar_chart_data}"
        )

        # Save HTML
        with open(html_file, 'w') as f:
            f.write(rendered_html)
        if os.path.exists(html_file):
            logger.info(f"Summary HTML generated successfully: {html_file}")
        else:
            logger.error(f"Summary HTML file not found after generation: {html_file}")

        # Generate PDF
        doc = SimpleDocTemplate(pdf_file, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        title_style = styles['Heading1']
        body_style = styles['BodyText']
        pdf_severity_colors = {
            'Critical': colors.Color(0.8, 0.2, 0.2),
            'High': colors.Color(0.8, 0.4, 0.2),
            'Medium': colors.Color(0.8, 0.8, 0.2),
            'Low': colors.Color(0.2, 0.8, 0.2),
            'Compliant': colors.Color(0.2, 0.4, 0.8),
            'Info': colors.grey
        }

        elements.append(Paragraph("Cloudflare Security Audit Summary Report", title_style))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"Prepared by: Optiv Security", body_style))
        elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
        elements.append(Spacer(1, 24))

        if zones_data:
            data = [['Zone Name', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Compliant', 'IP Access Rules', 'Old WAF']]
            for zone in summary_data:
                data.append([
                    Paragraph(zone['name'], cell_style),
                    Paragraph(str(zone['critical']), cell_style),
                    Paragraph(str(zone['high']), cell_style),
                    Paragraph(str(zone['medium']), cell_style),
                    Paragraph(str(zone['low']), cell_style),
                    Paragraph(str(zone['info']), cell_style),
                    Paragraph(str(zone['compliant']), cell_style),
                    Paragraph(str(zone['ip_access_rules']), cell_style),
                    Paragraph(zone['old_waf'], cell_style)
                ])
            col_widths = [100, 50, 50, 50, 50, 50, 50, 50, 50]
            table = Table(data, colWidths=col_widths, splitByRow=True)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('WORDWRAP', (0, 0), (-1, -1), 'CJK')
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph("No zones processed.", body_style))
        elements.append(Spacer(1, 24))

        elements.append(Paragraph("Severity Distribution", title_style))
        try:
            pie_chart_buffer = io.BytesIO(pie_chart_bytes)
            elements.append(Image(pie_chart_buffer, width=3*inch, height=3*inch))
            logger.debug("Pie chart embedded successfully in PDF")
        except Exception as e:
            logger.error(f"Failed to embed pie chart in PDF: {str(e)}")
            elements.append(Paragraph("Error: Pie chart could not be embedded.", body_style))

        elements.append(Spacer(1, 24))

        elements.append(Paragraph("Critical and High Findings by Zone", title_style))
        try:
            bar_chart_buffer = io.BytesIO(bar_chart_bytes)
            elements.append(Image(bar_chart_buffer, width=4*inch, height=3*inch))
            logger.debug("Bar chart embedded successfully in PDF")
        except Exception as e:
            logger.error(f"Failed to embed bar chart in PDF: {str(e)}")
            elements.append(Paragraph("Error: Bar chart could not be embedded.", body_style))

        elements.append(Spacer(1, 24))

        doc.build(elements)
        if os.path.exists(pdf_file):
            logger.info(f"Summary PDF generated successfully: {pdf_file}")
        else:
            logger.error(f"Summary PDF file not found after generation: {pdf_file}")

        return html_file, pdf_file
    except Exception as e:
        logger.error(f"Error generating summary HTML/PDF: {str(e)}")
        return None, None

def main():
    # Main loop - check env, fetch zones, run checks, generate reports
    if not CLOUDFLARE_API_TOKEN or not CLOUDFLARE_API_EMAIL:
        logger.error("CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_EMAIL not set.")
        return

    os.makedirs("cloudflare_audit_reports", exist_ok=True)
    logger.info("Created output directory: cloudflare_audit_reports")

    logger.debug("Fetching zones")
    response = requests.get(f"{BASE_URL}/zones", headers=headers)
    if response.status_code != 200:
        logger.error(f"Failed to fetch zones: {response.status_code} {response.reason}, Content: {response.text}")
        return

    zones = response.json().get('result', [])
    logger.info(f"Retrieved {len(zones)} zones: {[zone['name'] for zone in zones]}")
    zones_data = []

    for i, zone in enumerate(zones, 1):
        zone_id = zone['id']
        zone_name = zone['name']
        logger.info(f"Processing zone {i} of {len(zones)}: {zone_name} ({zone_id})")

        findings = []
        findings.extend(check_min_tls_version(zone_id, zone_name))
        findings.extend(check_true_client_ip_header(zone_id, zone_name))
        findings.extend(check_bot_management(zone_id, zone_name))
        findings.extend(check_security_level(zone_id, zone_name))
        findings.extend(check_http3(zone_id, zone_name))
        findings.extend(check_dnssec(zone_id, zone_name))
        findings.extend(check_always_use_https(zone_id, zone_name))
        findings.extend(check_waf(zone_id, zone_name))
        findings.extend(check_firewall_rules(zone_id, zone_name))
        findings.extend(check_managed_rules(zone_id, zone_name))
        findings.extend(check_rate_limiting(zone_id, zone_name))
        findings.extend(check_ip_access_rules(zone_id, zone_name))

        dns_records = fetch_all_dns_records(zone_id, zone_name)

        try:
            html_file, pdf_file = generate_zone_pdf(zone_id, zone_name, findings, dns_records)
            docx_file = generate_zone_docx(zone_id, zone_name, findings, dns_records)
            if html_file and pdf_file and docx_file:
                zones_data.append({'name': zone_name, 'findings': findings})
            else:
                logger.error(f"Skipping zone {zone_name} due to report generation failure")
        except Exception as e:
            logger.error(f"Failed to process zone {zone_name} ({zone_id}): {str(e)}")

    try:
        html_file, pdf_file = generate_summary_pdf(zones_data)
        docx_file = generate_summary_docx(zones_data)
        if not (html_file and pdf_file and docx_file):
            logger.error("Summary report generation failed")
    except Exception as e:
        logger.error(f"Failed to generate summary reports: {str(e)}")

if __name__ == "__main__":
    main()