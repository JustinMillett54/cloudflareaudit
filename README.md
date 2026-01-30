# Cloudflare Security Audit Tool v2.0

A comprehensive Cloudflare security audit tool that checks zones against best practice criteria and generates detailed reports in HTML, PDF, DOCX, and CSV formats.

## 🚀 Features

### Core Audit Capabilities
- **Comprehensive Security Checks**: Audits 20+ security settings per zone
- **Deep Managed Rulesets Audit**: Identifies rules that should be enabled by default vs. those disabled
- **Risk Register**: Automatically generates a risk register for disabled security rules
- **SKU/Entitlements Discovery**: Auto-discovers available enterprise features (API Shield, Bot Management, etc.)
- **Logpush/SIEM Check**: Verifies SIEM integration configuration
- **Zone Inventory**: Lists all zones with their status and configuration

### Checks Performed
| Category | Checks |
|----------|--------|
| TLS/SSL | Min TLS version, SSL mode, HTTPS enforcement, Automatic HTTPS Rewrites |
| Security | Security level, Browser Integrity Check, Email Obfuscation |
| WAF | Legacy WAF status, Managed Rulesets (Cloudflare + OWASP), Custom Rules |
| Bot Protection | Bot Management status |
| DNS | DNSSEC status, All DNS records |
| Infrastructure | HTTP/3, Opportunistic Encryption, Origin Certificates |
| Compliance | IP Access Rules, Rate Limiting, Page Rules |
| Monitoring | Logpush/SIEM configuration |
| Caching | Cache level, Browser Cache TTL |

### Report Formats
- **HTML**: Modern, responsive design with executive summary, severity cards, and interactive tables
- **PDF**: Professional layout using ReportLab with embedded charts
- **DOCX**: Word document format via Pandoc conversion
- **CSV**: Data export for client analysis (findings, inventory, DNS records, risk register)

## 📋 Requirements

### Python
- Python 3.8+ (tested on 3.12)

### Dependencies
```bash
pip install requests reportlab pypandoc matplotlib jinja2
```

### System Requirements
- Pandoc (for DOCX generation): https://pandoc.org/installing.html

### Environment Variables
```bash
export CLOUDFLARE_API_TOKEN="your_token_here"
export CLOUDFLARE_API_EMAIL="your@email.com"
```

**Required API Token Permissions:**
- Zone:Read
- Firewall Services:Read
- DNS:Read
- Logs:Read (for Logpush)
- Zone Settings:Read

## 🔧 Usage

### Basic Usage
```bash
python CFAudit.py
```

### Advanced Options
```bash
# Specify output directory
python CFAudit.py --output-dir ./my_reports

# Export to CSV for data analysis
python CFAudit.py --csv

# Audit specific zones only
python CFAudit.py --zones example.com another-zone.com

# Skip DNS record collection (faster)
python CFAudit.py --skip-dns

# Customize report author
python CFAudit.py --prepared-by "Security Consulting Team"

# Full command with all options
python CFAudit.py --output-dir ./audit_2024 --csv --prepared-by "Optiv Security"
```

## 📁 Output Structure

```
cloudflare_audit_reports/
├── example_com_<zoneid>_audit_report.html
├── example_com_<zoneid>_audit_report.pdf
├── example_com_<zoneid>_audit_report.docx
├── summary_audit_report.html
├── summary_audit_report.pdf
├── summary_audit_report.docx
├── findings_<timestamp>.csv
├── zone_inventory_<timestamp>.csv
├── dns_records_<timestamp>.csv
└── risk_register_<timestamp>.csv
```

## 🎨 Report Features

### Executive Summary
- Severity distribution cards (Critical, High, Medium, Low, Info, Compliant)
- Total zones audited
- Visualization charts

### Zone Inventory
- Lists all audited zones with:
  - Zone name and ID
  - Plan type (Free, Pro, Business, Enterprise)
  - SSL status
  - Zone status (active/pending)

### SKU & Entitlements Discovery
- API Shield
- Bot Management
- Advanced Rate Limiting
- Load Balancing
- Spectrum
- Argo Smart Routing
- Image Optimization
- Cache Reserve
- Zaraz

### Managed Rulesets Audit
Deep analysis of WAF managed rulesets:
- Cloudflare Managed Ruleset
- Cloudflare OWASP Core Ruleset
- Exposed Credentials Check

Identifies:
- Rulesets that should be enabled by default
- Individual rules that have been disabled
- Rule overrides and modifications

### Risk Register
Automatically tracks:
- Disabled security rules
- Missing mandatory configurations
- Client justification status
- Remediation recommendations

### Logpush/SIEM Integration
Checks for:
- Configured Logpush jobs
- Active vs. disabled jobs
- Destination configurations

## 🔒 Security Considerations

- API credentials are read from environment variables (never hardcode!)
- All data remains local - no external data transmission
- Reports marked as "Confidential - For Internal Use Only"
- Detailed logging to `cloudflare_audit.log` for troubleshooting

## 📊 Severity Levels

| Severity | Description |
|----------|-------------|
| 🔴 Critical | Immediate security risk requiring urgent attention |
| 🟠 High | Significant security weakness |
| 🟡 Medium | Moderate risk that should be addressed |
| 🟢 Low | Minor improvement opportunity |
| ⚪ Info | Informational finding |
| 🔵 Compliant | Setting meets best practices |

## 🛠️ Customization

### Adding New Checks
1. Create a new function following the pattern:
```python
def check_feature(zone_id, zone_name):
    findings = []
    # API call and logic
    return findings
```

2. Add the call in `main()`:
```python
findings.extend(check_feature(zone_id, zone_name))
```

### Modifying Managed Ruleset IDs
Update `CLOUDFLARE_MANAGED_RULESETS` dictionary with new ruleset IDs.

### Changing Best Practice Thresholds
Modify `BEST_PRACTICE_SETTINGS` dictionary values.

## 🐛 Troubleshooting

### Common Issues

**"CLOUDFLARE_API_TOKEN not set"**
```bash
export CLOUDFLARE_API_TOKEN="your_token"
export CLOUDFLARE_API_EMAIL="your@email.com"
```

**"Failed to fetch zones: 403"**
- Check API token has Zone:Read permission
- Verify token is not expired

**"DOCX generation failed"**
- Install Pandoc: `apt install pandoc` or download from pandoc.org

**"No zones found"**
- Verify API token has access to the account's zones
- Check zone names/IDs if using `--zones` filter

### Debug Mode
Check `cloudflare_audit.log` for detailed API call logs.

## 📜 License

MIT License - See LICENSE file

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and test
4. Submit a pull request

## 📝 Changelog

### v2.0.0
- Added modern responsive HTML template
- Added CSV export functionality
- Added SKU/entitlements discovery
- Added deep managed rulesets audit
- Added risk register
- Added Logpush/SIEM checking
- Added zone inventory
- Added executive summary
- Added 10+ new security checks
- Added command-line arguments
- Improved PDF layout
- Better error handling

### v1.0.0
- Initial release with basic security checks
- HTML, PDF, DOCX reports

