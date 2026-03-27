# Passive Recon Tool - OSINT Domain Analysis

A **passive reconnaissance (OSINT)** tool designed to collect and analyze publicly available information about a target domain, generating a structured security report.

> [!NOTE]
> This project was developed for educational purposes in cybersecurity.

---

## Features

This tool performs:

* WHOIS lookup
* Passive DNS collection (VirusTotal API)
* Subdomain enumeration (crt.sh)
* Certificate transparency analysis
* Infrastructure mapping (IP, ASN, geolocation)
* Public document discovery (Wayback Machine)
* Metadata exposure analysis
* Automated risk assessment
* HTML report generation

---

## Technologies Used

* Python 3.x
* Requests
* python-whois
* Multithreading (ThreadPoolExecutor)
* Public OSINT APIs (VirusTotal, crt.sh, ipinfo)

---

## Installation

### 1. Clone the repository

```bash id="fgh9de"
git clone https://github.com/gabsteps/automated_report_scan
cd automated_report_scan
```

---


### 2. Install dependencies

```bash id="a8vn3t"
pip install -r requirements.txt
```
### Or Windows
```bash id="a8vn3t"
python -m pip install -r requirements.txt
```

---

## Configuration

You will need a **VirusTotal API Key**:

1. Create an account: https://www.virustotal.com/
2. Generate your API key

---

## Usage

### Basic command

```bash id="y82kfd"
python3 recon.py <domain> <"username"> <"api_key">
```

### Example

```bash id="w3x9lm"
python3 recon.py example.com "Gabriel" "YOUR_API_KEY"
```

---

## Project Structure

```id="l8sd3q"
.
├── recon.py             # Main execution script
├── passive.py           # OSINT data collection
├── data_filter.py       # WHOIS data processing
├── domain.py            # Domain data model
├── pdfgenerator.py      # Report generation
├── requirements.txt
└── template/
    └── report_template_passive_css.html
```

---

## Output

After execution, the tool generates:

```id="n3v7re"
report.html
```

The report includes:

* WHOIS information
* Passive DNS data
* Active/inactive subdomains
* Certificates
* Infrastructure details
* Public document findings
* Risk assessment summary

---

## Risk Assessment

The tool classifies risks into:

* 🟢 Low
* 🟡 Medium
* 🔴 High

Based on:

* Domain expiration proximity
* Suspicious subdomain naming
* Volume of exposed documents
* Infrastructure attack surface

---

## Limitations

* Relies on third-party APIs (rate limits may apply)
* WHOIS data may be incomplete or obfuscated
* Subdomain discovery depends on public certificates
* No active scanning (passive OSINT only)
* Public documents findings may be inconsistent

---

## Legal Disclaimer

This tool is intended **for educational purposes and authorized testing only**.

Any misuse for illegal activities is strictly the responsibility of the user.

---

## Possible Future Improvements

* Integration with additional OSINT sources
* PDF export support
* Web interface
* Vulnerability detection modules
* Result caching
* Choose between passive/active/mixed report

---

## Author

Gabriel Passos
Cybersecurity Student

---

## Contributing

Pull requests are welcome!
Feel free to open issues or suggest improvements.
