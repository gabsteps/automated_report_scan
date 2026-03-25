from pathlib import Path
from string import Template
from datetime import datetime

MAX_ROWS = 10

def format_date(date_value):
    if not date_value:
        return "N/A"

    if isinstance(date_value, list):
        date_value = date_value[0]
    elif isinstance(date_value, str):
        try:
            date_value = datetime.fromisoformat(date_value.replace("Z", ""))
        except:
            return date_value
    elif isinstance(date_value, int):
        return datetime.utcfromtimestamp(int(date_value)).strftime("%Y-%m-%d")
    elif isinstance(date_value, datetime):
        return date_value.strftime("%Y-%m-%d")


    return date_value.strftime("%Y-%m-%d")

def format_nameservers(ns_value):
    if not ns_value:
        return "N/A"

    if isinstance(ns_value, list):
        return ", ".join(ns_value)

    return str(ns_value)

def format_dns_table(results):
    if not results:
        return "<tr><td colspan='3'>No data found</td></tr>"

    rows = ""

    for rtype, value,first, last, source in results:
        rows += f"""
        <tr>
            <td>{rtype}</td>
            <td>{value}</td>
            <td>{format_date(first)}</td>
            <td>{format_date(last)}</td>
            <td>{source}</td>
        </tr>
        """

    return rows

def format_subdomains_table(subdomains):
    if not subdomains:
        return "<tr><td colspan='4'>No data found</td></tr>"

    rows = ""

    for sub, first, last, source, status in subdomains:
        status_class = "status-active" if status == "Active" else "status-inactive"
        rows += f"""
        <tr>
            <td>{sub}</td>
            <td>{format_date(first)}</td>
            <td>{format_date(last)}</td>
            <td>{source}</td>
            <td class="{status_class}">{status}</td>
        </tr>
        """

    return rows

def format_certificates_table(certs):
    if not certs:
        return "<tr><td colspan='4'>No data found</td></tr>"

    rows = ""

    for domain, issuer, first, last, is_wildcard in certs:
        # wildcard visual
        display_domain = f"<span class='wildcard'>{domain}</span>" if is_wildcard else domain

        rows += f"""
        <tr>
            <td>{display_domain}</td>
            <td>{issuer}</td>
            <td>{format_date(first)}</td>
            <td>{format_date(last)}</td>
        </tr>
        """

    return rows

def format_infrastructure_table(data):
    if not data:
        return "<tr><td colspan='4'>No data found</td></tr>"

    rows = ""

    for ip, asn, org, country, status in data:
        status_class = "status-active" if status == "Active" else "status-inactive"
        rows += f"""
        <tr>
            <td>{ip}</td>
            <td>{asn}</td>
            <td>{org}</td>
            <td>{country}</td>
            <td class="{status_class}">{status}</td>
        </tr>
        """

    return rows

def format_metadata_table(data):
    if not data:
        return "<tr><td colspan='2'>No findings</td></tr>"

    rows = ""

    for url, ftype, info in data:
        rows += f"""
        <tr>
            <td>{url}</td>
            <td>{ftype}</td>
            <td>{info}</td>
        </tr>
        """

    return rows


def format_metadata_summary(target):
    total = len(target.metadata)
    summary = target.metadata_summary

    breakdown = " | ".join([f"{k}: {v}" for k, v in summary.items()])

    return f"""
    <p><strong>Total Documents Found:</strong> {total}</p>
    <p><strong>Breakdown:</strong> {breakdown}</p>
    """

def format_metadata_preview(data):
    preview = data[:MAX_ROWS]

    rows = ""

    for url, ftype, info in preview:
        rows += f"""
        <tr>
            <td><a href="{url}">{url}</a></td>
            <td>{ftype}</td>
            <td>{info}</td>
        </tr>
        """

    if len(data) > MAX_ROWS:
        rows += f"""
        <tr>
            <td colspan="3"><em>Showing {MAX_ROWS} of {len(data)} results</em></td>
        </tr>
        """

    return rows

def format_metadata_full(data):
    rows = ""

    for url, ftype, info in data:
        rows += f"""
        <tr>
            <td><a href="{url}">{url}</a></td>
            <td>{ftype}</td>
            <td>{info}</td>
        </tr>
        """

    return rows

def format_risk_table(risks):
    rows = ""

    for category, level, notes in risks:
        rows += f"""
        <tr>
            <td>{category}</td>
            <td class="risk-{level.lower()}">{level}</td>
            <td>{notes}</td>
        </tr>
        """

    return rows

def get_passive_template():
    path = Path(__file__).parent / "template/report_template_passive_css.html"
    return path.read_text(encoding="utf8")

def generate_report(target, user):
    print("Generating report...")
    template = Template(get_passive_template())
    output = Path("report.html")

    report = (template.substitute(
                    name = user,
                    date = format_date(datetime.now()),
                    target = target.domain,

        # WHO IS INFO
                    domain_name = target.domain,
                    registrar = target.registrar,
                    generation_date = format_date(target.creation_date),
                    expiration_date = format_date(target.expiration_date),
                    org = target.registrant_organization,
                    country = target.country,
                    name_servers = format_nameservers(target.name_servers),

        # DNS TABLE
                    dns_records = format_dns_table(target.dns_info),

        # SUBDOMAIN RECORDS

                    subdomains = format_subdomains_table(target.subdomains),
        # CERT TRANSPARENCY
                    certificates = format_certificates_table(target.certificates),
        # IP's AND INFRASTRUCTURE
                    ip_infra = format_infrastructure_table(target.infrastructure),
        # PUBLIC DOCS FINDINGS
                    metadata_summary=format_metadata_summary(target),
                    metadata_preview=format_metadata_preview(target.metadata),
                    metadata_full=format_metadata_full(target.metadata),
        # RISK TABLE
                    overall_risk=target.overall_risk.lower(),
                    risk_table = format_risk_table(target.risk_assessment)))





    output.write_text(report, encoding="utf8")
    print("Report generated :)")

