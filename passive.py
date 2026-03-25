import whois
import data_filter
import requests
import socket
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from datetime import datetime, timezone

# COLLETS EVERY OSINT DATA, PROCESS IT AND UPDATES TARGET PROPERTIES TO BE USED LATER ON GENERATOR

# gather_whois just does a simple search on the provided domain
def get_whois(link):
    print("Getting whois data...")
    raw_whois = whois.whois(link)
    whois_data = data_filter.define_domain(raw_whois)
    whois_data.domain = whois_data.domain.lower()
    return  whois_data


# search for dns records using virus total api key and sets ip for infrastructure table
def get_passive_dns(target, api_key):
    print("Searching for passive DNS data...")

    url = f"https://www.virustotal.com/api/v3/domains/{target.domain}/resolutions"

    headers = {
        "x-apikey": api_key
    }

    try:
        r = requests.get(url, headers=headers, timeout=10)
    except:
        target.dns_info = []
        return target

    if r.status_code != 200:
        target.dns_info = []
        return target

    data = r.json()

    records = {}
    infrastructure_ips = set()

    for item in data.get("data", []):
        ip = item["attributes"].get("ip_address", "N/A")
        last_seen = item["attributes"].get("date", "N/A")

        if not ip:
            continue

        record_type = "AAAA" if ":" in ip else "A"

        # DNS (deduplicado + timeline)
        key = (record_type, ip)

        if key not in records:
            records[key] = [last_seen, last_seen]
        else:
            records[key][0] = min(records[key][0], last_seen)
            records[key][1] = max(records[key][1], last_seen)

        # Infra
        infrastructure_ips.add(ip)

    # montar lista final DNS
    results = []
    for (rtype, ip), (first, last) in records.items():
        results.append((rtype, ip, first, last, "VirusTotal"))

    target.dns_info = sorted(results)
    target.infrastructure_ips = list(infrastructure_ips)

    return target

# search for subdomains using crt.sh
def get_subdomains(target):
    print("Gathering subdomains & certificate data...")

    url = f"https://crt.sh/?q=%.{target.domain}&output=json"

    try:
        r = requests.get(url, timeout=20)
    except:
        target.subdomains = []
        target.certificates = []
        return target

    if r.status_code != 200:
        target.subdomains = []
        target.certificates = []
        return target

    data = r.json()

    # SUBDOMAINS
    subs = {}

    # CERTIFICATES (DEDUP)
    certs = {}

    for entry in data:
        names = entry.get("name_value", "").split("\n")
        issuer_raw = entry.get("issuer_name", "Unknown")
        first_seen = entry.get("not_before", "N/A")
        last_seen = entry.get("not_after", "N/A")

        issuer = "Unknown"

        parts = issuer_raw.split(",")

        for p in parts:
            p = p.strip()
            if p.startswith("CN="):
                issuer = p.replace("CN=", "").strip()
                break

        for name in names:
            name = name.strip().lower()

            if not name.endswith(target.domain):
                continue

            is_wildcard = "*" in name

            # CERTIFICATES
            key = (name, issuer)

            if key not in certs:
                certs[key] = [first_seen, last_seen, is_wildcard]
            else:
                certs[key][0] = min(certs[key][0], first_seen)
                certs[key][1] = max(certs[key][1], last_seen)

            # SUBDOMAINS
            if is_wildcard:
                continue

            if name == target.domain:
                continue

            if name not in subs:
                subs[name] = [first_seen, last_seen]
            else:
                subs[name][0] = min(subs[name][0], first_seen)
                subs[name][1] = max(subs[name][1], last_seen)

    # certificates final list
    cert_results = []
    for (domain, issuer), (first, last, wildcard) in certs.items():
        cert_results.append((domain, issuer, first, last, wildcard))

    # subdomains final list
    sub_results = []
    for sub, (first, last) in subs.items():
        sub_results.append((sub, first, last, "crt.sh"))

    # saves on target obj
    target.subdomains = sorted(sub_results)
    target.certificates = sorted(cert_results)

    # check if subdomain is responding
    target = check_subdomain_status(target)

    return target

# check if subdomains are active or not
def check_subdomain_status(target):
    #using threads to resolve subdomains to reduce report generation time
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(resolve_subdomain, target.subdomains))

    target.subdomains = results
    return target

# resolve one subdomain unity, optimized by threads
def resolve_subdomain(sub_tuple):
    sub, first, last, source = sub_tuple

    try:
        socket.gethostbyname(sub)
        status = "Active"
    except:
        status = "Inactive"

    return (sub, first, last, source, status)

#check if ip is reponding
def check_ip_status(ip_tuple):
    ip, asn, org, country = ip_tuple

    try:
        socket.gethostbyaddr(ip)
        status = "Active"
    except:
        status = "Inactive"

    return (ip, asn, org, country, status)

#important to reveal hidden subdomains
def get_certificate_transparency(target):
    url = f"https://crt.sh/?q=%.{target.domain}&output=json"

    try:
        r = requests.get(url, timeout=10)
    except:
        target.certificates = []
        return target

    if r.status_code != 200:
        target.certificates = []
        return target

    data = r.json()

    certs = []

    for entry in data:
        domains = entry.get("name_value", "").split("\n")
        issuer = entry.get("issuer_name", "Unknown")
        first_seen = entry.get("not_before", "N/A")
        last_seen = entry.get("not_after", "N/A")

        for d in domains:
            d = d.strip().lower()

            if target.domain not in d:
                continue

            certs.append((d, issuer, first_seen, last_seen))

    target.certificates = certs
    return target

def get_infrastructure(target):
    print("Enriching infrastructure data...")

    ips = getattr(target, "infrastructure_ips", [])

    if not ips:
        target.infrastructure = []
        return target

    # threading requests
    with ThreadPoolExecutor(max_workers=10) as executor:
        enriched = list(executor.map(get_ip_info, ips))
        results = list(executor.map(check_ip_status, enriched))

    target.infrastructure = results
    return target

def get_ip_info(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        data = r.json()

        org_raw = data.get("org", "Unknown")
        country = data.get("country", "Unknown")

        # asn and org
        if org_raw.startswith("AS"):
            parts = org_raw.split(" ", 1)
            asn = parts[0]
            org = parts[1] if len(parts) > 1 else "Unknown"
        else:
            asn = "Unknown"
            org = org_raw

        return (ip, asn, org, country)

    except:
        return (ip, "N/A", "N/A", "N/A")


def get_archived_docs(target):
    print("Enriching archived documents...")
    base_url = f"https://web.archive.org/cdx/search/cdx?url=*.{target.domain}/*&output=json&fl=original&collapse=urlkey"

    extensions = ["pdf", "doc", "docx"]

    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(lambda ext: fetch_ext(ext, base_url), extensions))

    urls = [u for sublist in results for u in sublist]

    target.urls = list(set(urls))
    build_metadata(target)
    return target


def fetch_ext(ext, base_url):
    url = f"{base_url}&filter=original:.*\\.{ext}$"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return []

        data = r.json()
        return [entry[0] for entry in data[1:]]

    except:
        return []


def build_metadata(target):
    print("Analyzing metadata exposure...")

    metadata = []
    types = []

    for url in getattr(target, "urls", []):

        if url.lower().endswith(".pdf"):
            ftype = "PDF"
            info = "May contain author/user metadata"

        elif url.lower().endswith(".docx"):
            ftype = "DOCX"
            info = "May expose software versions or usernames"

        elif url.lower().endswith(".doc"):
            ftype = "DOC"
            info = "Legacy format may expose metadata"

        else:
            continue

        metadata.append((url, ftype, info))
        types.append(ftype)

    target.metadata = metadata
    target.metadata_summary = Counter(types)

    return target

# RISK ASSESSMENT
def assess_domain(target):
    notes = []
    risk = "Low"

    if not target.expiration_date:
        return ("Domain Management", "Unknown", "Missing expiration data")

    now = datetime.now(target.expiration_date.tzinfo) if target.expiration_date.tzinfo else datetime.now()
    days_left = (target.expiration_date - now).days

    if days_left < 30:
        risk = "High"
        notes.append("Domain close to expiration")

    elif days_left < 90:
        risk = "Medium"
        notes.append("Expiration approaching")

    if not target.registrant_organization:
        notes.append("No organization info in WHOIS")

    return ("Domain Management", risk, ", ".join(notes))

def assess_subdomains(target):
    risky_keywords = ["dev", "test", "staging", "admin", "internal"]
    found = []

    for sub, *_ in target.subdomains:
        for keyword in risky_keywords:
            if keyword in sub:
                found.append(sub)
                break

    if len(found) > 5:
        return ("Subdomain Naming", "High", "Multiple sensitive subdomains detected")

    elif found:
        return ("Subdomain Naming", "Medium", f"Suspicious subdomains: {len(found)}")

    else:
        return ("Subdomain Naming", "Low", "No risky naming patterns")

def assess_metadata(target):
    total = len(target.metadata)

    if total > 1000:
        return ("Metadata Exposure", "High", "Large number of public documents")

    elif total > 100:
        return ("Metadata Exposure", "Medium", "Moderate document exposure")

    elif total > 0:
        return ("Metadata Exposure", "Low", "Few public documents found")

    else:
        return ("Metadata Exposure", "Low", "No documents found")

def assess_infrastructure(target):
    total = len(target.infrastructure)

    if total > 20:
        return ("Infrastructure Exposure", "Medium", "Large attack surface")

    elif total > 0:
        return ("Infrastructure Exposure", "Low", "Limited exposure")

    else:
        return ("Infrastructure Exposure", "Low", "No infrastructure identified")


def calculate_overall_risk(assessments):
    score_map = {"Low": 1, "Medium": 2, "High": 3}

    total = sum(score_map.get(risk, 0) for _, risk, _ in assessments)
    avg = total / len(assessments)

    if avg >= 2.5:
        return "High"
    elif avg >= 1.5:
        return "Medium"
    else:
        return "Low"

def build_risk_assessment(target):
    results = []

    results.append(assess_domain(target))
    results.append(assess_subdomains(target))
    results.append(assess_metadata(target))
    results.append(assess_infrastructure(target))

    target.risk_assessment = results
    target.overall_risk = calculate_overall_risk(results)

    return target