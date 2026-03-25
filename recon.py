#########################################################
# This code was made for educational/study purposes and #
# not to cause any harm by any means                    #
#                                                       #
# Automated target recon                                #
#                                                       #
# BitSec Nov 2, 2025                                    #
#########################################################
#!/usr/bin/env python3
from nis import cat

from passive import get_whois, get_passive_dns, get_subdomains, get_infrastructure, get_archived_docs, build_risk_assessment
from pdfgenerator import generate_report
import user
import sys

# passive_recon initialize and collect info from every passive tools for reporting later
def passive_recon(target):
    return get_whois(target)

def userdata():
    user_data = user
    user_data.name = sys.argv[2]
    user_data.api_key = sys.argv[3]
    return user_data

def main():
    usr = userdata()

    target = passive_recon(sys.argv[1])
    target = get_passive_dns(target, usr.api_key)
    target = get_subdomains(target)
    target = get_infrastructure(target)
    target = get_archived_docs(target)
    target = build_risk_assessment(target)
    generate_report(target, sys.argv[3])


if __name__ == "__main__":
    main()
