import domain

# define_domain has the objective of fulfill domain class attributes with collected public data
def define_domain(raw_whois):
    domain_target = domain.Domain() #initialize domain class as domain_target

    # fullfill domain_target class attributes
    domain_target.domain = raw_whois.get('domain_name')
    domain_target.registrar = raw_whois.get('registrar')
    domain_target.registrar_url = raw_whois.get('registrar_url')
    #domain_target.registrant_name = raw_whois.get('')
    domain_target.registrant_organization = raw_whois.get('org')
    #domain_target.registrant_email = raw_whois.get('')
    #domain_target.registrant_phone = raw_whois.get('')
    domain_target.admin_name = raw_whois.get('admin_name')
    #domain_target.admin_email = raw_whois.get('')
    #domain_target.admin_phone = raw_whois.get('')
    domain_target.tech_name = raw_whois.get('tech_name')
    #domain_target.tech_email = raw_whois.get('')
    #domain_target.tech_phone = raw_whois.get('')
    domain_target.creation_date = raw_whois.get('creation_date')
    domain_target.updated_date = raw_whois.get('updated_date')
    domain_target.expiration_date = raw_whois.get('expiration_date')
    #domain_target.status = raw_whois.get('')
    domain_target.name_servers = raw_whois.get('name_servers')
    domain_target.dnssec = raw_whois.get('dnssec')
    domain_target.raw_whois = raw_whois
    domain_target.raw_split = raw_whois # necessário verificar
    domain_target.whois_server = raw_whois.get('whois_server')
    domain_target.emails_found = raw_whois.get('emails')
    #domain_target.contacts_count = raw_whois.get('')
    #domain_target.domain_id = raw_whois.get('')
    domain_target.address = raw_whois.get('address')
    domain_target.city = raw_whois.get('city')
    domain_target.state = raw_whois.get('state')
    domain_target.country = raw_whois.get('country')

    return  domain_target