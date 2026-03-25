"""
Campos relevantes para extrair do WHOIS
domain (nome do domínio)
registrar (nome do registrador)
registrant_name (nome do proprietário/registrante, se disponível)
registrant_organization (organização do registrante)
registrant_email (e-mail do registrante)
registrant_phone (telefone do registrante)
admin_name (contato administrativo)
admin_email
admin_phone
tech_name (contato técnico)
tech_email
tech_phone
creation_date (data de criação do domínio)
updated_date (data de última atualização)
expiration_date (data de expiração)
status (status do domínio — ex.: clientTransferProhibited, ok)
name_servers (lista de nameservers)
dnssec (habilitado/disabled/valor)
raw_whois (texto bruto completo — salvar para referência)
whois_server (servidor WHOIS consultado)
emails_found (lista agregada de todos os e-mails encontrados no raw)
contacts_count (quantidade de contatos distintos encontrados)
registrar_url (URL do registrador, quando disponível)
registrar_abuse_contact (contacto para abuso, se presente)
domain_id (identificador do domínio no WHOIS, se existir)
"""

class Domain:
    def __init__(self,
                 domain = None,
                 registrar = None,
                 registrar_url = None,
                 registrant_name = None,
                 registrant_organization = None,
                 registrant_email = None,
                 registrant_phone = None,
                 admin_name = None,
                 admin_email = None,
                 admin_phone = None,
                 tech_name = None,
                 tech_email = None,
                 tech_phone = None,
                 creation_date = None,
                 updated_date = None,
                 expiration_date = None,
                 status = None,
                 name_servers = None,
                 dnssec = None,
                 raw_whois = None,
                 raw_split = None,
                 whois_server = None,
                 emails_found = None,
                 contacts_count = None,
                 domain_id = None,
                 address = None,
                 city = None,
                 state = None,
                 country = None,
                 dns_info = None,
                 subdomains = None,
                 certificates = None,
                 infrastructure_ips = None,
                 urls = None,
                 metadata = None,
                 risk_assessment = None,
                 overall_risk = None
                 ):
                self.domain = domain
                self.registrar = registrar
                self.registrar_url = registrar_url
                self.registrant_name = registrant_name
                self.registrant_organization = registrant_organization
                self.registrant_email = registrant_email
                self.registrant_phone = registrant_phone
                self.admin_name = admin_name
                self.admin_email = admin_email
                self.admin_phone = admin_phone
                self.tech_name = tech_name
                self.tech_email = tech_email
                self.tech_phone = tech_phone
                self.creation_date = creation_date
                self.updated_date = updated_date
                self.expiration_date = expiration_date
                self.status = status
                self.name_servers = name_servers
                self.dnssec = dnssec
                self.raw_whois = raw_whois
                self.raw_split = raw_split
                self.whois_server = whois_server
                self.emails_found = emails_found
                self.contacts_count = contacts_count
                self.domain_id = domain_id
                self.address = address
                self.city = city
                self.state = state
                self.country = country
                self.dns_info = dns_info
                self.subdomains = subdomains
                self.certificates = certificates
                self.infrastructure_ips = infrastructure_ips
                self.urls = urls
                self.metadata = metadata
                self.risk_assessment = risk_assessment
                self.overall_risk = overall_risk
"""
{'domain_name': 'EXAMPLE.COM',
'registrar': 'RESERVED-Internet Assigned Numbers Authority',
'registrar_url': 'http://res-dom.iana.org',
'reseller': None,
'whois_server': 'whois.iana.org',
'referral_url': None,
'updated_date': datetime.datetime(2026, 1, 16, 18, 26, 50, tzinfo=tzoffset('UTC', 0)),
'creation_date': datetime.datetime(1995, 8, 14, 4, 0, tzinfo=tzoffset('UTC', 0)),
'expiration_date': datetime.datetime(2026, 8, 13, 4, 0, tzinfo=tzoffset('UTC', 0)),
'name_servers': ['ELLIOTT.NS.CLOUDFLARE.COM', 'HERA.NS.CLOUDFLARE.COM'],
'status': ['clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited', 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 'clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited'],
'emails': None,
'dnssec': 'signedDelegation',
'name': None,
'org': None,
'address': None,
'city': None,
'state': None,
'registrant_postal_code': None,
'country': None,
'tech_name': None,
'tech_org': None,
'admin_name': None,
'admin_org': None}
-----------------
x{'domain_name': 'GOOGLE.COM', 
x'registrar': 'MarkMonitor, Inc.', 
x'registrar_url': 'http://www.markmonitor.com', 
'reseller': None, 
x'whois_server': 'whois.markmonitor.com', 
'referral_url': None, 
x'updated_date': [datetime.datetime(2019, 9, 9, 15, 39, 4, tzinfo=tzoffset('UTC', 0)), datetime.datetime(2024, 8, 2, 2, 17, 33, tzinfo=tzoffset('UTC', 0))], 
x'creation_date': [datetime.datetime(1997, 9, 15, 4, 0, tzinfo=tzoffset('UTC', 0)), datetime.datetime(1997, 9, 15, 7, 0, tzinfo=tzoffset('UTC', 0))], 
x'expiration_date': [datetime.datetime(2028, 9, 14, 4, 0, tzinfo=tzoffset('UTC', 0)), datetime.datetime(2028, 9, 13, 7, 0, tzinfo=tzoffset('UTC', 0))], 
x'name_servers': ['NS1.GOOGLE.COM', 'NS2.GOOGLE.COM', 'NS3.GOOGLE.COM', 'NS4.GOOGLE.COM'], 
'status': ['clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited', 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 'clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited', 'serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited', 'serverTransferProhibited https://icann.org/epp#serverTransferProhibited', 'serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited', 'clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)', 'clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)', 'clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)', 'serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)', 'serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)', 'serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)'], 
x'emails': ['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com'], 
x'dnssec': 'unsigned', 
'name': None, 
x'org': 'Google LLC', 
x'address': None, 
x'city': None, 
x'state': None, 
'registrant_postal_code': None, 
x'country': 'US', 
x'tech_name': None, 
'tech_org': None, 
x'admin_name': None, 
'admin_org': None}
"""

