import requests
import os
from .models.vulnerability import Vulnerability
from . import db

USERNAME = 'mopox06'
PASSWORD = os.getenv('PASSWORD')

def enrich_cve_in_db(cve_id):
    url = f'https://app.opencve.io/api/cve/{cve_id}'
    response = requests.get(url, auth=(USERNAME, PASSWORD))
    if response.status_code != 200:
        return

    data = response.json()
    cvss_data = data.get('metrics', {}).get('cvssV3_1', {}).get('data', {})
    cwes = ', '.join(data.get('weaknesses', []))
    vendors = ', '.join(data.get('vendors', []))
    exploited = bool(data.get('exploited'))

    vuln = Vulnerability.query.filter_by(cve_id=cve_id).first()
    if vuln:
        vuln.cvss_v3_score = cvss_data.get('score', '')
        vuln.cvss_v3_vector = cvss_data.get('vector', '')
        vuln.cwes = cwes
        vuln.vendors = vendors
        vuln.exploited = exploited
        db.session.commit()

def enrich_all_cves():
    cves = Vulnerability.query.all()
    for vuln in cves:
        enrich_cve_in_db(vuln.cve_id)
