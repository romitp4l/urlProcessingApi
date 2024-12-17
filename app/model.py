import whois
import requests
from urllib.parse import urlparse
import tldextract
import socket
import re
from bs4 import BeautifulSoup
import dns.resolver
import json

def analyze_url(url):
    report = {}

    try:
        # 1. Basic URL Information
        parsed_url = urlparse(url)
        report['url'] = url
        report['scheme'] = parsed_url.scheme
        report['netloc'] = parsed_url.netloc
        report['path'] = parsed_url.path
        report['query'] = parsed_url.query
        report['length'] = len(url)  # Add the length of the URL

        # 2. Domain Information
        extracted = tldextract.extract(url)
        report['subdomain'] = extracted.subdomain
        report['domain'] = extracted.domain
        report['suffix'] = extracted.suffix

        # Whois lookup
        try:
            w = whois.whois(url)
            # Ensure all keys and values are strings
            report['whois'] = {str(k): (v.decode('utf-8') if isinstance(v, bytes) else v) for k, v in w.items()}
        except Exception as e:
            report['whois_error'] = str(e)

        # 3. Other URL Features (Indicators of Phishing)
        try:
            ip_address = socket.gethostbyname(parsed_url.netloc)
            report['ip_address'] = ip_address
        except socket.gaierror:
            report['ip_address'] = "Could not resolve hostname"

        # 4. Content Analysis
        try:
            response = requests.get(url, timeout=5, verify=False)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")

            report['title'] = soup.title.string if soup.title else None
            report['iframes'] = len(soup.find_all('iframe'))
            report['scripts'] = len(soup.find_all('script'))
            report['external_links'] = len([link.get('href') for link in soup.find_all('a') if link.get('href') and not link.get('href').startswith('#') and not parsed_url.netloc in link.get('href')])

            # Content-Based Features
            report['https'] = parsed_url.scheme == "https"
            report['favicon'] = any(link.get('href') for link in soup.find_all('link', rel='icon'))
            report['login_form'] = bool(soup.find('form', {'action': re.compile(r'login|signin', re.IGNORECASE)}))

        except requests.exceptions.RequestException as e:
            report['content_error'] = str(e)
        except Exception as e:
            report['parsing_error'] = str(e)

        # 5. DNS Records
        try:
            resolver = dns.resolver.Resolver()
            a_records = resolver.resolve(parsed_url.netloc, 'A')
            report['dns_a_records'] = [record.address for record in a_records]
            mx_records = resolver.resolve(parsed_url.netloc, 'MX')
            report['dns_mx_records'] = [record.exchange.to_text() for record in mx_records]
            txt_records = resolver.resolve(parsed_url.netloc, 'TXT')
            report['dns_txt_records'] = [record.to_text() for record in txt_records]
        except dns.resolver.NXDOMAIN:
            report['dns_records_error'] = "Domain not found"
        except dns.exception.DNSException as e:
            report['dns_records_error'] = str(e)

        # 6. Phishing Heuristics

        # Add checks for the phishing heuristics
        report['shortened'] = len(url) < 20  # Assuming shortened URLs are < 20 characters
        report['has_@'] = "@" in url  # Check for @ in the URL
        report['double_slash_redirect'] = url.count('//') > 1  # Check for multiple slashes

        phishing_score = 0
        if report['length'] > 75: phishing_score += 1
        if report['shortened']: phishing_score += 2
        if report['has_@']: phishing_score += 2
        if report['double_slash_redirect']: phishing_score += 2
        if not report['https']: phishing_score += 2
        if report['login_form']: phishing_score += 3
        if 'whois_error' in report: phishing_score += 1
        if 'content_error' in report: phishing_score += 1
        if report.get('iframes', 0) > 2: phishing_score += 1
        if report.get('external_links', 0) > 10: phishing_score += 1

        report['phishing_score'] = phishing_score

    except Exception as e:
        report['error'] = str(e)

    return report
