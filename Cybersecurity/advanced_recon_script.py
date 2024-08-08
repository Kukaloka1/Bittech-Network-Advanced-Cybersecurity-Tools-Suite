import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
import socket
import dns.resolver
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_identity():
    print("Verifying your identity from multiple sources...")
    try:
        # Verify IP and country from ipapi.co
        ip_response = requests.get('https://ipapi.co/json/')
        ip_data = ip_response.json()
        ip1 = ip_data.get('ip', 'Unknown')
        country1 = ip_data.get('country_name', 'Unknown')
        
        # Verify IP from ipify.org
        ip2 = requests.get('https://api.ipify.org').text
        
        # Verify IP from ident.me
        ip3 = requests.get('https://ident.me').text

        # Get User Agent
        ua_response = requests.get('https://httpbin.org/user-agent')
        user_agent = ua_response.json().get('user-agent', 'Unknown')

        print(f"\nYour current information:")
        print(f"IP (source 1): {ip1}")
        print(f"IP (source 2): {ip2}")
        print(f"IP (source 3): {ip3}")
        print(f"Country (according to source 1): {country1}")
        print(f"User Agent: {user_agent}")

        if ip1 != ip2 or ip1 != ip3 or ip2 != ip3:
            print("\nWARNING! Discrepancies detected in the reported IPs.")
            print("This could indicate a problem with your VPN or an information leak.")

        confirmation = input("\nDo you want to continue with the reconnaissance? (y/n): ").lower()
        return confirmation == 'y'
    except Exception as e:
        print(f"Error verifying identity: {str(e)}")
        return False

class AdvancedRecon:
    def __init__(self, domain):
        self.domain = domain
        self.results = {
            "emails": set(),
            "hosts": set(),
            "ip_addresses": set(),
            "social_media": set(),
            "subdomains": set()
        }

    def clean_and_validate_url(self, url):
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean_url += f"?{parsed.query}"
        return clean_url

    def check_dns(self):
        try:
            ip = socket.gethostbyname(self.domain)
            print(f"DNS resolution successful. IP: {ip}")
            self.results["ip_addresses"].add(ip)
            return True
        except socket.gaierror:
            print(f"Error: Could not resolve the domain name {self.domain}")
            return False

    def get_dns_records(self):
        records = {}
        try:
            for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(self.domain, qtype)
                    records[qtype] = [str(rdata) for rdata in answers]
                    if qtype in ['A', 'AAAA']:
                        self.results["ip_addresses"].update(records[qtype])
                except dns.resolver.NoAnswer:
                    pass
        except dns.resolver.NXDOMAIN:
            print(f"Error: The domain {self.domain} does not exist.")
        except Exception as e:
            print(f"Error getting DNS records: {str(e)}")
        return records

    def search_google(self):
        url = f"https://www.google.com/search?q=site:{self.domain}"
        try:
            response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('cite')
            for link in links:
                self.results["subdomains"].add(urlparse(link.text).netloc)
        except Exception as e:
            print(f"Error in Google search: {str(e)}")

    def search_linkedin(self):
        url = f"https://www.linkedin.com/company/{self.domain}"
        try:
            response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200:
                self.results["social_media"].add(f"LinkedIn: {url}")
        except Exception as e:
            print(f"Error in LinkedIn search: {str(e)}")

    def search_github(self):
        url = f"https://api.github.com/search/code?q={self.domain}"
        try:
            response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
            data = response.json()
            if 'items' in data:
                for item in data['items']:
                    if 'repository' in item and 'html_url' in item['repository']:
                        self.results["social_media"].add(f"GitHub: {item['repository']['html_url']}")
        except Exception as e:
            print(f"Error in GitHub search: {str(e)}")

    def extract_emails_from_url(self, url):
        try:
            response = requests.get(url, timeout=5)
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', response.text)
            self.results["emails"].update(emails)
        except Exception as e:
            print(f"Error extracting emails from {url}: {str(e)}")

    def run(self):
        print(f"Starting advanced reconnaissance for {self.domain}...")
        
        if not self.check_dns():
            return

        dns_records = self.get_dns_records()
        print("\nDNS records found:")
        for record_type, records in dns_records.items():
            print(f"{record_type}: {', '.join(records)}")

        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.submit(self.search_google)
            executor.submit(self.search_linkedin)
            executor.submit(self.search_github)
            
            urls_to_check = [f"http://{self.domain}", f"https://{self.domain}"] + list(self.results["subdomains"])
            futures = [executor.submit(self.extract_emails_from_url, url) for url in urls_to_check]
            for future in as_completed(futures):
                future.result()

        self.print_results()

    def print_results(self):
        print("\nAdvanced reconnaissance results:")
        print("---------------------------------------")
        for key, values in self.results.items():
            if values:
                print(f"\n{key.capitalize()}:")
                for value in values:
                    print(f"- {value}")
            else:
                print(f"\nNo {key} found")

def main():
    if check_identity():
        domain = input("\nEnter the target domain: ")
        recon = AdvancedRecon(domain)
        recon.run()
    else:
        print("Reconnaissance canceled. Check your network configuration and try again.")

if __name__ == "__main__":
    main()
