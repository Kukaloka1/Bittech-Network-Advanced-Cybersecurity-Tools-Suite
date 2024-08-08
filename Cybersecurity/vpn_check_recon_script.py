import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin
import socket
import dns.resolver

def check_vpn():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        ip = response.json()['ip']
        print(f"Tu dirección IP actual es: {ip}")
        
        vpn_confirmation = input("¿Estás usando una VPN? (s/n): ").lower()
        if vpn_confirmation != 's':
            print("Se recomienda usar una VPN para actividades de reconocimiento.")
            proceed = input("¿Deseas continuar sin VPN? (s/n): ").lower()
            if proceed != 's':
                return False
    except Exception as e:
        print(f"Error al verificar la IP: {str(e)}")
    return True

def clean_and_validate_url(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query:
        clean_url += f"?{parsed.query}"
    return clean_url

def check_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"Resolución de DNS exitosa. IP: {ip}")
        return True
    except socket.gaierror:
        print(f"Error: No se pudo resolver el nombre de dominio {domain}")
        return False

def get_dns_records(domain):
    records = {}
    try:
        for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, qtype)
                records[qtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                pass
    except dns.resolver.NXDOMAIN:
        print(f"Error: El dominio {domain} no existe.")
    except Exception as e:
        print(f"Error al obtener registros DNS: {str(e)}")
    return records

def simple_recon(url):
    print(f"Iniciando reconocimiento simple para {url}...")
    
    results = {
        "hosts": set(),
        "emails": set(),
    }

    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        content = soup.get_text() + str(soup)
        base_domain = urlparse(url).netloc
        results["hosts"].update(re.findall(r'([\w-]+\.{0}[\w\.-]+)'.format(re.escape(base_domain)), content))
        results["emails"].update(re.findall(r'[\w\.-]+@[\w\.-]+', content))

        for link in soup.find_all('a', href=True):
            href = urljoin(url, link['href'])
            if base_domain in href:
                results["hosts"].add(urlparse(href).netloc)

    except requests.exceptions.RequestException as e:
        print(f"Error durante el reconocimiento: {str(e)}")
        return None

    return {k: list(v) for k, v in results.items()}

def print_results(results):
    if results is None:
        return

    print("\nResultados del reconocimiento:")
    print("-------------------------------")
    
    for key in ["hosts", "emails"]:
        if results[key]:
            print(f"\n{key.capitalize()} encontrados:")
            for item in results[key]:
                print(f"- {item}")
        else:
            print(f"\nNo se encontraron {key}")

if __name__ == "__main__":
    if check_vpn():
        while True:
            domain = input("Introduce el dominio objetivo: ")
            clean_url = clean_and_validate_url(domain)
            print(f"URL limpia y validada: {clean_url}")
            confirmation = input("¿Es esta la URL correcta? (s/n): ").lower()
            if confirmation == 's':
                parsed_url = urlparse(clean_url)
                if check_dns(parsed_url.netloc):
                    dns_records = get_dns_records(parsed_url.netloc)
                    print("\nRegistros DNS encontrados:")
                    for record_type, records in dns_records.items():
                        print(f"{record_type}: {', '.join(records)}")
                    results = simple_recon(clean_url)
                    print_results(results)
                else:
                    print("Verificación de DNS fallida. El dominio puede no existir o estar bloqueado.")
                break
            else:
                print("Por favor, intenta ingresar el dominio nuevamente.")
    else:
        print("Reconocimiento cancelado. Se recomienda usar una VPN para esta actividad.")