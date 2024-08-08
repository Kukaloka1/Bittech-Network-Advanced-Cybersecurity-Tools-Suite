import requests
from bs4 import BeautifulSoup
import re
import json

def simple_recon(domain):
    print(f"Iniciando reconocimiento simple para {domain}...")
    
    results = {
        "hosts": set(),
        "emails": set(),
    }

    try:
        # Obtener contenido de la página principal
        response = requests.get(f"http://{domain}", timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Buscar subdominios y emails en el contenido
        content = soup.get_text() + str(soup)
        results["hosts"].update(re.findall(r'([\w-]+\.{0}[\w\.-]+)'.format(re.escape(domain)), content))
        results["emails"].update(re.findall(r'[\w\.-]+@[\w\.-]+', content))

        # Buscar en los enlaces
        for link in soup.find_all('a', href=True):
            href = link['href']
            if domain in href:
                results["hosts"].add(href.split('//')[-1].split('/')[0])

    except Exception as e:
        print(f"Error durante el reconocimiento: {str(e)}")

    return {k: list(v) for k, v in results.items()}

def print_results(results):
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
    domain = input(": ")
    results = simple_recon(domain)
    print_results(results)
    