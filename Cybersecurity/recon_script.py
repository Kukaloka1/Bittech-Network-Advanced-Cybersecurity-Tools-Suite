from theharvester.discovery import *
from theharvester.discovery.constants import *
import asyncio
import json

async def run_theharvester(domain, limit=100):
    print(f"Iniciando reconocimiento para {domain}...")
    
    try:
        search_engines = [
            googlesearch.SearchGoogle,
            bingsearch.SearchBing,
            duckduckgosearch.SearchDuckDuckGo,
        ]

        results = {
            "hosts": set(),
            "ips": set(),
            "emails": set(),
        }

        for engine in search_engines:
            search = engine(domain, limit)
            await search.process()
            results["hosts"].update(search.get_hostnames())
            results["ips"].update(search.get_ips())
            results["emails"].update(search.get_emails())

        return {k: list(v) for k, v in results.items()}
    except Exception as e:
        print(f"Error durante el reconocimiento: {str(e)}")
        return None

def print_results(results):
    if results is None:
        return

    print("\nResultados del reconocimiento:")
    print("-------------------------------")
    
    for key in ["hosts", "emails", "ips"]:
        if key in results and results[key]:
            print(f"\n{key.capitalize()} encontrados:")
            for item in results[key]:
                print(f"- {item}")
        else:
            print(f"\nNo se encontraron {key}")

if __name__ == "__main__":
    domain = input(": ")
    results = asyncio.run(run_theharvester(domain))
    print_results(results)