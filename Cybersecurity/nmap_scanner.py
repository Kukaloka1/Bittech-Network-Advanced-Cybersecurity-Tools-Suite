import nmap
import sys
import os
import subprocess

def find_nmap():
    """Intenta encontrar la ruta de Nmap en MacOS"""
    try:
        # Intenta usar 'which' para encontrar nmap
        result = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass

    # Búsqueda en ubicaciones comunes de MacOS
    common_paths = [
        '/usr/local/bin/nmap',
        '/opt/homebrew/bin/nmap',
        '/usr/bin/nmap',
    ]
    for path in common_paths:
        if os.path.exists(path):
            return path
    return None

def nmap_scan(target, ports, nmap_path):
    try:
        nm = nmap.PortScanner(nmap_search_path=(nmap_path,))
        nm.scan(target, ports)
        
        for host in nm.all_hosts():
            print(f'Host : {host} ({nm[host].hostname()})')
            print(f'Estado : {nm[host].state()}')
            
            for proto in nm[host].all_protocols():
                print(f'----------')
                print(f'Protocolo : {proto}')
                
                lport = nm[host][proto].keys()
                for port in lport:
                    print(f'Puerto : {port}\tEstado : {nm[host][proto][port]["state"]}')
    except nmap.PortScannerError as e:
        print(f"Error al ejecutar Nmap: {e}")
        print("Asegúrate de que Nmap esté instalado y accesible.")
    except Exception as e:
        print(f"Ocurrió un error inesperado: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Uso: python nmap_scanner.py <ip_objetivo> <rango_puertos> [ruta_nmap]")
        print("Ejemplo: python nmap_scanner.py 192.168.1.1 1-1000")
        print("O: python nmap_scanner.py 192.168.1.1 1-1000 /usr/local/bin/nmap")
        sys.exit(1)

    target = sys.argv[1]
    ports = sys.argv[2]
    nmap_path = sys.argv[3] if len(sys.argv) == 4 else find_nmap()

    if not nmap_path:
        print("No se pudo encontrar Nmap. Por favor, proporciona la ruta manualmente.")
        sys.exit(1)

    print(f"Usando Nmap en: {nmap_path}")
    nmap_scan(target, ports, nmap_path)