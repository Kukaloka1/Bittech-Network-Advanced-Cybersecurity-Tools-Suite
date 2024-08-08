import psutil
import requests
import os
import re

# Lista de palabras clave asociadas con spyware y malware
SUSPICIOUS_KEYWORDS = ["keylogger", "spyware", "malware", "trojan", "stealer", "ransomware"]

# URL para verificar la reputación de los procesos y conexiones (ejemplo con VirusTotal)
VIRUSTOTAL_API_KEY = ""  # Obtén tu API key de VirusTotal
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files"

def get_running_processes():
    """Obtiene la lista de procesos en ejecución."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        processes.append(proc.info)
    return processes

def check_process_reputation(process_name):
    """Verifica la reputación de un proceso usando VirusTotal."""
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    params = {
        "query": process_name
    }
    response = requests.get(VIRUSTOTAL_URL, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    return None

def detect_suspicious_processes(processes):
    """Detecta procesos sospechosos basados en palabras clave y reputación."""
    suspicious_processes = []
    for process in processes:
        if any(keyword in process['name'].lower() for keyword in SUSPICIOUS_KEYWORDS):
            process['reputation'] = check_process_reputation(process['name'])
            suspicious_processes.append(process)
    return suspicious_processes

def get_network_connections():
    """Obtiene la lista de conexiones de red activas."""
    try:
        connections = psutil.net_connections(kind='inet')
        return connections
    except psutil.AccessDenied:
        print("Acceso denegado al intentar obtener las conexiones de red. Intenta ejecutar el script con sudo.")
        return []

def detect_suspicious_connections(connections):
    """Detecta conexiones de red sospechosas."""
    suspicious_connections = []
    for conn in connections:
        if conn.raddr and conn.status == 'ESTABLISHED':
            suspicious_connections.append(conn)
    return suspicious_connections

def check_autostart_entries():
    """Revisa los registros de inicio automático en el sistema."""
    autostart_entries = []
    if os.name == 'nt':
        # Windows
        reg_paths = [
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        ]
        for reg_path in reg_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        autostart_entries.append(winreg.EnumValue(key, i))
            except Exception as e:
                print(f"Error leyendo el registro: {e}")
    elif os.name == 'posix':
        # Linux/Mac
        autostart_files = [
            os.path.expanduser("~/.bashrc"),
            os.path.expanduser("~/.bash_profile"),
            os.path.expanduser("~/.profile"),
            "/etc/rc.local"
        ]
        for file in autostart_files:
            if os.path.exists(file):
                with open(file, 'r') as f:
                    autostart_entries.extend(f.readlines())
    return autostart_entries

def detect_suspicious_autostart(entries):
    """Detecta entradas de inicio automático sospechosas."""
    suspicious_entries = []
    for entry in entries:
        if any(keyword in entry.lower() for keyword in SUSPICIOUS_KEYWORDS):
            suspicious_entries.append(entry)
    return suspicious_entries

def main():
    print("Analizando procesos en ejecución...")
    processes = get_running_processes()
    suspicious_processes = detect_suspicious_processes(processes)
    
    print("Analizando conexiones de red...")
    connections = get_network_connections()
    suspicious_connections = detect_suspicious_connections(connections)
    
    print("Revisando entradas de inicio automático...")
    autostart_entries = check_autostart_entries()
    suspicious_autostart_entries = detect_suspicious_autostart(autostart_entries)
    
    if suspicious_processes:
        print("Procesos sospechosos detectados:")
        for proc in suspicious_processes:
            print(proc)
    else:
        print("No se detectaron procesos sospechosos.")
    
    if suspicious_connections:
        print("Conexiones de red sospechosas detectadas:")
        for conn in suspicious_connections:
            print(conn)
    else:
        print("No se detectaron conexiones de red sospechosas.")
    
    if suspicious_autostart_entries:
        print("Entradas de inicio automático sospechosas detectadas:")
        for entry in suspicious_autostart_entries:
            print(entry)
    else:
        print("No se detectaron entradas de inicio automático sospechosas.")

if __name__ == "__main__":
    main()

