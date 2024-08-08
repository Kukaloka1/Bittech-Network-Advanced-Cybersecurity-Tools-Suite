import zipfile
import re
from xml.etree import ElementTree
import os
import hashlib

def analyze_apk(apk_path):
    results = {}
    
    with zipfile.ZipFile(apk_path, 'r') as apk:
        # Análisis de permisos
        print("Analizando permisos...")
        manifest = apk.read('AndroidManifest.xml')
        results['permissions'] = analyze_permissions(manifest)
        
        # Búsqueda de URLs y endpoints
        print("Buscando URLs y endpoints...")
        results['urls'] = find_urls(apk)
        
        # Análisis de librerías
        print("Analizando librerías...")
        results['libraries'] = analyze_libraries(apk)
        
        # Cálculo de hash
        print("Calculando hash del APK...")
        results['apk_hash'] = calculate_apk_hash(apk_path)

    return results

def analyze_permissions(manifest_data):
    try:
        root = ElementTree.fromstring(manifest_data)
    except ElementTree.ParseError:
        # Si falla el parsing, el manifest podría estar en formato binario
        # En este caso, solo buscamos strings que parecen permisos
        permissions = re.findall(b'android.permission.[A-Z_]+', manifest_data)
        return [p.decode('utf-8') for p in permissions]
    
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    permissions = []
    for perm in root.findall(".//uses-permission"):
        name = perm.get('{http://schemas.android.com/apk/res/android}name')
        if name:
            permissions.append(name)
    return permissions

def find_urls(apk):
    urls = set()
    for file in apk.namelist():
        if file.endswith('.dex'):
            content = apk.read(file)
            urls.update(re.findall(b'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', content))
    return [url.decode('utf-8') for url in urls]

def analyze_libraries(apk):
    libraries = [name for name in apk.namelist() if name.startswith('lib/') and name.endswith('.so')]
    return libraries

def calculate_apk_hash(apk_path):
    sha256_hash = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def main():
    apk_path = input("Ingrese la ruta del archivo APK a analizar: ")
    results = analyze_apk(apk_path)
    
    print("\nResultados del análisis:")
    print(f"Permisos: {', '.join(results['permissions'])}")
    print(f"URLs encontradas: {', '.join(results['urls'])}")
    print(f"Librerías: {', '.join(results['libraries'])}")
    print(f"Hash del APK (SHA256): {results['apk_hash']}")

if __name__ == "__main__":
    main()