import subprocess
import json
import re
import zipfile
import xml.etree.ElementTree as ET
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def analyze_apk(apk_path):
    results = {}
    
    # Análisis con APKTool
    print("Descompilando APK...")
    run_command(f"apktool d {apk_path} -o apk_decompiled")
    
    # Análisis de permisos
    print("Analizando permisos...")
    results['permissions'] = analyze_permissions("apk_decompiled/AndroidManifest.xml")
    
    # Búsqueda de URLs y endpoints
    print("Buscando URLs y endpoints...")
    results['urls'] = find_urls("apk_decompiled")
    
    # Análisis de librerías nativas
    print("Analizando librerías nativas...")
    results['native_libs'] = analyze_native_libs("apk_decompiled/lib")
    
    # Verificación de ofuscación
    print("Verificando ofuscación...")
    results['obfuscation'] = check_obfuscation("apk_decompiled/smali")
    
    # Análisis de certificado
    print("Analizando certificado...")
    results['certificate'] = analyze_certificate(apk_path)
    
    # Limpieza
    run_command("rm -rf apk_decompiled")
    
    return results

def analyze_permissions(manifest_path):
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    permissions = []
    for perm in root.findall(".//uses-permission"):
        permissions.append(perm.attrib['{http://schemas.android.com/apk/res/android}name'])
    return permissions

def find_urls(decompiled_path):
    urls = []
    for root, dirs, files in os.walk(decompiled_path):
        for file in files:
            if file.endswith('.smali'):
                with open(os.path.join(root, file), 'r') as f:
                    content = f.read()
                    urls.extend(re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', content))
    return list(set(urls))

def analyze_native_libs(lib_path):
    libs = []
    if os.path.exists(lib_path):
        for arch in os.listdir(lib_path):
            arch_path = os.path.join(lib_path, arch)
            if os.path.isdir(arch_path):
                libs.extend([lib for lib in os.listdir(arch_path) if lib.endswith('.so')])
    return libs

def check_obfuscation(smali_path):
    obfuscated = False
    for root, dirs, files in os.walk(smali_path):
        for file in files:
            if file.endswith('.smali'):
                with open(os.path.join(root, file), 'r') as f:
                    content = f.read()
                    if re.search(r'\b[a-z]{1,2}\b', content):
                        obfuscated = True
                        break
        if obfuscated:
            break
    return obfuscated

def analyze_certificate(apk_path):
    with zipfile.ZipFile(apk_path, 'r') as apk:
        for file in apk.namelist():
            if file.startswith('META-INF/') and file.endswith('.RSA'):
                cert_data = apk.read(file)
                cert = x509.load_der_x509_certificate(cert_data)
                return {
                    "subject": str(cert.subject),
                    "issuer": str(cert.issuer),
                    "version": cert.version,
                    "serial_number": cert.serial_number,
                    "not_valid_before": cert.not_valid_before,
                    "not_valid_after": cert.not_valid_after,
                    "fingerprint": cert.fingerprint(hashes.SHA256()).hex()
                }
    return None

def main():
    apk_path = input("Ingrese la ruta del archivo APK a analizar: ")
    results = analyze_apk(apk_path)
    
    print("\nResultados del análisis:")
    print(f"Permisos: {', '.join(results['permissions'])}")
    print(f"URLs encontradas: {', '.join(results['urls'])}")
    print(f"Librerías nativas: {', '.join(results['native_libs'])}")
    print(f"Ofuscación detectada: {'Sí' if results['obfuscation'] else 'No'}")
    
    if results['certificate']:
        print("\nInformación del certificado:")
        for key, value in results['certificate'].items():
            print(f"{key}: {value}")

if __name__ == "__main__":
    main()