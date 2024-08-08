import subprocess
import os
import sys
import logging
import requests

def run_command(command):
    """Run a shell command."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"Error executing command: {command}")
        logging.error(result.stderr)
        print(f"Error executing command: {command}")
        print(result.stderr)
    else:
        logging.info(result.stdout)
        print(result.stdout)
    return result

def install_openvpn():
    """Install OpenVPN and Easy-RSA."""
    run_command("sudo apt update")
    run_command("sudo apt install openvpn easy-rsa -y")

def setup_easy_rsa():
    """Set up Easy-RSA and generate keys."""
    easyrsa_dir = os.path.expanduser("~/openvpn-ca")
    if not os.path.exists(easyrsa_dir):
        os.makedirs(easyrsa_dir)
    run_command(f"make-cadir {easyrsa_dir}")
    os.chdir(easyrsa_dir)
    run_command("cp /usr/share/easy-rsa/* .")
    run_command("source ./vars && ./clean-all")
    run_command("./build-ca --batch")
    run_command("./build-key-server server --batch")
    run_command("./build-dh")
    run_command("./build-key client --batch")

def copy_keys():
    """Copy keys to OpenVPN directory."""
    keys_path = os.path.expanduser("~/openvpn-ca/keys/")
    openvpn_dir = "/etc/openvpn"
    if not os.path.exists(openvpn_dir):
        os.makedirs(openvpn_dir)
    files_to_copy = ["ca.crt", "server.crt", "server.key", "dh2048.pem"]
    for file in files_to_copy:
        run_command(f"sudo cp {keys_path}{file} {openvpn_dir}")

def create_server_config(user_agent):
    """Create OpenVPN server configuration file."""
    openvpn_dir = "/etc/openvpn"
    if not os.path.exists(openvpn_dir):
        os.makedirs(openvpn_dir)
    server_conf = f"""
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 10 120
cipher AES-256-CBC
persist-key
persist-tun
status openvpn-status.log
verb 3
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
script-security 2
up /etc/openvpn/change_user_agent.sh
"""
    with open("/etc/openvpn/server.conf", "w") as file:
        file.write(server_conf)
    
    # Create script to change user agent
    change_user_agent_script = f"""
#!/bin/bash
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 3128
iptables -t mangle -A PREROUTING -p tcp --dport 443 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 3128
"""
    with open("/etc/openvpn/change_user_agent.sh", "w") as file:
        file.write(change_user_agent_script)
    run_command("sudo chmod +x /etc/openvpn/change_user_agent.sh")

def enable_ip_forwarding():
    """Enable IP forwarding."""
    run_command("echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf")
    run_command("sudo sysctl -p")

def configure_firewall():
    """Configure UFW firewall."""
    ufw_dir = "/etc/ufw"
    if not os.path.exists(ufw_dir):
        os.makedirs(ufw_dir)
    run_command("sudo ufw allow 1194/udp")
    run_command("sudo ufw allow OpenSSH")
    run_command("sudo ufw disable")
    run_command("sudo ufw enable")
    firewall_rules = """
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
COMMIT
"""
    with open("/etc/ufw/before.rules", "a") as file:
        file.write(firewall_rules)
    run_command("sudo ufw reload")

def start_openvpn_service():
    """Start OpenVPN service."""
    run_command("sudo openvpn --config /etc/openvpn/server.conf --daemon")

def stop_openvpn_service():
    """Stop OpenVPN service."""
    run_command("sudo pkill openvpn")

def status_openvpn_service():
    """Check the status of OpenVPN service."""
    run_command("pgrep openvpn && echo 'OpenVPN is running' || echo 'OpenVPN is stopped'")

def install_squid(user_agent):
    """Install and configure Squid proxy server."""
    run_command("sudo apt install squid -y")
    squid_conf_dir = "/etc/squid"
    if not os.path.exists(squid_conf_dir):
        os.makedirs(squid_conf_dir)
    squid_conf = f"""
http_port 3128
acl localnet src 10.8.0.0/24
http_access allow localnet
http_access deny all
cache_dir ufs /var/spool/squid 100 16 256
header_replace User-Agent "{user_agent}"
"""
    with open("/etc/squid/squid.conf", "w") as file:
        file.write(squid_conf)
    run_command("sudo service squid restart")

def log_connection_info():
    """Log the external IP and User-Agent to verify the connection."""
    try:
        headers = {'User-Agent': 'Tu-User-Agent'}
        ip_info = requests.get('https://api.ipify.org?format=json', headers=headers).json()
        logging.info(f"External IP: {ip_info['ip']}")
        print(f"External IP: {ip_info['ip']}")
        
        response = requests.get('http://httpbin.org/user-agent', headers=headers)
        user_agent = response.json()['user-agent']
        logging.info(f"User-Agent: {user_agent}")
        print(f"User-Agent: {user_agent}")
    except Exception as e:
        logging.error(f"Error obtaining connection info: {e}")
        print(f"Error obtaining connection info: {e}")

def main(action, user_agent=None):
    logging.basicConfig(filename='openvpn_setup.log', level=logging.INFO, 
                        format='%(asctime)s %(levelname)s:%(message)s')
    logging.info(f"Running action: {action}")
    print(f"Running action: {action}")

    if action == "install":
        install_openvpn()
        setup_easy_rsa()
        copy_keys()
        install_squid(user_agent)
        create_server_config(user_agent)
        enable_ip_forwarding()
        configure_firewall()
        start_openvpn_service()
        logging.info("VPN configurada con éxito. Copie los archivos ~/openvpn-ca/keys/{ca.crt, client.crt, client.key} al dispositivo cliente.")
        print("VPN configurada con éxito. Copie los archivos ~/openvpn-ca/keys/{ca.crt, client.crt, client.key} al dispositivo cliente.")
        log_connection_info()
    elif action == "start":
        start_openvpn_service()
        log_connection_info()
    elif action == "stop":
        stop_openvpn_service()
    elif action == "status":
        status_openvpn_service()
    else:
        logging.error("Acción no reconocida. Usa 'install', 'start', 'stop', 'status'.")
        print("Acción no reconocida. Usa 'install', 'start', 'stop', 'status'.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 setup_openvpn.py [install|start|stop|status] [USER_AGENT]")
    else:
        action = sys.argv[1]
        user_agent = sys.argv[2] if len(sys.argv) > 2 else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, como Gecko) Chrome/91.0.4472.124 Safari/537.36"
        main(action, user_agent)






#Haz el script ejecutable:
#chmod +x setup_openvpn.py

#Para instalar y configurar el servidor VPN (puedes especificar el User-Agent):
#sudo python3 setup_openvpn.py install "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

#Para iniciar el servicio VPN:
#sudo python3 setup_openvpn.py start

#Para detener el servicio VPN:
#sudo python3 setup_openvpn.py stop

#Para habilitar el servicio VPN para que se inicie al arrancar el sistema:
#sudo python3 setup_openvpn.py enable

#Para deshabilitar el servicio VPN para que no se inicie al arrancar el sistema:
#sudo python3 setup_openvpn.py disable

#Para verificar el estado del servicio VPN:
#sudo python3 setup_openvpn.py status

#CARPETAS:

#ls -la /etc/openvpn/
#ls -la /etc/squid/
#ls -la /etc/ufw/

#Inicia OpenVPN directamente usando el siguiente comando:
#sudo openvpn --config /etc/openvpn/server.conf --daemon

#Detener el Proceso de OpenVPN:
#sudo pkill openvpn

#Verifica si OpenVPN está corriendo usando pgrep:
#pgrep openvpn && echo "OpenVPN is running" || echo "OpenVPN is stopped"

