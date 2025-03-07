#!/usr/bin/env python3
import sys
import nmap
import scapy.all as scapy
from colorama import init, Fore, Style, Back
import argparse
import socket
import netifaces
import os
import time
from datetime import datetime
import threading
import queue
from tqdm import tqdm

init()  # Inicializar colorama

def print_banner():
    banner = f"""
{Fore.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║ {Fore.RED}███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗{Fore.CYAN} ║
║ {Fore.RED}████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║{Fore.CYAN} ║
║ {Fore.RED}██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║{Fore.CYAN} ║
║ {Fore.RED}██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║{Fore.CYAN} ║
║ {Fore.RED}██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║{Fore.CYAN} ║
║ {Fore.RED}╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Fore.CYAN} ║
╠═══════════════════════════════════════════════════════════════╣
║ {Fore.GREEN}[+] Herramienta de Escaneo de Red v3.5                      {Fore.CYAN}║
║ {Fore.GREEN}[+] Autor: Network Scanner Team                             {Fore.CYAN}║
║ {Fore.GREEN}[+] Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                   {Fore.CYAN}║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)

def get_arguments():
    parser = argparse.ArgumentParser(description='Scanner de red avanzado para Kali Linux')
    parser.add_argument('-t', '--target', dest='target', help='IP objetivo/rango (ejemplo: 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', dest='ports', help='Puertos a escanear (ejemplo: 21,22,80,443 o 1-1000)')
    parser.add_argument('-i', '--intense', action='store_true', help='Realizar escaneo intensivo')
    parser.add_argument('-o', '--output', dest='output', help='Guardar resultados en archivo')
    return parser.parse_args()

def get_default_gateway():
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        return default_gateway
    except:
        print(f"{Fore.RED}[!] Error al obtener el gateway por defecto{Style.RESET_ALL}")
        sys.exit(1)

def scan_network(ip, q):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        devices_list = []
        for element in answered_list:
            device_dict = {
                "ip": element[1].psrc,
                "mac": element[1].hwsrc
            }
            devices_list.append(device_dict)
        q.put(devices_list)
    except Exception as e:
        print(f"{Fore.RED}[!] Error durante el escaneo: {str(e)}{Style.RESET_ALL}")
        q.put([])

def get_device_details(ip, ports=None):
    nm = nmap.PortScanner()
    try:
        if ports:
            result = nm.scan(ip, arguments=f'-sS -sV -p{ports} -T4')
        else:
            result = nm.scan(ip, arguments='-sn')
        
        if ip in result['scan']:
            device_info = {
                'hostname': result['scan'][ip].hostname() or "Desconocido",
                'ports': result['scan'][ip].get('tcp', {}) if ports else {}
            }
            return device_info
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error al obtener detalles de {ip}: {str(e)}{Style.RESET_ALL}")
    return {'hostname': "Desconocido", 'ports': {}}

def print_result(devices_list, ports=None, output_file=None):
    print(f"\n{Fore.GREEN}[+] Dispositivos encontrados en la red:{Style.RESET_ALL}")
    header = f"\n{Fore.YELLOW}{'IP':15} {'MAC Address':18} {'Hostname':20}"
    if ports:
        header += f"{'Puertos Abiertos':30}"
    header += Style.RESET_ALL
    print(header)
    print("=" * (83 if ports else 53))
    
    output_content = []
    output_content.append("Resultados del escaneo - " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    output_content.append("=" * 80)
    output_content.append(f"{'IP':<15} {'MAC Address':<18} {'Hostname':<20} {'Puertos Abiertos':<30}")
    output_content.append("=" * 80)

    for device in tqdm(devices_list, desc="Analizando dispositivos", unit="dispositivo"):
        details = get_device_details(device["ip"], ports)
        open_ports = []
        if ports and details['ports']:
            for port, info in details['ports'].items():
                if info['state'] == 'open':
                    service = info.get('name', 'unknown')
                    open_ports.append(f"{port}/{service}")
        
        port_info = ', '.join(open_ports[:3]) + ('...' if len(open_ports) > 3 else '')
        print(f"{Fore.GREEN}{device['ip']:15}{Style.RESET_ALL} "
              f"{device['mac']:18} "
              f"{details['hostname']:20} "
              f"{port_info:30}")
        
        output_line = f"{device['ip']:<15} {device['mac']:<18} {details['hostname']:<20} {port_info:<30}"
        output_content.append(output_line)

    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write('\n'.join(output_content))
            print(f"\n{Fore.GREEN}[+] Resultados guardados en {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error al guardar resultados: {str(e)}{Style.RESET_ALL}")

def mostrar_menu():
    """Muestra el menú interactivo de la aplicación"""
    # Obtener información del sistema
    try:
        ip_local = socket.gethostbyname(socket.gethostname())
        gateway = get_default_gateway()
    except:
        ip_local = "Desconocida"
        gateway = "Desconocido"
    
    menu = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════╗
║ {Fore.YELLOW}             MENÚ PRINCIPAL                        {Fore.CYAN}║
╠═══════════════════════════════════════════════════╣
║ {Fore.GREEN}[1] Escaneo rápido de red                         {Fore.CYAN}║
║ {Fore.GREEN}[2] Escaneo completo (IP, MAC, hostname)          {Fore.CYAN}║
║ {Fore.GREEN}[3] Escaneo de puertos en dispositivos            {Fore.CYAN}║
║ {Fore.GREEN}[4] Monitoreo continuo de red                     {Fore.CYAN}║
║ {Fore.GREEN}[5] Escaneo de vulnerabilidades                   {Fore.CYAN}║
║ {Fore.GREEN}[6] Análisis de tráfico de red                    {Fore.CYAN}║
║ {Fore.GREEN}[7] Mapa de red                                   {Fore.CYAN}║
║ {Fore.GREEN}[8] Configuración                                 {Fore.CYAN}║
║ {Fore.GREEN}[9] Ayuda                                         {Fore.CYAN}║
║ {Fore.GREEN}[0] Salir                                         {Fore.CYAN}║
╠═══════════════════════════════════════════════════╣
║ {Fore.YELLOW} IP Local: {ip_local:<37} {Fore.CYAN}║
║ {Fore.YELLOW} Gateway: {gateway:<38} {Fore.CYAN}║
╚═══════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(menu)
    return input(f"{Fore.YELLOW}Seleccione una opción: {Style.RESET_ALL}")

def escaneo_rapido():
    """Realiza un escaneo rápido de la red"""
    gateway = get_default_gateway()
    target = f"{gateway}/24"
    print(f"\n{Fore.CYAN}[*] Iniciando escaneo rápido de red...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Objetivo: {target}{Style.RESET_ALL}")
    
    q = queue.Queue()
    scan_thread = threading.Thread(target=scan_network, args=(target, q))
    scan_thread.start()
    
    with tqdm(total=100, desc="Escaneando red", unit="%") as pbar:
        while scan_thread.is_alive():
            time.sleep(0.1)
            pbar.update(1)
            if pbar.n >= 100:
                pbar.n = 0
        scan_thread.join()
    
    devices_list = q.get()
    
    if not devices_list:
        print(f"\n{Fore.RED}[!] No se encontraron dispositivos en la red{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}[+] Dispositivos encontrados en la red:{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}{'IP':15} {'MAC Address':18}{Style.RESET_ALL}")
    print("=" * 33)
    
    for device in devices_list:
        print(f"{Fore.GREEN}{device['ip']:15}{Style.RESET_ALL} {device['mac']:18}")
    
    print(f"\n{Fore.GREEN}[+] Escaneo rápido completado{Style.RESET_ALL}")
    input(f"\n{Fore.YELLOW}Presione Enter para continuar...{Style.RESET_ALL}")

def escaneo_completo():
    """Realiza un escaneo completo de la red"""
    gateway = get_default_gateway()
    target = f"{gateway}/24"
    print(f"\n{Fore.CYAN}[*] Iniciando escaneo completo de red...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Objetivo: {target}{Style.RESET_ALL}")
    
    q = queue.Queue()
    scan_thread = threading.Thread(target=scan_network, args=(target, q))
    scan_thread.start()
    
    with tqdm(total=100, desc="Escaneando red", unit="%") as pbar:
        while scan_thread.is_alive():
            time.sleep(0.1)
            pbar.update(1)
            if pbar.n >= 100:
                pbar.n = 0
        scan_thread.join()
    
    devices_list = q.get()
    
    if not devices_list:
        print(f"\n{Fore.RED}[!] No se encontraron dispositivos en la red{Style.RESET_ALL}")
        return
    
    print_result(devices_list)
    
    guardar = input(f"\n{Fore.YELLOW}¿Desea guardar los resultados? (s/n): {Style.RESET_ALL}").lower()
    if guardar == 's':
        nombre_archivo = input(f"{Fore.YELLOW}Nombre del archivo: {Style.RESET_ALL}")
        if not nombre_archivo.endswith('.txt'):
            nombre_archivo += '.txt'
        print_result(devices_list, output_file=nombre_archivo)
    
    input(f"\n{Fore.YELLOW}Presione Enter para continuar...{Style.RESET_ALL}")

def escaneo_puertos():
    """Realiza un escaneo de puertos en dispositivos seleccionados"""
    gateway = get_default_gateway()
    target = f"{gateway}/24"
    print(f"\n{Fore.CYAN}[*] Buscando dispositivos en la red...{Style.RESET_ALL}")
    
    q = queue.Queue()
    scan_thread = threading.Thread(target=scan_network, args=(target, q))
    scan_thread.start()
    scan_thread.join()
    
    devices_list = q.get()
    
    if not devices_list:
        print(f"\n{Fore.RED}[!] No se encontraron dispositivos en la red{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}[+] Dispositivos encontrados:{Style.RESET_ALL}")
    for i, device in enumerate(devices_list, 1):
        print(f"{Fore.GREEN}[{i}] {device['ip']} ({device['mac']}){Style.RESET_ALL}")
    
    try:
        seleccion = input(f"\n{Fore.YELLOW}Seleccione un dispositivo (número) o 'todos': {Style.RESET_ALL}")
        puertos = input(f"{Fore.YELLOW}Ingrese puertos a escanear (ej: 21,22,80,443 o 1-1000): {Style.RESET_ALL}")
        
        if seleccion.lower() == 'todos':
            dispositivos_seleccionados = devices_list
        else:
            idx = int(seleccion) - 1
            if 0 <= idx < len(devices_list):
                dispositivos_seleccionados = [devices_list[idx]]
            else:
                print(f"{Fore.RED}[!] Selección inválida{Style.RESET_ALL}")
                return
        
        print(f"\n{Fore.CYAN}[*] Iniciando escaneo de puertos...{Style.RESET_ALL}")
        print_result(dispositivos_seleccionados, puertos)
        
    except ValueError:
        print(f"{Fore.RED}[!] Entrada inválida{Style.RESET_ALL}")
    
    input(f"\n{Fore.YELLOW}Presione Enter para continuar...{Style.RESET_ALL}")

def monitoreo_continuo():
    """Realiza un monitoreo continuo de la red para detectar nuevos dispositivos"""
    gateway = get_default_gateway()
    target = f"{gateway}/24"
    print(f"\n{Fore.CYAN}[*] Iniciando monitoreo continuo de red...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Presione Ctrl+C para detener el monitoreo{Style.RESET_ALL}")
    
    dispositivos_conocidos = set()
    
    try:
        while True:
            q = queue.Queue()
            scan_thread = threading.Thread(target=scan_network, args=(target, q))
            scan_thread.start()
            scan_thread.join()
            
            devices_list = q.get()
            dispositivos_actuales = {device['ip'] for device in devices_list}
            
            # Detectar nuevos dispositivos
            nuevos_dispositivos = dispositivos_actuales - dispositivos_conocidos
            if nuevos_dispositivos:
                print(f"\n{Fore.GREEN}[+] {datetime.now().strftime('%H:%M:%S')} - Nuevos dispositivos detectados:{Style.RESET_ALL}")
                for device in devices_list:
                    if device['ip'] in nuevos_dispositivos:
                        print(f"{Fore.GREEN}    {device['ip']} ({device['mac']}){Style.RESET_ALL}")
            
            # Detectar dispositivos desconectados
            dispositivos_desconectados = dispositivos_conocidos - dispositivos_actuales
            if dispositivos_desconectados:
                print(f"\n{Fore.YELLOW}[!] {datetime.now().strftime('%H:%M:%S')} - Dispositivos desconectados:{Style.RESET_ALL}")
                for ip in dispositivos_desconectados:
                    print(f"{Fore.YELLOW}    {ip}{Style.RESET_ALL}")
            
            dispositivos_conocidos = dispositivos_actuales
            time.sleep(10)  # Escanear cada 10 segundos
            
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}[*] Monitoreo detenido{Style.RESET_ALL}")
    
    input(f"\n{Fore.YELLOW}Presione Enter para continuar...{Style.RESET_ALL}")

def escaneo_vulnerabilidades():
    """Realiza un escaneo de vulnerabilidades en dispositivos seleccionados"""
    gateway = get_default_gateway()
    target = f"{gateway}/24"
    print(f"\n{Fore.CYAN}[*] Buscando dispositivos en la red...{Style.RESET_ALL}")
    
    q = queue.Queue()
    scan_thread = threading.Thread(target=scan_network, args=(target, q))
    scan_thread.start()
    scan_thread.join()
    
    devices_list = q.get()
    
    if not devices_list:
        print(f"\n{Fore.RED}[!] No se encontraron dispositivos en la red{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}[+] Dispositivos encontrados:{Style.RESET_ALL}")
    for i, device in enumerate(devices_list, 1):
        print(f"{Fore.GREEN}[{i}] {device['ip']} ({device['mac']}){Style.RESET_ALL}")
    
    try:
        seleccion = input(f"\n{Fore.YELLOW}Seleccione un dispositivo (número): {Style.RESET_ALL}")
        idx = int(seleccion) - 1
        
        if 0 <= idx < len(devices_list):
            ip = devices_list[idx]['ip']
            print(f"\n{Fore.CYAN}[*] Iniciando escaneo de vulnerabilidades en {ip}...{Style.RESET_ALL}")
            
            nm = nmap.PortScanner()
            print(f"{Fore.YELLOW}[*] Este proceso puede tardar varios minutos...{Style.RESET_ALL}")
            
            with tqdm(total=100, desc="Escaneando vulnerabilidades", unit="%") as pbar:
                # Ejecutar el escaneo en un hilo separado para mostrar la barra de progreso
                def run_scan():
                    nonlocal nm
                    try:
                        nm.scan(ip, arguments='-sS -sV --script vuln -T4')
                    except Exception as e:
                        print(f"{Fore.RED}[!] Error durante el escaneo: {str(e)}{Style.RESET_ALL}")
                
                scan_thread = threading.Thread(target=run_scan)
                scan_thread.start()
                
                while scan_thread.is_alive():
                    time.sleep(0.5)
                    pbar.update(1)
                    if pbar.n >= 100:
                        pbar.n = 0
                scan_thread.join()
            
            if ip in nm.all_hosts():
                print(f"\n{Fore.GREEN}[+] Resultados del escaneo de vulnerabilidades para {ip}:{Style.RESET_ALL}")
                
                for proto in nm[ip].all_protocols():
                    print(f"\n{Fore.YELLOW}Protocolo: {proto}{Style.RESET_ALL}")
                    
                    for port in nm[ip][proto].keys():
                        port_info = nm[ip][proto][port]
                        print(f"\n{Fore.GREEN}Puerto {port} ({port_info.get('name', 'desconocido')}){Style.RESET_ALL}")
                        print(f"Estado: {port_info.get('state', 'desconocido')}")
                        print(f"Servicio: {port_info.get('product', 'desconocido')} {port_info.get('version', '')}")
                        
                        # Mostrar vulnerabilidades si existen
                        if 'script' in port_info:
                            print(f"\n{Fore.RED}Vulnerabilidades detectadas:{Style.RESET_ALL}")
                            for script_name, output in port_info['script'].items():
                                print(f"{Fore.RED}[!] {script_name}:{Style.RESET_ALL}")
                                print(f"{output}\n")
            else:
                print(f"\n{Fore.RED}[!] No se pudo completar el escaneo de vulnerabilidades{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Selección inválida{Style.RESET_ALL}")
    
    except ValueError:
        print(f"{Fore.RED}[!] Entrada inválida{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.YELLOW}Presione Enter para continuar...{Style.RESET_ALL}")

def analisis_trafico():
    """Realiza un análisis del tráfico de red"""
    print(f"\n{Fore.CYAN}╔═══════════════════════════════════════════════════╗")
    print(f"║ {Fore.YELLOW}          ANÁLISIS DE TRÁFICO DE RED               {Fore.CYAN}║")
    print(f"╚═══════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}[*] Esta función captura y analiza paquetes de red en tiempo real.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Presione Ctrl+C para detener la captura.{Style.RESET_ALL}")
    
    try:
        # Verificar si scapy está disponible
        if not hasattr(scapy, 'sniff'):
            print(f"{Fore.RED}[!] Error: La función de captura de paquetes no está disponible.{Style.RESET_ALL}")
            return
        
        # Seleccionar interfaz
        interfaces = netifaces.interfaces()
        print(f"\n{Fore.GREEN}[+] Interfaces de red disponibles:{Style.RESET_ALL}")
        for i, iface in enumerate(interfaces, 1):
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    print(f"{Fore.GREEN}[{i}] {iface} - {ip}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[{i}] {iface}{Style.RESET_ALL}")
            except:
                print(f"{Fore.GREEN}[{i}] {iface}{Style.RESET_ALL}")
        
        seleccion = input(f"\n{Fore.YELLOW}Seleccione una interfaz (número): {Style.RESET_ALL}")
        try:
            idx = int(seleccion) - 1
            if 0 <= idx < len(interfaces):
                iface = interfaces[idx]
            else:
                print(f"{Fore.RED}[!] Selección inválida. Usando la primera interfaz.{Style.RESET_ALL}")
                iface = interfaces[0]
        except:
            print(f"{Fore.RED}[!] Entrada inválida. Usando la primera interfaz.{Style.RESET_ALL}")
            iface = interfaces[0]
        
        # Estadísticas de paquetes
        paquetes_total = 0
        paquetes_tcp = 0
        paquetes_udp = 0
        paquetes_icmp = 0
        paquetes_otros = 0
        ips_origen = {}
        ips_destino = {}
        puertos_destino = {}
        
        # Función para procesar cada paquete
        def procesar_paquete(paquete):
            nonlocal paquetes_total, paquetes_tcp, paquetes_udp, paquetes_icmp, paquetes_otros
            nonlocal ips_origen, ips_destino, puertos_destino
            
            paquetes_total += 1
            
            # Limpiar pantalla y mostrar estadísticas actualizadas
            os.system('clear' if os.name != 'nt' else 'cls')
            print(f"{Fore.CYAN}╔═══════════════════════════════════════════════════╗")
            print(f"║ {Fore.YELLOW}          ANÁLISIS DE TRÁFICO DE RED               {Fore.CYAN}║")
            print(f"╚═══════════════════════════════════════════════════╝{Style.RESET_ALL}")
            print(f"\n{Fore.GREEN}[+] Capturando paquetes en {iface}...{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Paquetes capturados: {paquetes_total}{Style.RESET_ALL}")
            
            # Analizar el paquete
            if paquete.haslayer(scapy.TCP):
                paquetes_tcp += 1
                protocolo = "TCP"
                if paquete.haslayer(scapy.IP):
                    puerto = paquete[scapy.TCP].dport
                    puertos_destino[puerto] = puertos_destino.get(puerto, 0) + 1
            elif paquete.haslayer(scapy.UDP):
                paquetes_udp += 1
                protocolo = "UDP"
                if paquete.haslayer(scapy.IP):
                    puerto = paquete[scapy.UDP].dport
                    puertos_destino[puerto] = puertos_destino.get(puerto, 0) + 1
            elif paquete.haslayer(scapy.ICMP):
                paquetes_icmp += 1
                protocolo = "ICMP"
            else:
                paquetes_otros += 1
                protocolo = "Otro"
            
            # Extraer IPs si están disponibles
            if paquete.haslayer(scapy.IP):
                ip_src = paquete[scapy.IP].src
                ip_dst = paquete[scapy.IP].dst
                ips_origen[ip_src] = ips_origen.get(ip_src, 0) + 1
                ips_destino[ip_dst] = ips_destino.get(ip_dst, 0) + 1
                
                # Mostrar detalles del paquete actual
                print(f"\n{Fore.YELLOW}Último paquete:{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Protocolo:{Style.RESET_ALL} {protocolo}")
                print(f"  {Fore.GREEN}Origen:{Style.RESET_ALL} {ip_src}")
                print(f"  {Fore.GREEN}Destino:{Style.RESET_ALL} {ip_dst}")
                if protocolo in ["TCP", "UDP"]:
                    puerto = paquete[scapy.TCP].dport if protocolo == "TCP" else paquete[scapy.UDP].dport
                    print(f"  {Fore.GREEN}Puerto destino:{Style.RESET_ALL} {puerto}")
            
            # Mostrar estadísticas
            print(f"\n{Fore.YELLOW}Estadísticas de protocolos:{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}TCP:{Style.RESET_ALL} {paquetes_tcp} ({paquetes_tcp/paquetes_total*100:.1f}%)")
            print(f"  {Fore.GREEN}UDP:{Style.RESET_ALL} {paquetes_udp} ({paquetes_udp/paquetes_total*100:.1f}%)")
            print(f"  {Fore.GREEN}ICMP:{Style.RESET_ALL} {paquetes_icmp} ({paquetes_icmp/paquetes_total*100:.1f}%)")
            print(f"  {Fore.GREEN}Otros:{Style.RESET_ALL} {paquetes_otros} ({paquetes_otros/paquetes_total*100:.1f}%)")
            
            # Mostrar IPs más frecuentes
            print(f"\n{Fore.YELLOW}IPs de origen más frecuentes:{Style.RESET_ALL}")
            for ip, count in sorted(ips_origen.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {Fore.GREEN}{ip}:{Style.RESET_ALL} {count}")
            
            print(f"\n{Fore.YELLOW}IPs de destino más frecuentes:{Style.RESET_ALL}")
            for ip, count in sorted(ips_destino.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {Fore.GREEN}{ip}:{Style.RESET_ALL} {count}")
            
            # Mostrar puertos más frecuentes
            if puertos_destino:
                print(f"\n{Fore.YELLOW}Puertos de destino más frecuentes:{Style.RESET_ALL}")
                for puerto, count in sorted(puertos_destino.items(), key=lambda x: x[1], reverse=True)[:5]:
                    servicio = "desconocido"
                    if puerto == 80:
                        servicio = "HTTP"
                    elif puerto == 443:
                        servicio = "HTTPS"
                    elif puerto == 53:
                        servicio = "DNS"
                    elif puerto == 22:
                        servicio = "SSH"
                    elif puerto == 21:
                        servicio = "FTP"
                    print(f"  {Fore.GREEN}{puerto} ({servicio}):{Style.RESET_ALL} {count}")
            
            print(f"\n{Fore.YELLOW}Presione Ctrl+C para detener la captura.{Style.RESET_ALL}")
        
        # Iniciar la captura de paquetes
        print(f"\n{Fore.GREEN}[+] Iniciando captura de paquetes en {iface}...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Presione Ctrl+C para detener la captura.{Style.RESET_ALL}")
        scapy.sniff(iface=iface, prn=procesar_paquete, store=False)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}[*] Captura de paquetes detenida{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error durante la captura: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.YELLOW}Presione Enter para continuar...{Style.RESET_ALL}")

def mapa_red():
    """Genera y muestra un mapa visual de la red"""
    print(f"\n{Fore.CYAN}╔═══════════════════════════════════════════════════╗")
    print(f"║ {Fore.YELLOW}                MAPA DE RED                       {Fore.CYAN}║")
    print(f"╚═══════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    gateway = get_default_gateway()
    target = f"{gateway}/24"
    print(f"\n{Fore.CYAN}[*] Escaneando la red para generar el mapa...{Style.RESET_ALL}")
    
    q = queue.Queue()
    scan_thread = threading.Thread(target=scan_network, args=(target, q))
    scan_thread.start()
    
    with tqdm(total=100, desc="Escaneando red", unit="%") as pbar:
        while scan_thread.is_alive():
            time.sleep(0.1)
            pbar.update(1)
            if pbar.n >= 100:
                pbar.n = 0
        scan_thread.join()
    
    devices_list = q.get()
    
    if not devices_list:
        print(f"\n{Fore.RED}[!] No se encontraron dispositivos en la red{Style.RESET_ALL}")
        return
    
    # Obtener detalles adicionales de los dispositivos
    print(f"\n{Fore.CYAN}[*] Obteniendo detalles de los dispositivos...{Style.RESET_ALL}")
    
    dispositivos_detallados = []
    for device in tqdm(devices_list, desc="Analizando dispositivos", unit="dispositivo"):
        details = get_device_details(device["ip"])
        device_info = {
            "ip": device["ip"],
            "mac": device["mac"],
            "hostname": details["hostname"]
        }
        dispositivos_detallados.append(device_info)
    
    # Generar mapa visual ASCII
    print(f"\n{Fore.GREEN}[+] Mapa de red generado:{Style.RESET_ALL}")
    
    # Dibujar el router/gateway
    print(f"\n{Fore.YELLOW}╔══════════════════════╗")
    print(f"║ {Fore.GREEN}Router/Gateway       {Fore.YELLOW}║")
    print(f"║ {Fore.GREEN}{gateway:<20}{Fore.YELLOW}║")
    print(f"╚═══════════╦══════════╝")
    print(f"            ║")
    print(f"            ║")
    print(f"            ▼{Style.RESET_ALL}")
    
    # Dibujar los dispositivos conectados
    for i, device in enumerate(dispositivos_detallados):
        if i == 0:
            print(f"{Fore.CYAN}╔══════════╩══════════╗")
        else:
            print(f"{Fore.CYAN}╠═════════════════════╣")
        
        hostname = device["hostname"]
        if hostname == "Desconocido" and device["ip"] == gateway:
            hostname = "Router/Gateway"
        
        print(f"║ {Fore.GREEN}Dispositivo {i+1:<9}{Fore.CYAN}║")
        print(f"║ {Fore.GREEN}IP: {device['ip']:<15}{Fore.CYAN}║")
        print(f"║ {Fore.GREEN}MAC: {device['mac']:<15}{Fore.CYAN}║")
        print(f"║ {Fore.GREEN}Nombre: {hostname[:15]:<15}{Fore.CYAN}║")
        
        if i == len(dispositivos_detallados) - 1:
            print(f"╚═════════════════════╝{Style.RESET_ALL}")
        else:
            print(f"║                     ║")
            print(f"║          ║          ║")
            print(f"║          ▼          ║")
    
    # Opción para guardar el mapa
    guardar = input(f"\n{Fore.YELLOW}¿Desea guardar el mapa de red? (s/n): {Style.RESET_ALL}").lower()
    if guardar == 's':
        nombre_archivo = input(f"{Fore.YELLOW}Nombre del archivo: {Style.RESET_ALL}")
        if not nombre_archivo.endswith('.txt'):
            nombre_archivo += '.txt'
        
        try:
            with open(nombre_archivo, 'w') as f:
                f.write(f"Mapa de Red - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Gateway: {gateway}\n\n")
                for i, device in enumerate(dispositivos_detallados, 1):
                    f.write(f"Dispositivo {i}:\n")
                    f.write(f"  IP: {device['ip']}\n")
                    f.write(f"  MAC: {device['mac']}\n")
                    f.write(f"  Nombre: {device['hostname']}\n\n")
            print(f"\n{Fore.GREEN}[+] Mapa guardado en {nombre_archivo}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error al guardar el mapa: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.YELLOW}Presione Enter para continuar...{Style.RESET_ALL}")

def mostrar_configuracion():
    """Muestra y permite modificar la configuración de la herramienta"""
    print(f"\n{Fore.CYAN}╔═══════════════════════════════════════════════════╗")
    print(f"║ {Fore.YELLOW}             CONFIGURACIÓN                         {Fore.CYAN}║")
    print(f"╚═══════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    # Configuraciones disponibles
    configuraciones = {
        "timeout_scan": 1,
        "verbose_mode": False,
        "auto_save": False,
        "save_path": "./resultados/",
        "color_theme": "default"
    }
    
    while True:
        print(f"\n{Fore.GREEN}Configuraciones actuales:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[1] Tiempo de espera de escaneo:{Style.RESET_ALL} {configuraciones['timeout_scan']} segundos")
        print(f"  {Fore.YELLOW}[2] Modo detallado:{Style.RESET_ALL} {'Activado' if configuraciones['verbose_mode'] else 'Desactivado'}")
        print(f"  {Fore.YELLOW}[3] Guardado automático:{Style.RESET_ALL} {'Activado' if configuraciones['auto_save'] else 'Desactivado'}")
        print(f"  {Fore.YELLOW}[4] Ruta de guardado:{Style.RESET_ALL} {configuraciones['save_path']}")
        print(f"  {Fore.YELLOW}[5] Tema de colores:{Style.RESET_ALL} {configuraciones['color_theme']}")
        print(f"  {Fore.YELLOW}[0] Volver al menú principal{Style.RESET_ALL}")
        
        opcion = input(f"\n{Fore.YELLOW}Seleccione una opción para modificar: {Style.RESET_ALL}")
        
        if opcion == "1":
            try:
                nuevo_valor = float(input(f"{Fore.YELLOW}Nuevo tiempo de espera (segundos): {Style.RESET_ALL}"))
                if nuevo_valor > 0:
                    configuraciones["timeout_scan"] = nuevo_valor
                    print(f"{Fore.GREEN}[+] Tiempo de espera actualizado{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] El tiempo debe ser mayor que 0{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Valor inválido{Style.RESET_ALL}")
        
        elif opcion == "2":
            configuraciones["verbose_mode"] = not configuraciones["verbose_mode"]
            print(f"{Fore.GREEN}[+] Modo detallado {'activado' if configuraciones['verbose_mode'] else 'desactivado'}{Style.RESET_ALL}")
        
        elif opcion == "3":
            configuraciones["auto_save"] = not configuraciones["auto_save"]
            print(f"{Fore.GREEN}[+] Guardado automático {'activado' if configuraciones['auto_save'] else 'desactivado'}{Style.RESET_ALL}")
        
        elif opcion == "4":
            nueva_ruta = input(f"{Fore.YELLOW}Nueva ruta de guardado: {Style.RESET_ALL}")
            if nueva_ruta:
                configuraciones["save_path"] = nueva_ruta
                print(f"{Fore.GREEN}[+] Ruta de guardado actualizada{Style.RESET_ALL}")
        
        elif opcion == "5":
            print(f"\n{Fore.YELLOW}Temas disponibles:{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}1. Default{Style.RESET_ALL}")
            print(f"  {Fore.BLUE}2. Blue{Style.RESET_ALL}")
            print(f"  {Fore.MAGENTA}3. Purple{Style.RESET_ALL}")
            print(f"  {Fore.RED}4. Red{Style.RESET_ALL}")
            
            tema = input(f"\n{Fore.YELLOW}Seleccione un tema: {Style.RESET_ALL}")
            if tema == "1":
                configuraciones["color_theme"] = "default"
            elif tema == "2":
                configuraciones["color_theme"] = "blue"
            elif tema == "3":
                configuraciones["color_theme"] = "purple"
            elif tema == "4":
                configuraciones["color_theme"] = "red"
            else:
                print(f"{Fore.RED}[!] Opción inválida{Style.RESET_ALL}")
                continue
            
            print(f"{Fore.GREEN}[+] Tema actualizado (se aplicará en el próximo inicio){Style.RESET_ALL}")
        
        elif opcion == "0":
            break
        
        else:
            print(f"{Fore.RED}[!] Opción inválida{Style.RESET_ALL}")
    
    # Guardar configuraciones (simulado)
    print(f"\n{Fore.GREEN}[+] Configuraciones guardadas{Style.RESET_ALL}")
    time.sleep(1)

def mostrar_ayuda():
    """Muestra la ayuda de la herramienta"""
    ayuda = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║ {Fore.YELLOW}                        AYUDA                                  {Fore.CYAN}║
╠═══════════════════════════════════════════════════════════════╣
║ {Fore.GREEN}Escaneo rápido:{Fore.WHITE} Detecta rápidamente dispositivos en la red    {Fore.CYAN}║
║ {Fore.GREEN}Escaneo completo:{Fore.WHITE} Muestra IP, MAC y nombres de host           {Fore.CYAN}║
║ {Fore.GREEN}Escaneo de puertos:{Fore.WHITE} Analiza puertos abiertos en dispositivos  {Fore.CYAN}║
║ {Fore.GREEN}Monitoreo continuo:{Fore.WHITE} Detecta nuevos dispositivos en tiempo real{Fore.CYAN}║
║ {Fore.GREEN}Escaneo de vulnerabilidades:{Fore.WHITE} Busca vulnerabilidades conocidas {Fore.CYAN}║
║                                                               ║
║ {Fore.YELLOW}Esta herramienta debe usarse solo en redes con autorización.   {Fore.CYAN}║
║ {Fore.YELLOW}El uso no autorizado puede ser ilegal.                         {Fore.CYAN}║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(ayuda)
    input(f"\n{Fore.YELLOW}Presione Enter para continuar...{Style.RESET_ALL}")

def menu_principal():
    """Función principal que maneja el menú interactivo"""
    while True:
        os.system('clear' if os.name != 'nt' else 'cls')
        print_banner()
        opcion = mostrar_menu()
        
        if opcion == "1":
            escaneo_rapido()
        elif opcion == "2":
            escaneo_completo()
        elif opcion == "3":
            escaneo_puertos()
        elif opcion == "4":
            monitoreo_continuo()
        elif opcion == "5":
            escaneo_vulnerabilidades()
        elif opcion == "6":
            analisis_trafico()
        elif opcion == "7":
            mapa_red()
        elif opcion == "8":
            mostrar_configuracion()
        elif opcion == "9":
            mostrar_ayuda()
        elif opcion == "0":
            print(f"\n{Fore.GREEN}[+] Gracias por usar Network Scanner. ¡Hasta pronto!{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"\n{Fore.RED}[!] Opción inválida. Intente nuevamente.{Style.RESET_ALL}")
            time.sleep(1)

def main():
    if not sys.platform.startswith('linux'):
        print(f"{Fore.RED}[!] Esta herramienta está diseñada para ejecutarse en Kali Linux{Style.RESET_ALL}")
        sys.exit(1)

    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Este script necesita privilegios de root. Ejecuta con sudo.{Style.RESET_ALL}")
        sys.exit(1)

    args = get_arguments()
    
    # Si se proporcionan argumentos, ejecutar en modo clásico
    if args.target or args.ports or args.intense or args.output:
        print_banner()
        target = args.target
        ports = args.ports
        output_file = args.output

        if not target:
            gateway = get_default_gateway()
            target = f"{gateway}/24"
            print(f"{Fore.YELLOW}[*] No se especificó objetivo. Usando red por defecto: {target}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[*] Iniciando escaneo de red...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Objetivo: {target}{Style.RESET_ALL}")
        if ports:
            print(f"{Fore.CYAN}[*] Puertos a escanear: {ports}{Style.RESET_ALL}")
        
        start_time = time.time()
        
        q = queue.Queue()
        scan_thread = threading.Thread(target=scan_network, args=(target, q))
        scan_thread.start()
        
        with tqdm(total=100, desc="Escaneando red", unit="%") as pbar:
            while scan_thread.is_alive():
                time.sleep(0.1)
                pbar.update(1)
                if pbar.n >= 100:
                    pbar.n = 0
            scan_thread.join()
        
        devices_list = q.get()
        
        if not devices_list:
            print(f"\n{Fore.RED}[!] No se encontraron dispositivos en la red{Style.RESET_ALL}")
            sys.exit(0)

        print_result(devices_list, ports, output_file)
        
        end_time = time.time()
        duration = end_time - start_time
        print(f"\n{Fore.GREEN}[+] Escaneo completado en {duration:.2f} segundos{Style.RESET_ALL}")
    else:
        # Ejecutar en modo interactivo con menú
        menu_principal()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Escaneo interrumpido por el usuario{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1) 