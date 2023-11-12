import socket
import threading
import nmap
import datetime
import os
import logging

DEFAULT_PORTS = list(range(1, 1024))
TIMEOUT = 1
THREAD_COUNT = 50  # Número de hilos
current_datetime = datetime.datetime.now()
formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                    filename="loggin.log")


def save_to_report(report_filename, ports,hosts,version):
    with open(report_filename, 'w') as file:
        file.write(f"### INFORME GENERADO EL {formatted_datetime} ###\n")
        if hosts:
            file.write("### HOSTS ACTIVOS EN LA RED ###\n")
            for host, host_name in hosts:
                file.write(f"Host: {host} ({host_name}) está activo (respondió al ping)\n")
        if ports:  
            # Escribir información general
            file.write("\n### RESULTADO DEL ESCANEO DE PUERTOS ###\n")
            file.write("{:<10} {:<10}\n".format("Puerto", "Estado"))
            file.write("="*25 + "\n")
            # Escribir información específica de los puertos abiertos
            for port in ports:
                file.write("{:<10} {:<10}\n".format(port, "Abierto"))
        if version:
            file.write("\n### ESCANEO DE PRODUCTOS Y VERSIONES DE LOS PUERTOS ###")
            file.write("\n{:<15} {:<10} {:<15} {:<15} {:<30} {:<15}".format("Host", "Puerto", "Estado", "Nombre", "Producto", "Versión"))
            file.write("="*102)  # Línea separadora
            for result in version:
                file.write("\n{:<15} {:<10} {:<15} {:<15} {:<30} {:<15}".format(result['host'], result['port'], result['state'], result['name'],result['product'], result['version']))


def parse_ports(ports):
    if '-' in ports:
        start, end = map(int, ports.split('-'))
        return list(range(start, end + 1))
    else:
        return [int(p) for p in ports.split(',')]

def scan_ports(target_ip, ports, open_ports):
    try:
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(TIMEOUT)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
    except Exception as e:
        print(f"Error en el hilo: {e}")


def scan_hosts(target_ip):
    active_hosts = []
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target_ip, arguments='-sn')
    for host in scanner.all_hosts():
        try:
            host_name, _, _ = socket.gethostbyaddr(host)
        except socket.herror:
            host_name = "Desconocido"
        active_hosts.append((host, host_name))
    return active_hosts

def full_scan_ports(target_ip):
    # Escaneo para obtener puertos abiertos
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments=f'-sS --min-rate 800 -n -p- -open -Pn')
    
    open_ports = [int(port) for scanned_host in scanner.all_hosts() if 'tcp' in scanner[scanned_host]
                  for port, info in scanner[scanned_host]['tcp'].items() if info.get('state') == 'open']
    return open_ports

def scan_versions(target_ip, ports):
    if not ports:
        print('No se han especificado puertos para escanear versiones.')
        return []
    
    port_argument_version = f'-p {",".join(map(str, ports))}'    
    # Crear un nuevo objeto nmap.PortScanner() para el escaneo de versiones
    scanner_version = nmap.PortScanner()

    # Escaneo para obtener información sobre los servicios (versiones)
    scanner_version.scan(target_ip, arguments=f'-sV -n {port_argument_version} -Pn')

    results = []
    for scanned_host in scanner_version.all_hosts():
        if 'tcp' in scanner_version[scanned_host]:
            for port, info in scanner_version[scanned_host]['tcp'].items():
                if info.get('state') == 'open':
                    service_info = {
                        'host': scanned_host,
                        'port': int(port),
                        'state': info.get('state', 'Desconocido'),
                        'name': info.get('name') or 'Desconocido',
                        'product': info.get('product') or 'Desconocido',
                        'version': info.get('version') or 'Desconocido',
                    }
                    results.append(service_info)
    if not results:
        print('No se encontraron servicios con versiones en los puertos especificados.')
    return results


####PROGRAMA PRINCIPAL
def scan(ip,args):
    open_ports = [] #Aqui se guardan los puertos encontrados
    versiones = [] #Aqui se guardan los resultados del escaneo de versiones
    active_hosts = [] #Aqui se guardan los hosts encontrados
    logger = logging.getLogger(__name__)

    try:
        if args.scan_hosts:
            network_to_scan = '.'.join(ip.split('.')[:-1]) + '.0/24'
            logger.info(f'Iniciando escaneo de hosts en la red...{network_to_scan}')
            active_hosts = scan_hosts(network_to_scan)
            logger.info('Escaneo de hosts completado.')

        if args.scan_ports and (args.allports):
            logger.info(f'Iniciando escaneo de todos los puertos...{ip}')
            open_ports=full_scan_ports(ip)
            logger.info(f'Escaneo de todos los puertos completado. Puertos abiertos: {open_ports}')

        elif args.scan_ports and not(args.allports):
            print('Estas haciendo un escaneo simple')
            ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
            threads = []
            thread_count = min(THREAD_COUNT, len(ports)) #ahora la cantidad de hilos se determina de forma dinamica dependiendo la cantidad de puertos
            # Dividir la lista de puertos en partes para distribuir entre hilos
            port_chunks = [ports[i:i + len(ports) // thread_count] for i in range(0, len(ports), len(ports) // thread_count)]
        
            try:
                # Crear y ejecutar hilos
                for chunk in port_chunks:
                    thread = threading.Thread(target=scan_ports, args=(ip, chunk, open_ports))
                    threads.append(thread)
                    thread.start()

                # Esperar a que todos los hilos terminen
                for thread in threads:
                    thread.join()

            except Exception as e:
                logger.error(f'Error: {e}')
        elif not(args.scan_hosts) and not(args.scan_ports):
            print("Selecciona al menos una opción: -sp para escaneo de puertos o -sh para escaneo de hosts.")
            logger.warning('No se seleccionaaron argumentos validos')


### Escaneo de Versiones
        if args.Version:
            if open_ports:
                # Realizar escaneo de versiones usando open_ports
                versiones = scan_versions(ip, open_ports)
            elif args.ports:
                # Realizar escaneo de versiones usando ports
                ports = parse_ports(args.ports) if args.ports else print('Necesitas ingresar puertos para escanear sus versiones')
                versiones = scan_versions(ip, ports)

##### Desde aqui se manda a crear el archivo de reporte
        if args.output_file:
            # Retrocede un nivel para obtener el directorio padre
            directorio_reportes = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Reportes')
            # Verificar si el directorio "Reportes" existe
            if not os.path.exists(directorio_reportes):
                # Crear el directorio si no existe
                os.makedirs(directorio_reportes)
            ruta_reporte = os.path.join(directorio_reportes, args.output_file)
            save_to_report(ruta_reporte,open_ports,active_hosts,versiones)
            
    except Exception as e:
        logger.error(f'Error durante la ejecución: {e}')
    except KeyboardInterrupt:
        logger.warning('Proceso interrumpido por el usuario. Saliendo...')

if __name__ == "__main__":
    # Ejecutar la función solo si el script se ejecuta directamente
    scan()
