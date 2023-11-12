import os
import logging
import datetime
import socket



current_datetime = datetime.datetime.now()
formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                    filename="loggin.log")
logger = logging.getLogger(__name__)

try:
    import builtwith
    import requests
    import re
    from urllib.parse import urlparse
    import whois
    import gzip
except ImportError:
    #os.system("pipreqs ./")
    logger.error('Error al importar las librerias')
    logger.info('Instalando librerias faltantes')
    os.system("pip install pipreqs")
    os.system("pip install -r requirements.txt")
    exit()




def save_to_report(report_filename,ip_info,infodomain,tecno,banner,emails):
    with open(report_filename, 'w') as file:
        file.write("#"*25+f" INFORME GENERADO EL {formatted_datetime} "+"#"*25+"\n")
        file.write(f"\n"+"#"*25+" INFORMACION OBTENIDA DE SHODAN "+"#"*25+"\n")
        file.write(f"IP: {ip_info['ip']}\n")
        file.write(f"Puertos abiertos: {', '.join(map(str, ip_info['ports']))}\n")
        file.write(f"CPEs: {', '.join(ip_info['cpes'])}\n")
        file.write(f"Hostnames: {', '.join(ip_info['hostnames'])}\n")
        file.write(f"Tags: {', '.join(ip_info['tags'])}\n")
        file.write(f"Vulnerabilidades: {', '.join(ip_info['vulns'])}\n")
        if isinstance(infodomain, dict):
            file.write(f"\n"+"#"*25+" INFORMACION DEL DOMINIO "+"#"*25+"\n")
            for key, value in infodomain.items():
                file.write(f"{key}: {value}\n")
        else:
            file.write(infodomain)
        if tecno:
            file.write(f"\n"+"#"*25+" TECNOLOGIAS ENCONTRADAS "+"#"*25+"\n")
            for category, technologies in tecno.items():
                file.write(f'{category.capitalize()}:\n')
                for tech in technologies:
                    file.write(f'  - {tech}\n')
        if banner:
            file.write("\n"+"#"*25+" INFORMACION DEL BANNER SERVER "+"#"*25+f"\n{banner}")
        if emails:
            file.write(f"\n"+"#"*25+" CORREOS ELECTRONICOS ENCONTRADOS "+"#"*25+"\n")
            for email in emails:
                file.write(f'  - {email}\n')

def obtener_informacion_whois(dominio):
    try:
        informacion = whois.whois(dominio)
        return informacion
    except whois.parser.PywhoisError as e:
        logger.error(f'Error al obtener información WHOIS: {e}')
        return f'Error al obtener información WHOIS: {e}'
    
def obtener_info_shodan(ip_objetivo):
    try:
        # Realizar la solicitud a la API de Shodan
        url = f"https://internetdb.shodan.io/{ip_objetivo}"
        respuesta = requests.get(url)
        # Verificar si la solicitud fue exitosa (código de estado 200)

        if respuesta.status_code == 200:
            # Convertir la respuesta JSON a un diccionario
            ip_info = respuesta.json()
            # Imprimir la información obtenida
            return ip_info

        else:
            print(f"Error en la solicitud. Código de estado: {respuesta.status_code}")
            print(f"Respuesta completa: {respuesta.text}")
    except Exception as e:
        logger.error(f"Error: {e}")

def obtener_tecnologias(url):
    try:
        # Utiliza el módulo builtwith para obtener información sobre las tecnologías
        result = builtwith.builtwith(url)

        # Algunos servidores pueden comprimir la respuesta, intenta descomprimir
        if isinstance(result, bytes):
            result = gzip.decompress(result).decode('utf-8')
            result = builtwith.parse(result)

        return result

    except Exception as e:
        logger.error(f'Error al obtener tecnologías: {e}')
        return None

def obtener_banner(target, port):
    s = socket.socket()
    try:
        # Establecer un tiempo de espera para la conexión
        s.settimeout(2)
        # Conectar al servidor en el puerto especificado
        s.connect((target, port))
        # Enviar una solicitud HTTP básica para obtener el banner
        s.sendall(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
        # Recibir la respuesta del servidor
        banner = s.recv(1024).decode('utf-8')
        return banner
    except socket.timeout:
        logger.error('Tiempo de espera agotado al conectar al servidor.')
        return 'Tiempo de espera agotado al conectar al servidor.'
    except socket.error as e:
        logger.error(f'Error de conexión: {e}')
        return f'Error de conexión: {e}'
    finally:
        # Cerrar la conexión
        s.close()

def buscar_correos(url):
    try:
        # Realizar la solicitud GET a la página web
        response = requests.get(url)
        response.raise_for_status()  # Verificar si hay errores en la solicitud

        # Utilizar una expresión regular para encontrar direcciones de correo electrónico
        pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        matches = pattern.findall(response.text)
        # Eliminar duplicados utilizando un conjunto
        unique_emails = set(matches)
    except requests.RequestException as e:
        logger.error(f'Error al realizar la solicitud: {e}')
    except Exception as e:
        logger.error(f'Error inesperado: {e}')
    return unique_emails

def web(target,args):
    banner=None
    emails=None
    tecno=None

    #Extraer el dominio de la url dada
    domain = urlparse(target).netloc
    logger.info(f'Dominio obtenido {domain}')

    # Llama a la función para realizar la consulta de DNS
    try:
        # Realizar la consulta de DNS
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        logger.error(f'Error al realizar la consulta de DNS:{e}')
        print(f"Error al realizar la consulta de DNS: {e}")
    #
    ip_info=obtener_info_shodan(ip)

    informacion = obtener_informacion_whois(domain)
    logger.info(f'Ip obtenida de la consulta DNS {ip}')


    if args.tecnologias:
        tecno=obtener_tecnologias(target)
    if args.banner:
        banner = obtener_banner(domain, args.puerto)
    if args.correos:
        emails=buscar_correos(target)
    if args.output_file:
            # Retrocede un nivel para obtener el directorio padre
            directorio_reportes = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Reportes')
            # Verificar si el directorio "Reportes" existe
            if not os.path.exists(directorio_reportes):
                # Crear el directorio si no existe
                os.makedirs(directorio_reportes)
            ruta_reporte = os.path.join(directorio_reportes, args.output_file)
            save_to_report(ruta_reporte,ip_info,informacion,tecno,banner,emails)
        
if __name__ == "__main__":
    # Ejecutar la función solo si el script se ejecuta directamente
    web()