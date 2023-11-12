import os
import argparse
import subprocess
import logging
from datetime import datetime

from Modulos import Funciones
from Modulos import scanner_ports
from Modulos import webscrap

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                    filename="loggin.log")
logger = logging.getLogger(__name__)

def validatepath(directorio):
        
        if not os.path.exists(directorio):
                raise argparse.ArgumentTypeError("El directorio no existe")
        
        if os.access(directorio, os.R_OK):
                return directorio
        
        else:
                raise argparse.ArgumentTypeError("El directorio no se puede leer")

def parse_args():
    parser = argparse.ArgumentParser(description='Ejecuta uno de los modulos disponibles.\n'
                                     '- encriptado\n'
                                     '- scan\n'
                                     '- webscrap\n'
                                     '- email\n'
                                     '- hash\n'
                                     '- busqueda',formatter_class=argparse.RawTextHelpFormatter)

    subparsers = parser.add_subparsers(dest='module', help='Seleccionar el módulo a ejecutar.')
    #Encriptado
    parser_encriptado = subparsers.add_parser("encriptado", description="Modulo de encriptacion de un mensaje\n"
                                            "Ejemplo de uso:\n"
                                            "   - py main.py encriptado -mens Mensaje a encriptar -clave Clave para la encriptación(opcional)")
    parser_encriptado.add_argument("-mens", dest="mens", help="Mensaje a encriptar")
    parser_encriptado.add_argument("-clave", dest="clave", help="Palabra clave para cifrar", default="TILIN")

    #Envio de mail
    parser_mail = subparsers.add_parser("email", description="Modulo de envio de correo\n"
                                                "Ejemplo de uso:\n"
                                                "    - py main.py mail -remitente example@x.com -destinatario x@y.com\n"
                                                "    -cc Contraseña de aplicacion -asunto Asunto del correo"
                                                "    -correo Cuerpo del correo",
                                                formatter_class=argparse.RawTextHelpFormatter)
    parser_mail.add_argument("-remitente", dest="remitente", type=str, help="Correo que envia el mensaje")
    parser_mail.add_argument("-destinatario", dest="destinatario", type=str, help="Correo objetivo")
    parser_mail.add_argument("-cc", dest="cc", type=str, help="Contraseña de correo")
    parser_mail.add_argument("-asunto", dest="asunto", type=str, help="El asunto del correo")
    parser_mail.add_argument("-correo", dest="correo", help="Cuerpo del correo")

    #Valor hash de un directorio
    parser_hash = subparsers.add_parser("hash", description="Modulo para obtener valor hash de un directorio\n"
                                                        "Ejemplo de uso:\n"
                                                        "       - py main.py hash -b Nombre de archivo base + .pickle"
                                                        "       -p Directorio objetivo"
                                                        "       -t Archivo temporal",
                                                        formatter_class=argparse.RawTextHelpFormatter)
    parser_hash.add_argument("-b", dest="baseline", help="Archivo base")
    parser_hash.add_argument("-p", dest="path", type=validatepath, help="Objetivo a buscar hash")
    parser_hash.add_argument("-tmp", dest="tmp", help="Archivo temporal")

    #web scrapping
    parser_busqueda = subparsers.add_parser("busqueda", help="")
    parser_busqueda.add_argument("busqueda", help="Palabra a buscar")

    # Subparser para el módulo de escaneo de puertos
    parser_scan = subparsers.add_parser('scan', description='ESTAS EJECUTANDO EL MODULO DE ESCANEO DE PUERTOS\n'
                                                 'Ejemplos de uso:\n'
                                                 '   - py main.py scan  192.168.1.1 -sh  /// Escaneo de red, regresa todos los hosts activos\n'
                                                 '   - py main.py scan  192.168.1.1 -sp  /// Escaneo simple de puertos, solo los primeros 1024\n'
                                                 '   - py main.py scan 192.168.1.1 -sp -p 80,443 -o Reporte.txt /// Escaneo a los puertos dados, se guarda en un txt\n'
                                                 '   - py main.py scan  192.168.1.1 -sp -p- -V -o Reporte.txt  /// Escaneo completo a todos los puertos, determina sus productos y versiones, lo guarda en un txt\n',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser_scan.add_argument('ip', help='Dirección IP a escanear.')
    parser_scan.add_argument('--scan_ports', '-sp', action='store_true', help='Realizar escaneo simple de puertos.')
    parser_scan.add_argument('--scan_hosts', '-sh', action='store_true', help='Realizar escaneo de hosts en la red.')
    parser_scan.add_argument('--Version', '-V', action='store_true', help='Escaneo de productos y versiones de puertos')
    parser_scan.add_argument('--output_file', '-o', help='Nombre del archivo de salida (formato TXT).')
    parser_scan.add_argument('--ports', '-p', help='Puertos a escanear. Ejemplo: 80,443 o 100-500')
    parser_scan.add_argument('--allports', '-p-', action='store_true', help='Todos los puertos')


    # Subparser para el módulo de análisis web
    parser_webscrap = subparsers.add_parser('webscrap', description='ESTAS EJECUTANDO EL MODULO DE ANALISIS WEB\n'
                                                 'Ejemplos de uso:\n'
                                                 '   - py main.py webscrap http://example.com -o WebReport.txt /// Obtiene informacion basica del target y la guarda en un txt\n'
                                                 '   - py main.py webscrap http://example.com -tec -email -o WebReport.txt /// Obtiene las tecnologias usadas y correos electronicos\n'
                                                 '   - py main.py webscrap http://example.com -sbn -port 80 -o WebReport.txt /// Obtiene la informacion del banner del servidor\n',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser_webscrap.add_argument('target', help='Dirección del servidor web')
    parser_webscrap.add_argument('-tec', '--tecnologias', action='store_true', help='Obtener información sobre tecnologías utilizadas.')
    parser_webscrap.add_argument('-sbn', '--banner', action='store_true', help='Obtener el banner del servidor.')
    parser_webscrap.add_argument('-email', '--correos', action='store_true', help='Buscar correos electrónicos en la página web.')
    parser_webscrap.add_argument('-p', '--puerto', type=int, default=80, help='Puerto del servidor web (predeterminado: 80).')
    parser_webscrap.add_argument('--output_file', '-o', help='Nombre del archivo de salida (formato TXT).')

    return parser.parse_args()

if __name__ == "__main__":
    #verificar_instalar_dependencias()

    try:
        params = parse_args()
        module_to_run = params.module

        if module_to_run == "encriptado":
            Funciones.encriptado(params.mens, params.clave)
        elif module_to_run == "hash":
            Funciones.obt_hash(params.baseline, params.path, params.tmp)
        elif module_to_run == "email":
            Funciones.envio_correo(params.remitente, params.cc, params.destinatario, params.asunto, params.correo)
        elif module_to_run == "busqueda":
            Funciones.busqueda(params.busqueda)
        elif module_to_run == "scan":
            scanner_ports.scan(params.ip, params)
        elif module_to_run == "webscrap":
            webscrap.web(params.target, params)
        else:
            logger.error(f'Modulo no reconocido: {module_to_run}')
            print(f"Módulo no reconocido: {module_to_run}")

    except argparse.ArgumentError as e:
        logger.error(f'Error en los argumentos: {e}')
        print(f"Error en los argumentos: {e}")

    except Exception as e:
        logger.error(f'Error durante la ejecución: {e}')

