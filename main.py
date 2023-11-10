import argparse
from Modulos import webscrap
from Modulos import scanner_ports
import logging

def parse_args():
    parser = argparse.ArgumentParser(description='Ejecutar módulo de escaneo de puertos o análisis web.')

    subparsers = parser.add_subparsers(dest='module', help='Seleccionar el módulo a ejecutar.')

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
    args = parse_args()
    module_to_run = args.module

    if module_to_run == 'scan':
        # Lógica para ejecutar el módulo de escaneo de puertos
        scanner_ports.scan(args.ip, args)
    elif module_to_run == 'webscrap':
        # Lógica para ejecutar el módulo de análisis web
        if args.tecnologias or args.banner or args.correos:
            webscrap.web(args.target, args)
        else:
            print('Por favor, seleccione al menos una opción: -tec, -sbn, o -email.')
    else:
        print('Por favor, seleccione un módulo válido: scan o webscrap.')


