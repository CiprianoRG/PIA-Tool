# PIA-Tool

- FRANCISCO ABBAD RAMIREZ GOMEZ
- JESUS PONCE DE LEON MOTA
- LUIS CIPRIANO RODRIGUEZ GONZALEZ

## Descripción

Proyecto de programación que incluye varias herramientas para ciberseguridad, entre ellas:
- Escaneo de puertos
- Webscraping
- Encriptado
- Hashes
- Envío de correos

## Modo de Uso

A continuación, se detalla el modo de uso de cada herramienta:

### Escaneo de Puertos

Ejemplos de uso:
   - py main.py scan  192.168.1.1 -sh  /// Escaneo de red, regresa todos los hosts activos
   - py main.py scan  192.168.1.1 -sp  /// Escaneo simple de puertos, solo los primeros 1024
   - py main.py scan 192.168.1.1 -sp -p 80,443 -o Reporte.txt /// Escaneo a los puertos dados, se guarda en un txt
   - py main.py scan  192.168.1.1 -sp -p- -V -o Reporte.txt  /// Escaneo completo a todos los puertos, determina sus productos y versiones, lo guarda en un txt
     
### Webscraping
Argumentos:
  target     Dirección del servidor web (argumento posicional)
  -tec      Obtener información sobre tecnologías utilizadas.
  -sbn      Obtener informacion del banner del servidor.
  -p            Puerto del servidor web (predeterminado: 80).
  -email     Buscar correos electrónicos en la página web.
  -o            Nombre del archivo de salida (formato TXT). ---> Unica forma de salida

Ejemplos de uso:
   - py main.py webscrap http://example.com -o WebReport.txt /// Obtiene informacion basica del target y la guarda en un txt
   - py main.py webscrap http://example.com -tec -email -o WebReport.txt /// Obtiene las tecnologias usadas y correos electronicos
   - py main.py webscrap http://example.com -sbn -port 80 -o WebReport.txt /// Obtiene la informacion del banner del servidor
     
### Encriptado

 Ejemplo de uso: 
    - py main.py encriptado -mens "Mensaje a encriptar" -clave Clave para la encriptación(opcional)
   
### Hashes

Ejemplo de uso:
       - py main.py hash -b Nombre de archivo base + .pickle       -p Directorio objetivo       -t Archivo temporal
       
### Envío de Correos

Ejemplo de uso:
    - py main.py mail -remitente example@x.com -destinatario x@y.com -cc Contraseña de aplicacion -asunto Asunto del correo  -correo Cuerpo del correo

