import os
try:
    from googlesearch import search
    import  subprocess, pickle, openpyxl, lxml, socket
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

except ImportError:
    #os.system("pipreqs ./")
    os.system("pip install pipreqs")
    os.system("pip install -r requirements.txt")
    exit()


def crear_guardar(destino, archivo, contenido):
    os.makedirs(destino, exist_ok=True)
    with open(os.path.join(destino, archivo), "w") as file:
        file.write(contenido)
        


def busqueda(query):
    try:
        results = []
        for enlace in search(query, tld="com", num=15, stop=15, pause=5):
            results.append(enlace)
        directorio = os.getcwd()
        directorio = directorio + "\Busquedas"
        os.makedirs(directorio, exist_ok=True)

        wb = openpyxl.Workbook()
        sheet = wb.active
        c1 = sheet.cell(row=1, column=1)
        c1.value = "Busquedas"
        posicion = 1
        for busquedas in results:
            celda = sheet.cell(row=(posicion + 1), column=1)
            el = busquedas
            celda.value = busquedas
            posicion += 1
        ruta = directorio + "\Busquedas.xlsx"
        wb.save(ruta)
    except:
        pass
        


def encriptado(message, clave):
    try:

        espacios = 1
        while espacios > 0:
            espacios = clave.count(" ")
            if clave.isalpha() == False:
                espacios += 1
        key = len(clave)

        translated = ""
        simbolos = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789 !?."

        for symbol in message:
            if symbol in simbolos:

                symbolindex = simbolos.find(symbol)
                transtaledindex = symbolindex + key

                if transtaledindex >= len(simbolos):

                    transtaledindex = transtaledindex - len(simbolos)

                elif transtaledindex < 0:

                    transtaledindex = transtaledindex + len(simbolos)

                translated = translated + simbolos[transtaledindex]

            else:
            
                translated = translated + symbol
    
        directorio = os.getcwd()
        directorio = directorio + "\Encriptado"
        crear_guardar(directorio, "Resultado.txt", translated)

    except:
        pass

def envio_correo(remite, contrasena, destinatario, asunto, mensaje):
    
    try:

        # Crea el objeto MIME
        msg = MIMEMultipart()
        msg['From'] = remite
        msg['To'] = destinatario
        msg['Subject'] = asunto

        # Agrega el mensaje al cuerpo del correo
        msg.attach(MIMEText(mensaje, 'plain'))

        # Conecta al servidor SMTP de Gmail
        servidor_smtp = smtplib.SMTP('smtp.gmail.com', 587)
        servidor_smtp.starttls()

        # Inicia sesión en tu cuenta de Gmail
        servidor_smtp.login(remite, contrasena)

        # Envía el correo
        servidor_smtp.sendmail(remite, destinatario, msg.as_string())

        # Cierra la conexión al servidor SMTP
        servidor_smtp.quit()

    except:
        pass

def obt_hash(basefile, objetivo, tmpfile):

    
    try:
        directorio = os.getcwd()
        directorio += "\Hash"
        os.makedirs(directorio, exist_ok=True)
        with open(os.path.join(directorio, tmpfile), "w") as file:
            file.write("")
        temporalfile = "Hash\\" + tmpfile

        contenido = """param(
            [string]$TargetFolder="c:\windows\system32\drivers\",
            [string]$ResultFile="baseline.txt"
        )

        Get-ChildItem $TargetFolder | Get-FileHash | Select-Object -Property Hash, Path | Format-Table -HideTableHeaders | Out-File $ResultFile -Encoding ascii
        """
        with open(os.path.join(directorio, "HashAcquire.ps1"), "w") as file:
            file.write(contenido)
        
        command = "powershell -ExecutionPolicy ByPass -File Hash\HashAcquire.ps1 -TargetFolder \""+ objetivo + "\" -ResultFile \"" + temporalfile +"\""

        powerShellResult = subprocess.run(command, stdout=subprocess.PIPE)
        
        if powerShellResult.stderr == None:
        
            baseDict = {}

            with open(os.paht.join(directorio,tmpfile), "r") as inFile:
                for eachLine in inFile:
                    lineList = eachLine.split()
                    if len(lineList) == 2:
                        hashValue = lineList[0]
                        fileName = lineList[1]
                        baseDict[hashValue] = fileName
                    else:
                        continue

            with open(os.path.join(directorio, basefile), "wb") as outFile:
                pickle.dump(baseDict, outFile)
                
        
        else:
            pass
    
    except Exception:
        pass
        






