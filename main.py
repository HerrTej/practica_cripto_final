import base64
import json
import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


# funcion para borrar los archivos
def borrar_archivos(file):
    if os.path.exists(file):
        os.remove(file)
def write(file_write, lista_leer):
    try:
        with open(file_write, "x", encoding="utf-8", newline="") as file:
            data = []
            for item in lista_leer:
                data.append(item)
            json.dump(data, file, indent=2)
            file.close()
    except FileExistsError:
        # leer archivo
        with open(file_write, "r", encoding="utf-8", newline="") as file:
            data = json.load(file)
            file.close()
        for item in lista_leer:
            data.append(item)
        with open(file_write, "w") as file:
            json.dump(data, file, indent=2)
            file.close()


# encriptar base datos trabajadores
def encriptar_veterinarios(file_datos_veterinarios):
    # leer archivo
    with open(file_datos_veterinarios, "r", encoding="utf-8", newline="") as file:
        resultado_veterinarios = json.load(file)
        file.close()

    key = get_random_bytes(32)
    cipher_encrypt = AES.new(key, AES.MODE_CFB)
    dicc_datos = {
        "Key": b64encode(key).decode("utf-8"),
        "Cipher_encrypt.iv": b64encode(cipher_encrypt.iv).decode("utf-8")
    }
    # meter archivos key y el .iv
    with open(my_file_keys_veterinarios, "w", encoding="utf-8", newline="") as file:
        json.dump(dicc_datos, file, indent=2)
        file.close()

    # encriptar
    lista_encriptados_veterinarios = []
    for diccionario in resultado_veterinarios:
        # sacamos valores
        nombre_veterinario = diccionario.get("Nombre")
        identificador_veterinario = diccionario.get("Identificador")
        clave_veterinario = diccionario.get("Clave")
        # codificamos
        nombre_codificado_veterinario = nombre_veterinario.encode("utf-8")
        identificador_codificado_veterinario = identificador_veterinario.encode("utf-8")
        clave_codificado_veterinario = clave_veterinario.encode("utf-8")
        # encriptamos
        ciphered_bytes_nombre_veterinario = cipher_encrypt.encrypt(nombre_codificado_veterinario)
        ciphered_bytes_identificador_veterinario = cipher_encrypt.encrypt(identificador_codificado_veterinario)
        ciphered_bytes_clave_veterinario = cipher_encrypt.encrypt(clave_codificado_veterinario)

        diccionario_final_veterinarios = {
            "Nombre codificado": b64encode(ciphered_bytes_nombre_veterinario).decode("utf-8"),
            "Identificador codificado": b64encode(ciphered_bytes_identificador_veterinario).decode("utf-8"),
            "Clave codificado": b64encode(ciphered_bytes_clave_veterinario).decode("utf-8")
        }

        lista_encriptados_veterinarios.append(diccionario_final_veterinarios)

    # guardar en un archivo los datos
    write(my_file_encriptada_veterinarios,lista_encriptados_veterinarios)


# desencriptar base datos trabajadores
def desencriptar_veterinario(my_file_encriptada_veterinarios, clave_final_veterinario, nombre_veterinario):
    # leer archivo
    with open(my_file_encriptada_veterinarios, "r", encoding="utf-8", newline="") as file_leer:
        desencriptados_veterinarios = json.load(file_leer)
        file_leer.close()
    # leer archivo
    with open(my_file_keys_veterinarios, "r", encoding="utf-8", newline="") as file_key_veterinarios:
        claves_veterinarios = json.load(file_key_veterinarios)
        file_key_veterinarios.close()

    key_descifrado = claves_veterinarios.get("Key")
    iv_descirado = claves_veterinarios.get("Cipher_encrypt.iv")
    key_desencriptar = b64decode(key_descifrado)
    iv_desencriptar = b64decode(iv_descirado)
    cipher_decrypt = AES.new(key_desencriptar, AES.MODE_CFB, iv=iv_desencriptar)
    lista_desencriptados = []
    lista_nombre_veterinarios = []
    lista_claves_veterinarios = []
    contador_comprobante_veterinario = 0
    for diccionario_encriptado in desencriptados_veterinarios:

        nombre_veterinario_encriptado = diccionario_encriptado.get("Nombre codificado")
        identificador_veterinario_encriptado = diccionario_encriptado.get("Identificador codificado")
        clave_veterinario_encriptado = diccionario_encriptado.get("Clave codificado")

        nombre_veterinario_descifrado = cipher_decrypt.decrypt(b64decode(nombre_veterinario_encriptado))
        identificador_veterinario_descifrado = cipher_decrypt.decrypt(b64decode(identificador_veterinario_encriptado))
        clave_veterinario_descifrado = cipher_decrypt.decrypt(b64decode(clave_veterinario_encriptado))

        lista_nombre_veterinarios.append(nombre_veterinario_descifrado.decode("utf-8"))
        lista_claves_veterinarios.append(clave_veterinario_descifrado.decode("utf-8"))
        diccionario_final = {
            "Nombre": nombre_veterinario_descifrado.decode("utf-8"),
            "Identificador": identificador_veterinario_descifrado.decode("utf-8"),
            "Clave": clave_veterinario_descifrado.decode("utf-8")
        }
        if clave_final_veterinario == clave_veterinario_descifrado.decode(
                "utf-8") and nombre_veterinario == nombre_veterinario_descifrado.decode("utf-8"):
            contador_comprobante_veterinario += 1

        lista_desencriptados.append(diccionario_final)
    # guardar en un archivo los datos
    write(file_datos_veterinarios,lista_desencriptados)
    devolver = 2
    # if para que el trabajador pueda elegir entre ver los datos de todos
    # los clientes o los que tengan el nombre que ellos quieran
    if contador_comprobante_veterinario == 1:
        return contador_comprobante_veterinario

    if contador_comprobante_veterinario == 0:
        print("Nombre de usuario o contraseña incorrectos\n")
        return devolver


# encriptar base datos clientes
def encriptar(file_datos):
    # leer archivo
    with open(file_datos, "r", encoding="utf-8", newline="") as file:
        resultado = json.load(file)
        file.close()

    key = get_random_bytes(32) #clave aleatoria
    cipher_encrypt = AES.new(key, AES.MODE_CFB)
    dicc_datos = {
        "Key": b64encode(key).decode("utf-8"),
        "Cipher_encrypt.iv": b64encode(cipher_encrypt.iv).decode("utf-8")
    }
    # meter archivos key y el .iv
    with open(my_file_keys, "w", encoding="utf-8", newline="") as file:
        json.dump(dicc_datos, file, indent=2)
        file.close()

    # encriptar
    lista_encriptados = []
    for diccionario in resultado:
        # sacamos valores
        nombre = diccionario.get("Nombre")
        apellido = diccionario.get("Apellido")
        dni = diccionario.get("DNI")
        nombre_mascota = diccionario.get("Nombre mascota")
        especie = diccionario.get("Especie")
        diagnostico = diccionario.get("Diagnostico")
        clave_cliente = diccionario.get("Clave")
        # codificamos
        nombre_codificado = nombre.encode("utf-8")
        apellido_codificado = apellido.encode("utf-8")
        dni_codificado = dni.encode("utf-8")
        nombre_mascota_codificado = nombre_mascota.encode("utf-8")
        especie_codificado = especie.encode("utf-8")
        diagnostico_codificado = diagnostico.encode("utf-8")
        clave_cliente_codificada = clave_cliente.encode("utf-8")
        # encriptamos
        ciphered_bytes_nombre = cipher_encrypt.encrypt(nombre_codificado)
        ciphered_bytes_apellido = cipher_encrypt.encrypt(apellido_codificado)
        ciphered_bytes_dni = cipher_encrypt.encrypt(dni_codificado)
        ciphered_bytes_mascota = cipher_encrypt.encrypt(nombre_mascota_codificado)
        ciphered_bytes_especie = cipher_encrypt.encrypt(especie_codificado)
        ciphered_bytes_diagnostico = cipher_encrypt.encrypt(diagnostico_codificado)
        ciphered_bytes_clave_cliente = cipher_encrypt.encrypt(clave_cliente_codificada)
        diccionario_final = {
            "Nombre codificado": b64encode(ciphered_bytes_nombre).decode("utf-8"),
            "Apellido codificado": b64encode(ciphered_bytes_apellido).decode("utf-8"),
            "DNI codificado": b64encode(ciphered_bytes_dni).decode("utf-8"),
            "Nombre mascota codificado": b64encode(ciphered_bytes_mascota).decode("utf-8"),
            "Especie codificado": b64encode(ciphered_bytes_especie).decode("utf-8"),
            "Diagnostico codificado": b64encode(ciphered_bytes_diagnostico).decode("utf-8"),
            "Clave codificado": b64encode(ciphered_bytes_clave_cliente).decode("utf-8")

        }

        lista_encriptados.append(diccionario_final)

    # guardar en un archivo los datos
    write(my_file_encriptada, lista_encriptados)


# desencriptar base datos clientes
def desencriptar(my_file_encriptada, my_file_keys, clave_final, nombre):
    # leer archivo
    with open(my_file_encriptada, "r", encoding="utf-8", newline="") as file:
        desencriptados = json.load(file)
        file.close()
    # leer archivo
    with open(my_file_keys, "r", encoding="utf-8", newline="") as file:
        claves = json.load(file)
        file.close()

    key_descifrado = claves.get("Key")
    iv_descirado = claves.get("Cipher_encrypt.iv")
    key_desencriptar = b64decode(key_descifrado)
    iv_desencriptar = b64decode(iv_descirado)
    cipher_decrypt = AES.new(key_desencriptar, AES.MODE_CFB, iv=iv_desencriptar)
    lista_desencriptados = []
    lista_nombre = []
    lista_claves = []
    for diccionario_encriptado in desencriptados:

        nombre_encriptado = diccionario_encriptado.get("Nombre codificado")
        apellido_encriptado = diccionario_encriptado.get("Apellido codificado")
        dni_encriptado = diccionario_encriptado.get("DNI codificado")
        nombre_mascota_encriptados = diccionario_encriptado.get("Nombre mascota codificado")
        especie_encriptado = diccionario_encriptado.get("Especie codificado")
        diagnostico_encriptado = diccionario_encriptado.get("Diagnostico codificado")
        clave_cliente_encriptado = diccionario_encriptado.get("Clave codificado")

        nombre_descifrado = cipher_decrypt.decrypt(b64decode(nombre_encriptado))
        apellido_descifrado = cipher_decrypt.decrypt(b64decode(apellido_encriptado))
        dni_descifrado = cipher_decrypt.decrypt(b64decode(dni_encriptado))
        nombre_mascotas_descifrado = cipher_decrypt.decrypt(b64decode(nombre_mascota_encriptados))
        especie_descifrado = cipher_decrypt.decrypt(b64decode(especie_encriptado))
        diagnostico_descifrado = cipher_decrypt.decrypt(b64decode(diagnostico_encriptado))
        clave_cliente_descifrado = cipher_decrypt.decrypt(b64decode(clave_cliente_encriptado))
        lista_nombre.append(nombre_descifrado.decode("utf-8"))
        lista_claves.append(clave_cliente_descifrado.decode("utf-8"))
        diccionario_final = {
            "Nombre": nombre_descifrado.decode("utf-8"),
            "Apellido": apellido_descifrado.decode("utf-8"),
            "DNI": dni_descifrado.decode("utf-8"),
            "Nombre mascota": nombre_mascotas_descifrado.decode("utf-8"),
            "Especie": especie_descifrado.decode("utf-8"),
            "Diagnostico": diagnostico_descifrado.decode("utf-8"),
            "Clave": clave_cliente_descifrado.decode("utf-8")
        }
        # imprimir valores para el cliente
        lista_desencriptados.append(diccionario_final)
        if clave_final == clave_cliente_descifrado.decode("utf-8") and nombre == nombre_descifrado.decode("utf-8"):
            print("Tus datos son:")
            print("Nombre completo:", diccionario_final.get("Nombre") + " " + diccionario_final.get("Apellido"))
            print("DNI:", diccionario_final.get("DNI"))
            print("Nombre mascota:", diccionario_final.get("Nombre mascota"))
            print("Especie:", diccionario_final.get("Especie"))
            print("Diagnostico:", diccionario_final.get("Diagnostico"))
            print("\n")
        # imprimir datos nombre trabajador haya dado
        if ((
                nombre == "Veterinario1" or nombre == "Veterinario2" or nombre == "Veterinario3") and clave_final == nombre_descifrado.decode(
            "utf-8")):
            print("Los datos de este cliente son:")
            print("Nombre completo:", diccionario_final.get("Nombre") + " " + diccionario_final.get("Apellido"))
            print("DNI:", diccionario_final.get("DNI"))
            print("Nombre mascota:", diccionario_final.get("Nombre mascota"))
            print("Especie:", diccionario_final.get("Especie"))
            print("Diagnostico:", diccionario_final.get("Diagnostico"))
            print("\n")
        # imprimir datos todos los clientes
        if ((
                nombre == "Veterinario1" or nombre == "Veterinario2" or nombre == "Veterinario3") and clave_final == "todos"):
            print("Los datos del cliente son:")
            print("Nombre completo:", diccionario_final.get("Nombre") + " " + diccionario_final.get("Apellido"))
            print("DNI:", diccionario_final.get("DNI"))
            print("Nombre mascota:", diccionario_final.get("Nombre mascota"))
            print("Especie:", diccionario_final.get("Especie"))
            print("Diagnostico:", diccionario_final.get("Diagnostico"))
            print("\n")

    # guardar en un archivo los datos
    write(file_datos, lista_desencriptados)
    contador_comprobante = 0
    comprobar_nombre = 0
    for item in range(48):
        if clave_final != lista_claves[item] or nombre != lista_nombre[0]:
            contador_comprobante += 1
            comprobar_nombre = 1

    if contador_comprobante == 48 and nombre != "Veterinario1" and nombre != "Veterinario2" or nombre != "Veterinario3" and comprobar_nombre != 1:
        print("Nombre de usuario o contraseña incorrectos\n")

def new_data(file_añadir):
    with open(file_añadir, "r", encoding="utf-8", newline="") as file:
        datos = json.load(file)
        file.close()
    borrar_archivos(file_datos)
    nombre = input("Nombre de la persona que quieres añadir: ")
    apellido = input("Apellido de la persona que quieres añadir: ")
    dni = input("DNI de la persona que quieres añadir: ")
    nombre_mascota = input("Nombre de la mascota que quieres añadir: ")
    especie = input("Especie de la macota que quieres añadir: ")
    diagnostico = input("Diagnostico que quieres añadir: ")
    clave_determinada = bytes(input("Clave predeterminada que quieres añadir: "), "utf-8")
    hash_inicial = SHA256.new(clave_determinada)
    clave_final = hash_inicial.hexdigest()
    diccionario ={
            "Nombre": nombre,
            "Apellido": apellido,
            "DNI": dni,
            "Nombre mascota": nombre_mascota,
            "Especie": especie,
            "Diagnostico": diagnostico,
            "Clave": clave_final
    }


    datos.append(diccionario)
    write(file_datos, datos)
    encriptar(file_datos)
    borrar_archivos(file_datos)
    clave_final = "firmar"
    nombre = "Veterinario1"
    desencriptar(my_file_encriptada, my_file_keys, clave_final, nombre)
    borrar_archivos(my_file_encriptada)
    firmar(file_datos)


def firmar(file_firmar):
    borrar_archivos(file_signatures)
    with open(file_firmar, "r", encoding="utf-8", newline="") as file:
        datos = json.load(file)
        file.close()
    contador = 0
    lista_diccionarios = []
    encriptar(file_datos)
    borrar_archivos(file_datos)
    for item in datos:
        res_bytes = json.dumps(item).encode('utf-8')
        key_private1 = open("./A/Akey.pem", "rb").read()
        private_key = RSA.importKey(key_private1, passphrase="hola")
        signer = PKCS1_v1_5.new(private_key)
        # Cifrado hash
        digest = SHA256.new(res_bytes)
        # Aquí para firma digital
        sign = signer.sign(digest)
        signature = b64encode(sign).decode("utf-8")
        diccionario = {
            "Cliente": contador,
            "Firma": signature,
        }
        contador += 1
        lista_diccionarios.append(diccionario)

    with open(file_signatures, 'w') as fp1:
        json.dump(lista_diccionarios, fp1, indent=2)
        file.close()
    print("Ha añadido un diagnostico y ha sido firmado con su firma digital")


def validar(file_datos_validar,persona,nombre):
    with open(file_datos_validar, "r", encoding="utf-8", newline="") as file:
        datos = json.load(file)
        file.close()
    with open(file_signatures, "r", encoding="utf-8", newline="") as file:
        datos_firmas = json.load(file)
        file.close()
    encriptar(file_datos)
    borrar_archivos(file_datos)
    if nombre == "Validar":
        public_key = open("./A/Acert.pem", "rb").read()
        # public_key = open("./A/ac1cert.pem", "rb").read()
        public_key2 = RSA.importKey(public_key)
        verifier = PKCS1_v1_5.new(public_key2)
    elif nombre == "Validar2":
        public_key = open("./A/ac1cert.pem", "rb").read()
        public_key2 = RSA.importKey(public_key)
        verifier = PKCS1_v1_5.new(public_key2)

    for item in datos_firmas:
        if int(item.get("Cliente")) == persona:
            firma = item.get("Firma")
            # signature = b64decode(firma)
            # firma_decode = signature.decode("utf-8")
            # nombre_descifrado.decode("utf-8")
            # signature = b64decode(firma_decode)
            comprobante = persona

    diccionario = datos[comprobante]
    res_bytes = json.dumps(diccionario).encode('utf-8')
    digest = SHA256.new(res_bytes)
    # Assumes the data is base64 encoded to begin with
    is_verify = verifier.verify(digest, base64.b64decode(firma))
    if is_verify == True:
        print( "El diagnostico de la Persona "+str(persona), "ha sido firmada por el Veterinario 1" )
    else:
        print("El diagnostico de la Persona " + str(persona), "no ha sido firmado por el Veterinario 2")





# archivos utilizados
my_file_keys = "keys.json"
my_file_encriptada = "base_encriptada.json"
file_datos = "base_datos.json"
file_datos_veterinarios = "veterinarios.json"
my_file_keys_veterinarios = "keys_veterinarios.json"
my_file_encriptada_veterinarios = "base_encriptada_veterinarios.json"
file_signatures = "signatures.json"

# ejecución del porgrama
texto = "si"
while texto == 'si':

    nombre = input("Nombre: ")
    if  nombre == "Validar":
        persona = int(input("Persona que quieres comprobar la firma: "))
        clave_final = "Validar"
        nombre = "Veterinario1"
        desencriptar(my_file_encriptada, my_file_keys, clave_final, nombre)
        borrar_archivos(my_file_encriptada)
        nombre = "Validar"
        validar(file_datos, persona, nombre)
        texto = input("Escriba SI para continuar y NO para salir: ").lower()

    elif nombre == "Validar2":
        persona = int(input("Persona que quieres comprobar la firma: "))
        clave_final = "Validar"
        nombre = "Veterinario1"
        desencriptar(my_file_encriptada, my_file_keys, clave_final, nombre)
        borrar_archivos(my_file_encriptada)
        nombre = "Validar2"
        validar(file_datos, persona,nombre)
        texto = input("Escriba SI para continuar y NO para salir: ").lower()
    else:
        clave = bytes(input("Indica tu contraseña: "), "utf-8")
        # usar algoritmo SHA256 para hacer hash a la contraseña escrita por el usuario
        hash_inicial = SHA256.new(clave)
        clave_final = hash_inicial.hexdigest()
        # clave vetX es es un numero del 1 al 3
        if nombre == "Veterinario1" or nombre == "Veterinario2" or nombre == "Veterinario3":
            comprobar = 0
            comprobar1 = desencriptar_veterinario(my_file_encriptada_veterinarios, clave_final, nombre)
            borrar_archivos(my_file_encriptada_veterinarios)
            encriptar_veterinarios(file_datos_veterinarios)
            borrar_archivos(file_datos_veterinarios)
            if comprobar1 != 2:
                comprobar = desencriptar_veterinario(my_file_encriptada_veterinarios, clave_final, nombre)
                borrar_archivos(file_datos_veterinarios)
            # preguntar si quieres ver datos todos clientes o de uno solo
            if comprobar == 1:
                cliente_datos = input(
                    "¿De que cliente quiere ver los datos?(escriba su nombre), si quiere ver todos, escriba todos y si quiere añadir un nuevo diagnostico escriba añadir ")
                # imprimir dato todos los clientes
                if cliente_datos == "todos":
                    clave_final = cliente_datos
                    desencriptar(my_file_encriptada, my_file_keys, clave_final, nombre)
                    borrar_archivos(my_file_encriptada)
                    encriptar(file_datos)
                    borrar_archivos(file_datos)
                #añadir un nuevo cliente
                elif cliente_datos == "añadir":
                    clave_final = cliente_datos
                    desencriptar(my_file_encriptada, my_file_keys, clave_final, nombre)
                    borrar_archivos(my_file_encriptada)
                    new_data(file_datos)
                # imprimir datos de un cliente
                else:
                    clave_final = cliente_datos
                    desencriptar(my_file_encriptada, my_file_keys, clave_final, nombre)
                    borrar_archivos(my_file_encriptada)
                    encriptar(file_datos)
                    borrar_archivos(file_datos)



        else:
            # claves = personaXX XX es un número del 0 al 48 incluidos
            desencriptar(my_file_encriptada, my_file_keys, clave_final, nombre)
            borrar_archivos(my_file_encriptada)
            encriptar(file_datos)
            borrar_archivos(file_datos)
        # repite el bucle while si el usuario pone si y cuando pone no se finaliza el programa
        texto = input("Escriba SI para continuar y NO para salir: ").lower()


# XXXXXXXXY