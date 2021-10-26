import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pathlib import Path
import os


def borrar_archivos(file):
    if os.path.exists(file):
        os.remove(file)
my_file_keys = str(Path.home()) + "/PyCharmProjects/practica_cripto_final/keys.json"
my_file_encriptada = str(Path.home()) + "/PyCharmProjects/practica_cripto_final/base_encriptada.json"
file_datos = str(Path.home()) + "/PyCharmProjects/practica_cripto_final/base_datos.json"


borrar_archivos(my_file_keys)
borrar_archivos(my_file_encriptada)

with open(file_datos, "r", encoding="utf-8", newline="") as file:
    resultado = json.load(file)
    file.close()

key = get_random_bytes(32)
cipher_encrypt = AES.new(key, AES.MODE_CFB)
dicc_datos = {
    "Key": b64encode(key).decode("utf-8"),
    "Cipher_encrypt.iv": b64encode(cipher_encrypt.iv).decode("utf-8")
}
# meter archivos key y el .iv
with open(my_file_keys, "w", encoding="utf-8", newline="") as file:
    json.dump(dicc_datos, file, indent=2)
    file.close()

lista_encriptados = []
for diccionario in resultado:
    # sacamos valores
    nombre = diccionario.get("Nombre")
    apellido = diccionario.get("Apellido")
    dni = diccionario.get("DNI")
    nombre_mascota = diccionario.get("Nombre mascota")
    especie = diccionario.get("Especie")
    diagnostico = diccionario.get("Diagnostico")
    # codificamos
    nombre_codificado = nombre.encode("utf-8")
    apellido_codificado = apellido.encode("utf-8")
    dni_codificado = dni.encode("utf-8")
    nombre_mascota_codificado = nombre_mascota.encode("utf-8")
    especie_codificado = especie.encode("utf-8")
    diagnostico_codificado = diagnostico.encode("utf-8")
    # encriptamos
    ciphered_bytes_nombre = cipher_encrypt.encrypt(nombre_codificado)
    ciphered_bytes_apellido = cipher_encrypt.encrypt(apellido_codificado)
    ciphered_bytes_dni = cipher_encrypt.encrypt(dni_codificado)
    ciphered_bytes_mascota = cipher_encrypt.encrypt(nombre_mascota_codificado)
    ciphered_bytes_especie = cipher_encrypt.encrypt(especie_codificado)
    ciphered_bytes_diagnostico = cipher_encrypt.encrypt(diagnostico_codificado)
    diccionario_final = {
        "Nombre codificado": b64encode(ciphered_bytes_nombre).decode("utf-8"),
        "Apellido codificado": b64encode(ciphered_bytes_apellido).decode("utf-8"),
        "DNI codificado": b64encode(ciphered_bytes_dni).decode("utf-8"),
        "Nombre mascota codificado": b64encode(ciphered_bytes_mascota).decode("utf-8"),
        "Especie codificado": b64encode(ciphered_bytes_especie).decode("utf-8"),
        "Diagnostico codificado": b64encode(ciphered_bytes_diagnostico).decode("utf-8")
    }

    lista_encriptados.append(diccionario_final)

# guardar los datos
try:
    with open(my_file_encriptada, "x", encoding="utf-8", newline="") as file:
        data = []
        for item in lista_encriptados:
            data.append(item)
        json.dump(data, file, indent=2)
        file.close()
except FileExistsError:
    with open(my_file_encriptada, "r", encoding="utf-8", newline="") as file:
        data = json.load(file)
        file.close()
    for item in lista_encriptados:
        data.append(item)
    with open(my_file_encriptada, "w") as file:
        json.dump(data, file, indent=2)
        file.close()

borrar_archivos(file_datos)

# DESENCRIPTAR
# ----------------------------------------------------------------------------------------------------------------------------------

# cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=cipher_encrypt.iv)
# print(cipher_decrypt)
# deciphered_bytes = cipher_decrypt.decrypt(ciphered_bytes)
# deciphered_bytes2 = cipher_decrypt.decrypt(ciphered_bytes2)
# print("info desencriptada", deciphered_bytes)
# print("info desencriptada", deciphered_bytes2)

with open(my_file_encriptada, "r", encoding="utf-8", newline="") as file:
    desencriptados = json.load(file)
    file.close()

with open(my_file_keys, "r", encoding="utf-8", newline="") as file:
    claves = json.load(file)
    file.close()

key_descifrado = claves.get("Key")
iv_descirado = claves.get("Cipher_encrypt.iv")
key_desencriptar = b64decode(key_descifrado)
iv_desencriptar = b64decode(iv_descirado)
cipher_decrypt = AES.new(key_desencriptar, AES.MODE_CFB, iv=iv_desencriptar)
lista_desencriptados = []

for diccionario_encriptado in desencriptados:
    nombre_encriptado = diccionario_encriptado.get("Nombre codificado")
    apellido_encriptado = diccionario_encriptado.get("Apellido codificado")
    dni_encriptado = diccionario_encriptado.get("DNI codificado")
    nombre_mascota_encriptados = diccionario_encriptado.get("Nombre mascota codificado")
    especie_encriptado = diccionario_encriptado.get("Especie codificado")
    diagnostico_encriptado = diccionario_encriptado.get("Diagnostico codificado")

    nombre_descifrado = cipher_decrypt.decrypt(b64decode(nombre_encriptado))
    apellido_descifrado = cipher_decrypt.decrypt(b64decode(apellido_encriptado))
    dni_descifrado = cipher_decrypt.decrypt(b64decode(dni_encriptado))
    nombre_mascotas_descifrado = cipher_decrypt.decrypt(b64decode(nombre_mascota_encriptados))
    especie_descifrado = cipher_decrypt.decrypt(b64decode(especie_encriptado))
    diagnostico_descifrado = cipher_decrypt.decrypt(b64decode(diagnostico_encriptado))

    diccionario_final = {
        "Nombre": nombre_descifrado.decode("utf-8"),
        "Apellido": apellido_descifrado.decode("utf-8"),
        "DNI": dni_descifrado.decode("utf-8"),
        "Nombre mascota": nombre_mascotas_descifrado.decode("utf-8"),
        "Especie": especie_descifrado.decode("utf-8"),
        "Diagnostico": diagnostico_descifrado.decode("utf-8")
    }
    lista_desencriptados.append(diccionario_final)


try:
    with open(file_datos, "x", encoding="utf-8", newline="") as file:
        data = []
        for item in lista_desencriptados:
            data.append(item)
        json.dump(data, file, indent=2)
        file.close()
except FileExistsError:
    with open(file_datos, "r", encoding="utf-8", newline="") as file:
        data = json.load(file)
        file.close()
    for item in lista_desencriptados:
        data.append(item)
    with open(file_datos, "w") as file:
        json.dump(data, file, indent=2)
        file.close()

# HASH
# ----------------------------------------------------------------------------------------------------------------------------------
