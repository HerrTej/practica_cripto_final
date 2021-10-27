from Crypto.Hash import SHA256

nombre = input("Nombre: ")
clave = bytes(input("Indica tu contraseña: "), "utf-8")
hash_inicial = SHA256.new(clave)
clave_final = hash_inicial.hexdigest()
print(clave_final)
