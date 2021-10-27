from Crypto.Hash import SHA256

clave = bytes("vet1", "utf-8")
hash_inicial = SHA256.new(clave)
clave_final = hash_inicial.hexdigest()
print(clave_final)