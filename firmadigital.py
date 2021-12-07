import copy
from base64 import b64encode, b64decode
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA


class FirmaDigital:
    def __init__(self, data):
        self.data = data
        self.signature = {}

    def firmar(self):
        self.signature = copy.deepcopy(self.data)
        key = open("./Archivo/Akey.pem", "rb").read()
        rsakey = RSA.importKey(key, passphrase="1234")
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA1.new()
        if isinstance(self.signature, dict):
            for Key in self.signature:
                self.signature[Key]= b64encode((self.signature[Key]).encode("utf-8")).decode("utf-8")
                digest.update(b64decode(self.signature[Key]))
                self.signature[Key] = b64encode(signer.sign(digest)).decode("utf-8")
            return self.signature

        else:
            return "ERROR"

    def validar(self):
        public_key= open("./Archivo/APubKey.pem", "rb").read()
        rsakey = RSA.importKey(public_key)
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA1.new()
        count = 0
        if isinstance(self.data, dict):
            for key in self.data:
                self.data[key] = b64encode((self.data[key]).encode("utf-8")).decode("utf-8")
                digest.update(b64decode(self.data[key]))
                if signer.verify(digest, b64decode(self.signature[key])):
                    count += 1
                if count == len(self.signature):
                    return "Firma Verificada"
                else:
                    return "ERROR"


