import os
import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives import (padding)


def MyEncrypt(message, key):
    padder = padding.PKCS7(128).padder()
    paddedToEncrypt = padder.update(message)
    paddedToEncrypt += padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    buffer = bytearray((len(message) + 32 -1 ))
    len_encrypted = encryptor.update_into(paddedToEncrypt, buffer)
    cipherText = bytes(buffer[:len_encrypted]) + encryptor.finalize()
    print("CipherText: ", cipherText)
    return cipherText, iv

def MyDecrypt(cipherText, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    buffer = bytearray((len(cipherText)+32-1))
    len_decrypted = decryptor.update_into(cipherText, buffer)
    string = bytes(buffer[:len_decrypted]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(string)
    unpadded += unpadder.finalize()
    return unpadded

def MyFileEncrypt(filepath):
    ext = getExtension(filepath)
    file = open(filepath, "rb")
    fileBytes = file.read()
    key = os.urandom(16)
    cipherText, iv = MyEncrypt(fileBytes, key)
    return cipherText, iv, key, ext

def getExtension(filepath):
    return os.path.splitext(filepath)[1]

cit, iv, key, ext = MyFileEncrypt("image.jpg")
print(cit)
print(iv)
print(key)
print(ext)

fileName = "encrypted" + ext
f = open(fileName, "wb")
f.write(cit)
f.close()

newFileName = "decrypted" + ext
newFile = open(newFileName, "wb")
newFile.write(MyDecrypt(cit, key, iv))
