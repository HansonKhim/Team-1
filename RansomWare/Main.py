import os
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import (hashes, hmac, serialization)
from cryptography.hazmat.primitives import (padding, asymmetric)

### Toggle Comment For PNG, JPG, or TXT File ###
#fileToEncrypt = './TestFiles/Images/image.png'
fileToEncrypt = './TestFiles/Images/image.jpg'
#fileToEncrypt = './TestFiles/Text/test.txt'


rsa_public_key_file_path = "./KeyFiles/public.pem"
rsa_private_key_file_path = "./KeyFiles/private.pem"


def check_rsa_keys():
    public_exists = os.path.isfile(rsa_public_key_file_path)
    private_exists = os.path.isfile(rsa_private_key_file_path)
    file_exists = os.path.isfile(fileToEncrypt)

    if public_exists and private_exists and file_exists:
        # Tells User that PEM Files Exist
        print("PEM Files Exist")
    else:
        # Generates a private RSA Key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # Serializes the Private Key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Stores the Private Key In a new File
        private_key_file_path = open(rsa_private_key_file_path, "wb")
        private_key_file_path.write(private_pem)
        private_key_file_path.close()

        # Generates a Public RSA Key from Private Key
        public_key = private_key.public_key()
        #  Serializes the Public Key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Stores the Public Key In a new File
        public_key_file_path = open(rsa_public_key_file_path, "wb")
        public_key_file_path.write(public_pem)
        public_key_file_path.close()


def encDirectory(directory):
    # Check for or create RSA keys
    check_rsa_keys()

    for dirName, subdirList, fileList in os.walk(directory):
        for fileToEncrypt in fileList:
            RSACipher, cit, iv, tag, ext = MyRSAEncrypt(os.path.join(dirName, fileToEncrypt).replace("\\","/"), rsa_public_key_file_path)
            # Create and dump the JSON data into the object
            jsonObj = createJSON(cit, tag, iv, ext, RSACipher)
            # Delete original file
            os.remove(os.path.join(dirName, fileToEncrypt).replace("\\","/"))
            # Create encrypted json file named the same as the original file with different extension
            fileName = os.path.splitext(fileToEncrypt)[0] + ".json"
            createFile(os.path.join(dirName, fileName).replace("\\","/"), jsonObj)

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    # Encrypt the file
    C, tag, IV, key, ext, hkey = MyFileEncrypt(filepath)
    # Load the public key from file
    with open(RSA_Publickey_filepath, "rb") as rsa_file_path:
        public_key = serialization.load_pem_public_key(
            rsa_file_path.read(),
            backend=default_backend()
        )
    # Use the RSA Public Key to encrypt the key and HMAC key
    RSAkey = key+hkey
    RSACipher = public_key.encrypt(
        RSAkey,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Return the encrypted Key and HMACKey as well as the other information needed for decryption
    return RSACipher, C, IV, tag, ext


def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    with open(RSA_Privatekey_filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Get the plaintext from the RSACipher
    keys = private_key.decrypt(
        RSACipher,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )
    # Separate the Key and HMACKeys
    ekey = keys[0:32]
    hkey = keys[32:len(keys)]

    return ekey, hkey


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


def MyFileDecrypt(filename, rsa_private_key_file_path):
    # Decrypt the file
    decryptThis = open(filename, "r")
    fileContents = decryptThis.read()
    jsonUndone = json.loads(fileContents)

    citBytes = jsonUndone["cipherText"].encode('ISO-8859-1')
    rsacipher = jsonUndone["RSACipher"].encode('ISO-8859-1')
    iv = jsonUndone["iv"].encode('ISO-8859-1')
    tag = jsonUndone["tag"].encode('ISO-8859-1')
    ext = jsonUndone["extension"]

    #print(type(HMACKey))

    #print("HMACKEY After: ", HMACKey)

    #message = MyDecrypt(citBytes, key, iv, tag, HMACKey)
    ekey, hkey = MyRSADecrypt(rsacipher, citBytes, iv, tag, ext, rsa_private_key_file_path)
    message = MyDecrypt(citBytes, ekey, iv, tag, hkey)
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
    key = os.urandom(32)
    hkey = os.urandom(32)
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
    jsonData['createdBy'] = 'Team1'
    return json.dumps(jsonData)


def createFile(fileName, jsonObj):
    f = open(fileName, "w")
    f.write(jsonObj)
    f.close()

encDirectory('./TestFiles/EncryptThese')
