import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives import (padding, hashes, hmac)


def MyEncryptMac(message, EncKey, HMACKey):
    padder = padding.PKCS7(128).padder()
    paddedToEncrypt = padder.update(message)
    paddedToEncrypt += padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    buffer = bytearray((len(message) + 32 -1 ))
    encrypted = encryptor.update_into(paddedToEncrypt, buffer)
    cipherText = bytes(buffer[:encrypted]) + encryptor.finalize()
    # Create tag object
    t = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    # Create tag from ciphertext
    t.update(cipherText)
    # Get the tag as bytes
    tag = t.finalize()
    return cipherText, iv, tag

def MyFileDecrypt(filename, key, iv, tag, HMACKey):
    file = open(filename, "rb")
    fileBytes = file.read()
    message = MyDecrypt(fileBytes, key, iv, tag, HMACKey)
    return message

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
    # Create the buffer
    buffer = bytearray((len(cipherText)+32-1))
    # Add ciphertext to the buffer byte array
    len_decrypted = decryptor.update_into(cipherText, buffer)
    # Pass the ciphertext through the decryptor and get all of the data out of the decryptor using finalize
    string = bytes(buffer[:len_decrypted]) + decryptor.finalize()
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

cit, tag, iv, key, ext, hkey = MyFileEncrypt("image.jpg")
cit2, tag2, iv2, key2, ext2, hkey2 = MyFileEncrypt("testText2.txt")

fileName = "encrypted" + ext
f = open(fileName, "wb")
f.write(cit)
f.close()

# Get the message
message = MyFileDecrypt(fileName, key, iv, tag, hkey)
# Create a new file for the message
newFileName = "decrypted" + ext
newFile = open(newFileName, "wb")
# Write the message to the file
newFile.write(message)
